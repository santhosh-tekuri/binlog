package binlog

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"time"
)

// ErrMalformedPacket used to indicate malformed packet.
var ErrMalformedPacket = errors.New("malformed packet")

type null struct{}

// Remote represents connection to MySQL server.
type Remote struct {
	conn   net.Conn
	seq    uint8
	hs     handshake
	pubKey *rsa.PublicKey

	authFlow []string // for testing only

	// binlog related
	requestFile  string
	requestPos   uint32
	binlogReader *reader
	checksum     int // captures binlog_checksum sys-var
}

// Dial connects to the MySQL server specified.
func Dial(network, address string) (*Remote, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	// Enable TCP KeepAlive on TCP connections
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	var seq uint8
	r := newReader(conn, &seq)
	hs := handshake{}
	if err = hs.decode(r); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// unset the features we dont support
	hs.capabilityFlags &= ^uint32(capSessionTrack)
	return &Remote{
		conn: conn,
		seq:  seq,
		hs:   hs,
	}, nil
}

// IsSSLSupported tells whether MySQL server supports SSL.
func (bl *Remote) IsSSLSupported() bool {
	return bl.hs.capabilityFlags&capSSL != 0
}

// UpgradeSSL upgrades current connection to SSL. If tlsConfig is nil
// it will use InsecureSkipVerify true value. This should be called
// before Authenticate call.
func (bl *Remote) UpgradeSSL(tlsConfig *tls.Config) error {
	err := bl.write(sslRequest{
		capabilityFlags: capLongFlag | capSecureConnection,
		maxPacketSize:   maxPacketSize,
		characterSet:    bl.hs.characterSet,
	})
	if err != nil {
		return err
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}
	bl.conn = tls.Client(bl.conn, tlsConfig)
	return bl.conn.(*tls.Conn).Handshake()
}

// ListFiles lists the binary log files on the server,
// in the order they were created. It is equivalent to
// `SHOW BINARY LOGS` statement.
func (bl *Remote) ListFiles() ([]string, error) {
	rows, err := bl.queryRows(`show binary logs`)
	if err != nil {
		return nil, err
	}
	files := make([]string, len(rows))
	for i := range files {
		files[i] = rows[i][0].(string)
	}
	return files, nil
}

// MasterStatus provides status information about the binary log files of the server.
// It is equivalent to `SHOW MASTER STATUS` statement.
func (bl *Remote) MasterStatus() (file string, pos uint32, err error) {
	rows, err := bl.queryRows(`show master status`)
	if err != nil {
		return "", 0, err
	}
	if len(rows) == 0 {
		return "", 0, nil
	}
	off, err := strconv.Atoi(rows[0][1].(string))
	return rows[0][0].(string), uint32(off), err
}

// SetHeartbeatPeriod configures the interval to send HeartBeatEvent in absence of data.
// This avoids connection timeout occurring in the absence of data. Setting interval to 0
// disables heartbeats altogether.
//
// Use this, if you are using non-zero serverID to Seek method. In this case, server sends
// heartbeatEvents when there are no more events.
func (bl *Remote) SetHeartbeatPeriod(d time.Duration) error {
	_, err := bl.query(fmt.Sprintf("SET @master_heartbeat_period=%d", d))
	return err
}

func (bl *Remote) fetchBinlogChecksum() (string, error) {
	rows, err := bl.queryRows(`show global variables like 'binlog_checksum'`)
	if err != nil {
		return "", err
	}
	if len(rows) > 0 {
		return rows[0][1].(string), nil
	}
	return "", nil
}

func (bl *Remote) confirmChecksumSupport() error {
	_, err := bl.query(`set @master_binlog_checksum = @@global.binlog_checksum`)
	return err
}

// Seek requests binlog at fileName and position.
//
// if serverID is zero, NextEvent return io.EOF when there are no ore events.
// if serverID is non-zero, NextEvent waits for new events.
func (bl *Remote) Seek(serverID uint32, fileName string, position uint32) error {
	checksum, err := bl.fetchBinlogChecksum()
	if err != nil {
		return err
	}
	if checksum != "" && checksum != "NONE" {
		if err := bl.confirmChecksumSupport(); err != nil {
			return err
		}
		bl.checksum = 4
	} else {
		bl.checksum = 0
	}
	bl.seq = 0
	err = bl.write(comBinlogDump{
		binlogPos:      position,
		flags:          0,
		serverID:       serverID,
		binlogFilename: fileName,
	})
	bl.requestFile, bl.requestPos = fileName, position
	return err
}

func (bl *Remote) binlogVersion() (uint16, error) {
	sv, err := newServerVersion(bl.hs.serverVersion)
	if err != nil {
		return 0, err
	}
	return sv.binlogVersion(), nil
}

// NextEvent return next binlog event.
//
// return io.EOF when there are no more Events
func (bl *Remote) NextEvent() (Event, error) {
	// checksum: https://dev.mysql.com/worklog/task/?id=2540#tabs-2540-4
	r := bl.binlogReader
	if r == nil {
		r = newReader(bl.conn, &bl.seq)
		v, err := bl.binlogVersion()
		if err != nil {
			return Event{}, err
		}
		r.checksum = bl.checksum
		r.hash = crc32.NewIEEE()
		r.fde = FormatDescriptionEvent{BinlogVersion: v}
		bl.binlogReader = r
	} else {
		if err := r.drain(); err != nil {
			return Event{}, fmt.Errorf("binlog.NextEvent: error in draining event: %v", err)
		}
		if r.checksum > 0 {
			got := r.hash.Sum32()
			r.limit = -1
			want := r.int4()
			if r.err != nil {
				return Event{}, r.err
			}
			if got != want {
				return Event{}, fmt.Errorf("binlog.NextEvent: checksum failed got=%d want=%d", got, want)
			}
		}
		r.limit = -1
		r.rd = &packetReader{rd: bl.conn, seq: &bl.seq}
	}
	// Check first byte.
	b, err := r.peek()
	if err != nil {
		return Event{}, err
	}
	switch b {
	case okMarker:
		r.int1()
	case eofMarker:
		eof := eofPacket{}
		if err := eof.decode(r, bl.hs.capabilityFlags); err != nil {
			return Event{}, err
		}
		return Event{}, io.EOF
	case errMarker:
		ep := errPacket{}
		if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
			return Event{}, err
		}
		return Event{}, errors.New(ep.errorMessage)
	default:
		return Event{}, fmt.Errorf("binlogStream: got %0x want OK-byte", b)
	}
	return nextEvent(r, bl.checksum)
}

// NextRow returns next row for RowsEvent. Returns io.EOF when there are no more rows.
// valuesBeforeUpdate should be used only for events UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2.
func (bl *Remote) NextRow() (values []interface{}, valuesBeforeUpdate []interface{}, err error) {
	return nextRow(bl.binlogReader)
}

// Close closes connection.
func (bl *Remote) Close() error {
	return bl.conn.Close()
}

func (bl *Remote) write(event interface{ encode(w *writer) error }) error {
	w := newWriter(bl.conn, &bl.seq)
	if err := event.encode(w); err != nil {
		return err
	}
	return w.Close()
}

// comBinlogDump ---

type comBinlogDump struct {
	binlogPos      uint32
	flags          uint16
	serverID       uint32
	binlogFilename string
}

func (e comBinlogDump) encode(w *writer) error {
	w.int1(0x12) // COM_BINLOG_DUMP
	w.int4(e.binlogPos)
	w.int2(e.flags)
	w.int4(e.serverID)
	w.string(e.binlogFilename)
	return w.err
}

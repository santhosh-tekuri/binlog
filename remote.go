package binlog

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// todo: include packet type
var ErrMalformedPacket = errors.New("malformed packet")

type null struct{}

type Remote struct {
	conn net.Conn
	seq  uint8
	hs   handshake

	// binlog related
	requestFile  string
	requestPos   uint32
	binlogReader *reader
	checksum     int
}

func Dial(network, address string) (*Remote, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
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

// UpgradeSSL upgrades current connection to SSL. If rootCAs is nil,
// it will use InsecureSkipVerify true value. This should be done
// before Authenticate call
func (bl *Remote) UpgradeSSL(rootCAs *x509.CertPool) error {
	w := newWriter(bl.conn, &bl.seq)
	err := w.encodeClose(sslRequest{
		capabilityFlags: capLongFlag | capSecureConnection,
		maxPacketSize:   maxPacketSize,
		characterSet:    bl.hs.characterSet,
	})
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{}
	if rootCAs != nil {
		tlsConf.RootCAs = rootCAs
	} else {
		tlsConf.InsecureSkipVerify = true
	}
	bl.conn = tls.Client(bl.conn, tlsConf)
	return nil
}

// Authenticate sends the credentials to MySQL.
func (bl *Remote) Authenticate(username, password string) error {
	w := newWriter(bl.conn, &bl.seq)
	err := w.encodeClose(handshakeResponse41{
		capabilityFlags: capLongFlag | capSecureConnection,
		maxPacketSize:   maxPacketSize,
		characterSet:    bl.hs.characterSet,
		username:        username,
		authResponse:    encryptedPasswd([]byte(password), bl.hs.authPluginData),
		database:        "",
		authPluginName:  "",
		connectAttrs:    nil,
	})
	if err != nil {
		return err
	}

	r := newReader(bl.conn, &bl.seq)
	marker, err := r.peek()
	if err != nil {
		return err
	}
	if marker == errMarker {
		ep := errPacket{}
		if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
			return err
		}
		return errors.New(ep.errorMessage)
	}
	return r.drain()
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
		checksum, _ := rows[0][1].(string)
		return checksum, nil
	}
	return "", nil
}

func (bl *Remote) confirmChecksumSupport() error {
	_, err := bl.query(`set @master_binlog_checksum = @@global.binlog_checksum`)
	return err
}

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
	w := newWriter(bl.conn, &bl.seq)
	err = w.encodeClose(comBinlogDump{
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

func (bl *Remote) NextEvent() (Event, error) {
	r := bl.binlogReader
	if r == nil {
		r = newReader(bl.conn, &bl.seq)
		v, err := bl.binlogVersion()
		if err != nil {
			return Event{}, err
		}
		r.fde = FormatDescriptionEvent{BinlogVersion: v}
		bl.binlogReader = r
	} else {
		r.limit += bl.checksum
		if err := r.drain(); err != nil {
			return Event{}, fmt.Errorf("binlog.NextEvent: error in draining event: %v", err)
		}
		r.rd = &packetReader{rd: bl.conn, seq: &bl.seq}
		r.limit = -1
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

func (bl *Remote) NextRow() (values []interface{}, valuesBeforeUpdate []interface{}, err error) {
	return nextRow(bl.binlogReader)
}

func (bl *Remote) Close() error {
	return bl.conn.Close()
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

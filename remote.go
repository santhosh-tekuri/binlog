package binlog

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/crc32"
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
	checksum     int // captures binlog_checksum sys-var
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
	var plugin string
	switch bl.hs.authPluginName {
	case "mysql_native_password": // supported
		plugin = bl.hs.authPluginName
	case "": // unspecified
		plugin = "mysql_native_password"
	default:
		return fmt.Errorf("unsupported auth plugin '%s'", plugin)
	}
	authResponse, err := encryptedPasswd(plugin, []byte(password), bl.hs.authPluginData)
	if err != nil {
		return err
	}

	w := newWriter(bl.conn, &bl.seq)
	err = w.encodeClose(handshakeResponse41{
		capabilityFlags: capLongFlag | capSecureConnection,
		maxPacketSize:   maxPacketSize,
		characterSet:    bl.hs.characterSet,
		username:        username,
		authResponse:    authResponse,
		database:        "",
		authPluginName:  plugin,
		connectAttrs:    nil,
	})
	if err != nil {
		return err
	}
	var numAuthSwitches = 0
	for {
		r := newReader(bl.conn, &bl.seq)
		marker, err := r.peek()
		if err != nil {
			return err
		}
		switch marker {
		case okMarker:
			if err := r.drain(); err != nil {
				return err
			}
			// query serverVersion. seems azure reports wrong serverVersion in handshake
			rows, err := bl.queryRows(`select version()`)
			if err != nil {
				return err
			}
			bl.hs.serverVersion = rows[0][0].(string)
			return nil
		case errMarker:
			ep := errPacket{}
			if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
				return err
			}
			return errors.New(ep.errorMessage)
		case 0x01:
			return errors.New("authMoreData not supported")
		case 0xFE:
			if numAuthSwitches != 0 {
				return fmt.Errorf("AuthSwitch more than once")
			}
			numAuthSwitches++
			asr := authSwitchRequest{}
			if err := asr.decode(r); err != nil {
				return err
			}
			plugin = asr.pluginName
			authResponse, err = encryptedPasswd(plugin, []byte(password), asr.authPluginData)
			if err != nil {
				return err
			}
			w = newWriter(bl.conn, &bl.seq)
			if err := w.encodeClose(authSwitchResponse{authResponse}); err != nil {
				return err
			}
		default:
			return ErrMalformedPacket
		}
	}
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
		return rows[0][1].(string), nil
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

// checksum: https://dev.mysql.com/worklog/task/?id=2540#tabs-2540-4
func (bl *Remote) NextEvent() (Event, error) {
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

package binlog

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
)

var ErrMalformedPacket = errors.New("malformed packet")

type Null struct{}

type Remote struct {
	conn net.Conn
	seq  uint8
	hs   handshake

	// binlog related
	binlogReader *reader
	binlogFile   string
	binlogPos    uint32
}

func Dial(network, address string) (*Remote, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	var seq uint8
	r := newReader(conn, &seq)
	hs := handshake{}
	if err = hs.parse(r); err != nil {
		conn.Close()
		return nil, err
	}
	// unset the features we dont support
	hs.capabilityFlags &= ^uint32(CLIENT_SESSION_TRACK)
	return &Remote{
		conn: conn,
		seq:  seq,
		hs:   hs,
	}, nil
}

func (bl *Remote) IsSSLSupported() bool {
	return bl.hs.capabilityFlags&CLIENT_SSL != 0
}

func (bl *Remote) UpgradeSSL() error {
	w := newWriter(bl.conn, &bl.seq)
	err := w.writeClose(sslRequest{
		capabilityFlags: CLIENT_LONG_FLAG | CLIENT_SECURE_CONNECTION,
		maxPacketSize:   maxPacketSize,
		characterSet:    bl.hs.characterSet,
	})
	if err != nil {
		return err
	}
	bl.conn = tls.Client(bl.conn, &tls.Config{InsecureSkipVerify: true})
	return nil
}

func (bl *Remote) Authenticate(username, password string) error {
	w := newWriter(bl.conn, &bl.seq)
	err := w.writeClose(handshakeResponse41{
		capabilityFlags: CLIENT_LONG_FLAG | CLIENT_SECURE_CONNECTION,
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
		if err := ep.parse(r, bl.hs.capabilityFlags); err != nil {
			return err
		}
		return errors.New(ep.errorMessage)
	}
	return r.drain()
}

func (bl *Remote) ListFiles() ([]string, error) {
	rows, err := bl.queryRows(`show binary logs`)
	if err != nil {
		return nil, err
	}
	files := make([]string, len(rows))
	for i, _ := range files {
		files[i] = rows[i][0].(string)
	}
	return files, nil
}

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

func (bl *Remote) fetchBinlogChecksum() (string, error) {
	rows, err := bl.queryRows(`show variables like 'binlog_checksum'`)
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

func (bl *Remote) RequestBinlog(serverID uint32, fileName string, position uint32) error {
	checksum, err := bl.fetchBinlogChecksum()
	if err != nil {
		return err
	}
	if checksum != "" {
		if err := bl.confirmChecksumSupport(); err != nil {
			return err
		}
	}
	bl.seq = 0
	w := newWriter(bl.conn, &bl.seq)
	err = w.writeClose(comBinlogDump{
		binlogPos:      position,
		flags:          0,
		serverID:       serverID,
		binlogFilename: fileName,
	})
	if err != nil {
		bl.binlogFile, bl.binlogPos = fileName, position
	}
	return err
}

func (bl *Remote) nextLocation() (filename string, position uint32) {
	if bl.binlogReader == nil {
		return bl.binlogFile, bl.binlogPos
	}
	return bl.binlogReader.binlogFile, bl.binlogReader.binlogPos
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
		r.fde = formatDescriptionEvent{binlogVersion: v}
		bl.binlogReader = r
	} else {
		r.limit += 4
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
	case errMarker:
		ep := errPacket{}
		if err := ep.parse(r, bl.hs.capabilityFlags); err != nil {
			return Event{}, err
		}
		return Event{}, errors.New(ep.errorMessage)
	default:
		return Event{}, fmt.Errorf("binlogStream: got %0x want OK-byte", b)
	}

	return nextEvent(r)
}

func (bl *Remote) NextRow() ([][]interface{}, error) {
	return nextRow(bl.binlogReader)
}

func (bl *Remote) Close() error {
	return bl.conn.Close()
}

// comBinlogDump ---

const (
	COM_BINLOG_DUMP       = 0x12
	BINLOG_DUMP_NON_BLOCK = 0x01
)

type comBinlogDump struct {
	binlogPos      uint32
	flags          uint16
	serverID       uint32
	binlogFilename string
}

func (e comBinlogDump) writeTo(w *writer) error {
	w.int1(COM_BINLOG_DUMP)
	w.int4(e.binlogPos)
	w.int2(e.flags)
	w.int4(e.serverID)
	w.string(e.binlogFilename)
	return w.err
}

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

type Conn struct {
	conn net.Conn
	seq  uint8
	hs   handshake

	// binlog related
	binlogReader *reader
	binlogFile   string
	binlogPos    uint32
}

func Dial(network, address string) (*Conn, error) {
	netconn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	var seq uint8
	r := newReader(netconn, &seq)
	hs := handshake{}
	if err = hs.parse(r); err != nil {
		netconn.Close()
		return nil, err
	}
	// unset the features we dont support
	hs.capabilityFlags &= ^uint32(CLIENT_SESSION_TRACK)
	return &Conn{
		conn: netconn,
		seq:  seq,
		hs:   hs,
	}, nil
}

func (c *Conn) IsSSLSupported() bool {
	return c.hs.capabilityFlags&CLIENT_SSL != 0
}

func (c *Conn) UpgradeSSL() error {
	w := newWriter(c.conn, &c.seq)
	err := w.writeClose(sslRequest{
		capabilityFlags: CLIENT_LONG_FLAG | CLIENT_SECURE_CONNECTION,
		maxPacketSize:   maxPacketSize,
		characterSet:    c.hs.characterSet,
	})
	if err != nil {
		return err
	}
	c.conn = tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
	return nil
}

func (c *Conn) Authenticate(username, password string) error {
	w := newWriter(c.conn, &c.seq)
	err := w.writeClose(handshakeResponse41{
		capabilityFlags: CLIENT_LONG_FLAG | CLIENT_SECURE_CONNECTION,
		maxPacketSize:   maxPacketSize,
		characterSet:    c.hs.characterSet,
		username:        username,
		authResponse:    encryptedPasswd([]byte(password), c.hs.authPluginData),
		database:        "",
		authPluginName:  "",
		connectAttrs:    nil,
	})
	if err != nil {
		return err
	}

	r := newReader(c.conn, &c.seq)
	marker, err := r.peek()
	if err != nil {
		return err
	}
	if marker == errMarker {
		ep := errPacket{}
		if err := ep.parse(r, c.hs.capabilityFlags); err != nil {
			return err
		}
		return errors.New(ep.errorMessage)
	}
	return r.drain()
}

func (c *Conn) ListFiles() ([]string, error) {
	rows, err := c.queryRows(`show binary logs`)
	if err != nil {
		return nil, err
	}
	files := make([]string, len(rows))
	for i, _ := range files {
		files[i] = rows[i][0].(string)
	}
	return files, nil
}

func (c *Conn) MasterStatus() (file string, pos uint32, err error) {
	rows, err := c.queryRows(`show master status`)
	if err != nil {
		return "", 0, err
	}
	if len(rows) == 0 {
		return "", 0, nil
	}
	off, err := strconv.Atoi(rows[0][1].(string))
	return rows[0][0].(string), uint32(off), err
}

func (c *Conn) fetchBinlogChecksum() (string, error) {
	rows, err := c.queryRows(`show variables like 'binlog_checksum'`)
	if err != nil {
		return "", err
	}
	if len(rows) > 0 {
		return rows[0][1].(string), nil
	}
	return "", nil
}

func (c *Conn) confirmChecksumSupport() error {
	_, err := c.query(`set @master_binlog_checksum = @@global.binlog_checksum`)
	return err
}

func (c *Conn) RequestBinlog(serverID uint32, fileName string, position uint32) error {
	checksum, err := c.fetchBinlogChecksum()
	if err != nil {
		return err
	}
	if checksum != "" {
		if err := c.confirmChecksumSupport(); err != nil {
			return err
		}
	}
	c.seq = 0
	w := newWriter(c.conn, &c.seq)
	err = w.writeClose(comBinlogDump{
		binlogPos:      position,
		flags:          0,
		serverID:       serverID,
		binlogFilename: fileName,
	})
	if err != nil {
		c.binlogFile, c.binlogPos = fileName, position
	}
	return err
}

func (c *Conn) nextLocation() (filename string, position uint32) {
	if c.binlogReader == nil {
		return c.binlogFile, c.binlogPos
	}
	return c.binlogReader.binlogFile, c.binlogReader.binlogPos
}

func (c *Conn) binlogVersion() (uint16, error) {
	sv, err := newServerVersion(c.hs.serverVersion)
	if err != nil {
		return 0, err
	}
	return sv.binlogVersion(), nil
}

func (c *Conn) NextEvent() (Event, error) {
	r := c.binlogReader
	if r == nil {
		r = newReader(c.conn, &c.seq)
		v, err := c.binlogVersion()
		if err != nil {
			return Event{}, err
		}
		r.fde = formatDescriptionEvent{binlogVersion: v}
		c.binlogReader = r
	} else {
		r.limit += 4
		if err := r.drain(); err != nil {
			return Event{}, fmt.Errorf("binlog.NextEvent: error in draining event: %v", err)
		}
		r.rd = &packetReader{rd: c.conn, seq: &c.seq}
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
		if err := ep.parse(r, c.hs.capabilityFlags); err != nil {
			return Event{}, err
		}
		return Event{}, errors.New(ep.errorMessage)
	default:
		return Event{}, fmt.Errorf("binlogStream: got %0x want OK-byte", b)
	}

	return nextEvent(r)
}

func (c *Conn) NextRow() ([][]interface{}, error) {
	return nextRow(c.binlogReader)
}

func (c *Conn) Close() error {
	return c.conn.Close()
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

package binlog

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

type conn struct {
	conn       net.Conn
	seq        uint8
	hs         handshake
	fde        formatDescriptionEvent
	tme        tableMapEvent
	lastReader *reader
}

func Dial(network, address string) (*conn, error) {
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
	return &conn{
		conn: netconn,
		seq:  seq,
		hs:   hs,
	}, nil
}

func (c *conn) isSSLSupported() bool {
	return c.hs.capabilityFlags&CLIENT_SSL != 0
}

func (c *conn) upgradeSSL() error {
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

func (c *conn) authenticate(username, password string) error {
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
		if err := ep.parse(r, &c.hs); err != nil {
			return err
		}
		return errors.New(ep.errorMessage)
	}
	return r.drain()
}

func (c *conn) confirmChecksumSupport() error {
	c.seq = 0
	w := newWriter(c.conn, &c.seq)
	if err := w.query("set @master_binlog_checksum = @@global.binlog_checksum"); err != nil {
		return err
	}
	return newReader(c.conn, &c.seq).drain()
}

func (c *conn) requestBinlog(serverID uint32, fileName string, position uint32) error {
	c.seq = 0
	w := newWriter(c.conn, &c.seq)
	return w.writeClose(comBinlogDump{
		binlogPos:      position,
		flags:          0,
		serverID:       serverID,
		binlogFilename: fileName,
	})
}

func (c *conn) nextEvent() (interface{}, error) {
	if c.lastReader != nil {
		if err := c.lastReader.drain(); err != nil {
			return nil, fmt.Errorf("binlog.nextEvent: error in draining event: %v", err)
		}
	}
	r := newReader(c.conn, &c.seq)
	c.lastReader = r
	r.checksum = 4

	// Check first byte.
	b, err := r.peek()
	if err != nil {
		return nil, err
	}
	switch b {
	case okMarker:
		r.int1()
	case errMarker:
		ep := errPacket{}
		if err := ep.parse(r, &c.hs); err != nil {
			return nil, err
		}
		return nil, errors.New(ep.errorMessage)
	default:
		return nil, fmt.Errorf("binlogStream: got %0x want OK-byte", b)
	}

	// Read event header
	h := binaryEventHeader{}
	if err := h.parse(r); err != nil {
		return nil, err
	}
	fmt.Printf("%#v\n", h)

	// Read event body
	switch h.eventType {
	case FORMAT_DESCRIPTION_EVENT:
		c.fde = formatDescriptionEvent{}
		err := c.fde.parse(r)
		return c.fde, err
	case ROTATE_EVENT:
		re := rotateEvent{}
		err := re.parse(r, &c.fde)
		return re, err
	case TABLE_MAP_EVENT:
		c.tme = tableMapEvent{}
		err := c.tme.parse(r)
		return c.tme, err
	case WRITE_ROWS_EVENTv0, WRITE_ROWS_EVENTv1, WRITE_ROWS_EVENTv2,
		UPDATE_ROWS_EVENTv0, UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2,
		DELETE_ROWS_EVENTv0, DELETE_ROWS_EVENTv1, DELETE_ROWS_EVENTv2:
		re := rowsEvent{}
		re.reader = r
		err := re.parse(r, &c.fde, h.eventType, &c.tme)
		return &re, err
	default:
		return c.nextEvent()
	}
}

package binlog

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
)

type conn struct {
	conn net.Conn
	seq  uint8
	hs   handshake

	// binlog related
	binlogReader *reader
	binlogFile   string
	binlogPos    uint32
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
		if err := ep.parse(r, c.hs.capabilityFlags); err != nil {
			return err
		}
		return errors.New(ep.errorMessage)
	}
	return r.drain()
}

// todo: fetch binlog checksum

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
	err := w.writeClose(comBinlogDump{
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

func (c *conn) nextLocation() (filename string, position uint32) {
	if c.binlogReader == nil {
		return c.binlogFile, c.binlogPos
	}
	return c.binlogReader.binlogFile, c.binlogReader.binlogPos
}

func (c *conn) binlogVersion() (uint16, error) {
	sv, err := newServerVersion(c.hs.serverVersion)
	if err != nil {
		return 0, err
	}
	return sv.binlogVersion(), nil
}

func (c *conn) nextEvent() (interface{}, error) {
	r := c.binlogReader
	if r == nil {
		r = newReader(c.conn, &c.seq)
		v, err := c.binlogVersion()
		if err != nil {
			return nil, err
		}
		r.fde = formatDescriptionEvent{binlogVersion: v}
		c.binlogReader = r
	} else {
		r.limit += 4
		if err := r.drain(); err != nil {
			return nil, fmt.Errorf("binlog.nextEvent: error in draining event: %v", err)
		}
		r.rd = &packetReader{rd: c.conn, seq: &c.seq}
		r.limit = -1
	}

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
		if err := ep.parse(r, c.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return nil, errors.New(ep.errorMessage)
	default:
		return nil, fmt.Errorf("binlogStream: got %0x want OK-byte", b)
	}

	e, err := nextEvent(r)
	if e == nil && err == nil {
		return c.nextEvent()
	}
	return e, err
}

func (c *conn) dump(dir string) error {
	v, err := c.binlogVersion()
	if err != nil {
		return err
	}
	buf := make([]byte, 14)
	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	for {
		fmt.Println("--------------------------------")
		r := &packetReader{rd: c.conn, seq: &c.seq}
		_, err := io.ReadFull(r, buf)
		if err != nil {
			return err
		}
		if buf[0] != okMarker {
			return fmt.Errorf("binlogStream: got %0x want OK-byte", buf[0])
		}
		// timestamp = buf[1:5]
		eventType := buf[5]
		// serverID = buf[6:10]
		eventSize := binary.LittleEndian.Uint32(buf[10:])
		fmt.Printf("eventType: 0x%02x eventSize: 0x%02x\n", eventType, eventSize)
		switch eventType {
		case ROTATE_EVENT:
			lr := io.LimitReader(r, int64(eventSize-13)) // checksum
			buf, err := ioutil.ReadAll(lr)
			if err != nil {
				return err
			}
			if v > 1 {
				buf = buf[4+2+8 : len(buf)-4] // logPos, flags, position and exclude checksum
			}
			if f != nil {
				if err := f.Close(); err != nil {
					return err
				}
			}
			fmt.Println("creating file", string(buf))
			f, err = os.Create(path.Join(dir, string(buf)))
			if err != nil {
				return err
			}
			if _, err := f.Write([]byte{0xfe, 'b', 'i', 'n'}); err != nil {
				return err
			}
		default:
			lr := io.LimitReader(r, int64(eventSize-13)) // checksum
			if _, err := f.Write(buf[1:]); err != nil {
				return err
			}
			if _, err := io.Copy(f, lr); err != nil {
				return err
			}
		}
	}
}

func (c *conn) Close() error {
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

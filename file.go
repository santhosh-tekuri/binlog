package binlog

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type binlogFile struct {
	conn io.Reader
	seq  uint8

	binlogReader *reader
	binlogFile   string
	binlogPos    uint32
}

// todo: https://dev.mysql.com/doc/internals/en/determining-binary-log-version.html

func Open(file string) (*binlogFile, error) {
	f, err := openBinlogFile(file)
	if err != nil {
		return nil, err
	}
	return &binlogFile{
		conn: f,
	}, nil
}

func openBinlogFile(file string) (*os.File, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	_, err = io.ReadAtLeast(f, header, len(header))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header, []byte{0xfe, 'b', 'i', 'n'}) {
		return nil, fmt.Errorf("binlog.Open: %s has invalid fileheader", file)
	}
	return f, nil
}

func (c *binlogFile) nextEvent() (interface{}, error) {
	r := c.binlogReader
	if r == nil {
		r = &reader{
			rd:    c.conn,
			limit: -1,
		}
		r.fde = formatDescriptionEvent{binlogVersion: 4}
		c.binlogReader = r
	} else {
		fmt.Println("draining")
		r.limit += 4
		if err := r.drain(); err != nil {
			return nil, fmt.Errorf("binlog.nextEvent: error in draining event: %v", err)
		}
		r.limit = -1
		fmt.Println("drained")
	}

	if !r.more() {
		name := r.rd.(*os.File).Name()
		dot := strings.LastIndexByte(name, '.')
		if dot != -1 {
			suffix := name[dot+1:]
			for len(suffix) > 1 && suffix[0] == '0' {
				suffix = suffix[1:]
			}
			i, err := strconv.Atoi(suffix)
			if err == nil {
				nextFile := fmt.Sprintf("%s%06d", name[:dot+1], i+1)
				f, err := openBinlogFile(nextFile)
				if err == nil {
					fmt.Println("******************>>>>>>>>", nextFile)
					r.rd.(*os.File).Close()
					r.rd = f
					c.binlogFile, c.binlogPos = nextFile, 4 // magic header = 4
				}
			}
		}
	}

	// Read event header
	h := binaryEventHeader{}
	if err := h.parse(r); err != nil {
		return nil, err
	}
	fmt.Printf("%#v\n", h)

	headerSize := uint32(13)
	if r.fde.binlogVersion > 1 {
		headerSize = 19
	}
	r.limit = int(h.eventSize-headerSize) - 4 // checksum = 4

	c.binlogPos = h.logPos
	// Read event body
	switch h.eventType {
	case FORMAT_DESCRIPTION_EVENT:
		r.fde = formatDescriptionEvent{}
		err := r.fde.parse(r)
		return r.fde, err
	case ROTATE_EVENT:
		re := rotateEvent{}
		err := re.parse(r)
		if err != nil {
			c.binlogFile, c.binlogPos = re.nextBinlog, uint32(re.position)
		}
		return re, err
	case TABLE_MAP_EVENT:
		r.tme = tableMapEvent{}
		err := r.tme.parse(r)
		return r.tme, err
	case WRITE_ROWS_EVENTv0, WRITE_ROWS_EVENTv1, WRITE_ROWS_EVENTv2,
		UPDATE_ROWS_EVENTv0, UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2,
		DELETE_ROWS_EVENTv0, DELETE_ROWS_EVENTv1, DELETE_ROWS_EVENTv2:
		re := rowsEvent{}
		re.reader = r
		err := re.parse(r, h.eventType)
		return &re, err
	default:
		return c.nextEvent()
	}
}

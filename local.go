package binlog

import (
	"fmt"
	"os"
)

type Local struct {
	conn *dirReader

	binlogReader *reader
	binlogFile   string
	binlogPos    uint32
}

func Open(file string) (*Local, error) {
	f := &Local{
		binlogFile: file,
		binlogPos:  4,
	}
	r, err := newDirReader(&f.binlogFile)
	if err != nil {
		return nil, err
	}
	f.conn = r
	return f, nil
}

func (c *Local) NextEvent() (Event, error) {
	r := c.binlogReader
	if r == nil {
		v, err := findBinlogVersion(c.binlogFile)
		if err != nil {
			return Event{}, err
		}
		r = &reader{
			rd:       c.conn,
			tmeCache: c.conn.tmeCache,
			limit:    -1,
		}
		r.fde = formatDescriptionEvent{binlogVersion: v}
		c.binlogReader = r
	} else {
		r.limit += 4
		if err := r.drain(); err != nil {
			return Event{}, fmt.Errorf("binlog.NextEvent: error in draining event: %v", err)
		}
		r.limit = -1
	}

	return nextEvent(r)
}

func (c *Local) NextRow() ([][]interface{}, error) {
	return nextRow(c.binlogReader)
}

// todo: https://dev.mysql.com/doc/internals/en/determining-binary-log-version.html
func findBinlogVersion(file string) (uint16, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := &reader{rd: f, limit: -1}
	r.skip(4) // magic number
	r.skip(4)
	eventType := EventType(r.int1())
	r.skip(4)
	eventSize := r.int4()
	if r.err != nil {
		return 0, r.err
	}
	if eventType != START_EVENT_V3 && eventType != FORMAT_DESCRIPTION_EVENT {
		return 3, nil
	}
	if eventType == START_EVENT_V3 {
		if eventSize < 75 {
			return 1, nil
		}
		return 3, nil
	}
	if eventType == FORMAT_DESCRIPTION_EVENT {
		return 4, nil
	}
	return 0, fmt.Errorf("binlog.findBinlogVersion: cannot determine for %q", file)
}

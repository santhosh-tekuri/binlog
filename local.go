package binlog

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
)

type Local struct {
	dir  string
	conn *dirReader

	binlogReader *reader
	binlogFile   string
	binlogPos    uint32
}

func Open(dir string) (*Local, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("binlog.Open: %q is not a directory", dir)
	}
	return &Local{dir: dir}, nil
}

func (bl *Local) ListFiles() ([]string, error) {
	var files []string
	f, err := os.Open(path.Join(bl.dir, "binlog.index"))
	if err != nil {
		if os.IsNotExist(err) {
			return files, nil
		}
		return files, err
	}
	defer f.Close()
	r := bufio.NewScanner(f)
	for r.Scan() {
		files = append(files, r.Text())
	}
	return files, r.Err()
}

func (bl *Local) MasterStatus() (file string, pos uint32, err error) {
	files, err := bl.ListFiles()
	if err != nil {
		return "", 0, err
	}
	if len(files) == 0 {
		return "", 0, nil
	}
	file = files[len(files)-1]

	f, err := os.Open(path.Join(bl.dir, file))
	if err != nil {
		return "", 0, fmt.Errorf("binlog.Local.MasterStatus: error in open file: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}

	// Skip file header.
	_, err = f.Seek(4, io.SeekStart)
	if err != nil {
		return
	}
	pos += 4

	buf := make([]byte, 13)
	for {
		_, err = io.ReadFull(f, buf)
		if err == io.EOF {
			err = nil
			return
		}
		if err != nil {
			return
		}
		// Timestamp = buf[:4]
		// EventType := buf[4]
		// ServerID = buf[5:9]
		eventSize := binary.LittleEndian.Uint32(buf[9:])
		if int64(pos+eventSize-13) > fi.Size() {
			// partial record found
			return
		}
		if _, err = f.Seek(int64(eventSize-13), io.SeekCurrent); err != nil {
			return
		}
		pos += eventSize
	}
}

func (bl *Local) Seek(file string) error {
	bl.binlogFile, bl.binlogPos = file, 4
	r, err := newDirReader(bl.dir, &bl.binlogFile)
	if err != nil {
		return err
	}
	bl.conn = r
	return nil
}

func (bl *Local) ReadStatus() (filename string, position uint32) {
	if bl.binlogReader == nil {
		return bl.binlogFile, bl.binlogPos
	}
	return bl.binlogReader.binlogFile, bl.binlogReader.binlogPos
}

func (bl *Local) NextEvent() (Event, error) {
	r := bl.binlogReader
	if r == nil {
		v, err := findBinlogVersion(path.Join(bl.dir, bl.binlogFile))
		if err != nil {
			return Event{}, err
		}
		r = &reader{
			rd:       bl.conn,
			tmeCache: bl.conn.tmeCache,
			limit:    -1,
		}
		r.fde = formatDescriptionEvent{binlogVersion: v}
		bl.binlogReader = r
	} else {
		r.limit += 4
		if err := r.drain(); err != nil {
			return Event{}, fmt.Errorf("binlog.NextEvent: error in draining event: %v", err)
		}
		r.limit = -1
	}

	return nextEvent(r)
}

func (bl *Local) NextRow() (values []interface{}, valuesBeforeUpdate []interface{}, err error) {
	return nextRow(bl.binlogReader)
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

package binlog

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type Local struct {
	dir  string
	conn *dirReader

	binlogReader *reader
	checksum     int
}

func Open(dir string) (*Local, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("binlog.Open: %q is not a directory", dir)
	}
	return &Local{dir: dir, checksum: 4}, nil // todo: checksum
}

func (bl *Local) ListFiles() ([]string, error) {
	var files []string
	for {
		name := ".next"
		if len(files) > 0 {
			name = files[len(files)-1] + ".next"
		}
		f, err := os.Open(path.Join(bl.dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				return files, nil
			}
			return nil, err
		}
		buff, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}
		files = append(files, strings.TrimSpace(string(buff)))
	}
	return files, nil
}

func (bl *Local) addFile(name string) error {
	files, err := bl.ListFiles()
	if err != nil {
		return err
	}
	if err := ensureBinlogFile(path.Join(bl.dir, name)); err != nil {
		return err
	}
	next := ".next"
	if len(files) > 0 {
		if files[len(files)-1] == name {
			return nil
		}
		next = files[len(files)-1] + ".next"
	}
	return ioutil.WriteFile(path.Join(bl.dir, next), []byte(name), 0666)
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
	pos = 4

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
		if int64(pos+eventSize) > fi.Size() {
			// partial record found
			return
		}
		pos += eventSize
		if _, err = f.Seek(int64(pos), io.SeekStart); err != nil {
			return
		}

	}
}

func (bl *Local) Seek(serverID uint32, fileName string, position uint32) error {
	//todo: what about serverID and position
	r, err := newDirReader(bl.dir, &fileName)
	if err != nil {
		return err
	}
	bl.conn = r
	return nil
}

func (bl *Local) NextEvent() (Event, error) {
	r := bl.binlogReader
	if r == nil {
		v, err := findBinlogVersion(bl.conn.file.Name())
		if err != nil {
			return Event{}, err
		}
		r = &reader{
			rd:         bl.conn,
			tmeCache:   bl.conn.tmeCache,
			binlogFile: *bl.conn.name,
			limit:      -1,
		}
		bl.conn.name = &r.binlogFile
		r.fde = FormatDescriptionEvent{BinlogVersion: v}
		bl.binlogReader = r
	} else {
		r.limit += bl.checksum
		if err := r.drain(); err != nil {
			return Event{}, fmt.Errorf("binlog.NextEvent: error in draining event: %v", err)
		}
		r.limit = -1
	}

	return nextEvent(r, bl.checksum)
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

func ensureBinlogFile(file string) error {
	stat, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return ioutil.WriteFile(file, fileHeader, 0666)
		}
		return err
	}
	if stat.IsDir() {
		return fmt.Errorf("%s is directory", file)
	}
	if stat.Size() < headerSize {
		return ioutil.WriteFile(file, fileHeader, 0666)
	}
	return nil
}

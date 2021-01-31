package binlog

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
)

func (c *conn) dump(dir string) error {
	v, err := c.binlogVersion()
	if err != nil {
		return err
	}
	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	buf := make([]byte, 14)
	for {
		fmt.Println("--------------------------------")
		r := &packetReader{rd: c.conn, seq: &c.seq}
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if buf[0] != okMarker {
			return fmt.Errorf("binlog.dump: got %0x want OK-byte", buf[0])
		}
		// timestamp = buf[1:5]
		eventType := buf[5]
		// serverID = buf[6:10]
		eventSize := binary.LittleEndian.Uint32(buf[10:])
		fmt.Printf("eventType: 0x%02x eventSize: 0x%02x\n", eventType, eventSize)
		switch eventType {
		case ROTATE_EVENT:
			lr := io.LimitReader(r, int64(eventSize-13))
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
			f, err = createFile(dir, string(buf))
			if err != nil {
				return err
			}
		default:
			lr := io.LimitReader(r, int64(eventSize-13))
			if _, err := f.Write(buf[1:]); err != nil {
				return err
			}
			if _, err := io.Copy(f, lr); err != nil {
				return err
			}
		}
	}
}

func appendLine(file, line string) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("binlog.appendLine: error in appending to binlog.index: %v", err)
	}
	return f.Close()
}

func createFile(dir, file string) (*os.File, error) {
	f, err := os.Create(path.Join(dir, file))
	if err != nil {
		return nil, err
	}
	if _, err := f.Write([]byte{0xfe, 'b', 'i', 'n'}); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := appendLine(path.Join(dir, "binlog.index"), file); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func fetchLastLocation(dir string) (file string, pos uint32, err error) {
	// Find last file in dir.
	f, err := os.Open(path.Join(dir, "binlog.index"))
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	r := bufio.NewScanner(f)
	var last string
	for r.Scan() {
		last = r.Text()
	}
	if r.Err() != nil {
		return "", 0, err
	}

	f, err = os.Open(path.Join(dir, last))
	if err != nil {
		return "", 0, fmt.Errorf("binlog.fetchLocation: error in open last file: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	_, err = f.Seek(4, io.SeekStart)
	if err != nil {
		return
	}
	pos += 4

	buf := make([]byte, 13)
	for {
		fmt.Println("pos", pos)
		_, err = io.ReadFull(f, buf)
		if err == io.EOF {
			err = nil
			return
		}
		if err != nil {
			return
		}
		// timestamp = buf[:4]
		// eventType := buf[4]
		// serverID = buf[5:9]
		eventSize := binary.LittleEndian.Uint32(buf[9:])
		if int64(pos+eventSize-13) > fi.Size() {
			// partial record found
			fmt.Println("partial record", pos, eventSize, fi.Size())
			return
		}
		if _, err = f.Seek(int64(eventSize-13), io.SeekCurrent); err != nil {
			return
		}
		pos += eventSize
	}
}

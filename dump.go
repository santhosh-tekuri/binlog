package binlog

import (
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
			fmt.Println("creating file", string(buf))
			if err := appendLine(path.Join(dir, "binlog.index"), string(buf)); err != nil {
				return fmt.Errorf("binlog.dump: error in appending to binlog.index: %v", err)
			}
			f, err = os.Create(path.Join(dir, string(buf)))
			if err != nil {
				return err
			}
			if _, err := f.Write([]byte{0xfe, 'b', 'i', 'n'}); err != nil {
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
		return err
	}
	return f.Close()
}

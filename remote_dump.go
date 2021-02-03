package binlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
)

func (bl *Remote) Dump(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("binlog.Dump: %q is not a directory", dir)
	}
	v, err := bl.binlogVersion()
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
		r := &packetReader{rd: bl.conn, seq: &bl.seq}
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if buf[0] == errMarker {
			buff := bytes.NewBuffer(buf)
			if _, err := buff.ReadFrom(r); err != nil {
				return err
			}
			buf := buff.Bytes()
			if len(buf) < 3 {
				return fmt.Errorf("binlog.dump: got %0x want OK-byte", errMarker)
			}
			buf = buf[3:] // errHeader, errCode
			if bl.hs.capabilityFlags&capProtocol41 != 0 {
				if len(buf) < 6 {
					return fmt.Errorf("binlog.dump: got %0x want OK-byte", errMarker)
				}
				buf = buf[6:] // sqlStateMarker, sqlState
			}
			return errors.New(string(buf))
		}
		if buf[0] != okMarker {
			return fmt.Errorf("binlog.Dump: got %0x want OK-byte", buf[0])
		}
		// Timestamp = buf[1:5]
		eventType := EventType(buf[5])
		// ServerID = buf[6:10]
		eventSize := binary.LittleEndian.Uint32(buf[10:])
		fmt.Printf("EventType: 0x%02x EventSize: 0x%02x\n", eventType, eventSize)
		switch eventType {
		case HEARTBEAT_EVENT, UNKNOWN_EVENT, SLAVE_EVENT:
			// Ignore this event.
			if _, err := io.Copy(ioutil.Discard, r); err != nil {
				return err
			}
		case ROTATE_EVENT:
			lr := io.LimitReader(r, int64(eventSize-13))
			buf, err := ioutil.ReadAll(lr)
			if err != nil {
				return err
			}
			if v > 1 {
				buf = buf[4+2+8 : len(buf)-4] // LogPos, Flags, position and exclude checksum
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
	if _, err := f.Write(fileHeader); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := appendLine(path.Join(dir, "binlog.index"), file); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

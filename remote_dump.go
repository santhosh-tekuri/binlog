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
	// ignore FormatDescriptionEvent if it is not the first event in file
	ignoreFME := bl.requestPos > 4
	buf := make([]byte, 14)
	for {
		fmt.Println("--------------------------------")
		pr := &packetReader{rd: bl.conn, seq: &bl.seq}
		if n, err := io.ReadFull(pr, buf); err != nil {
			if err != io.ErrUnexpectedEOF { // non-ok packets can have size <14
				return err
			}
			buf = buf[:n]
		}
		if buf[0] != okMarker {
			r := &reader{
				rd:    io.MultiReader(bytes.NewReader(buf), pr),
				limit: -1,
			}
			switch buf[0] {
			case errMarker:
				ep := errPacket{}
				if err := ep.parse(r, bl.hs.capabilityFlags); err != nil {
					return err
				}
				return errors.New(ep.errorMessage)
			case eofMarker:
				ep := eofPacket{}
				if err := ep.parse(r, bl.hs.capabilityFlags); err != nil {
					return err
				}
				return io.EOF
			}
			return fmt.Errorf("binlog.Dump: got %0x want OK-byte", buf[0])
		}
		if len(buf) != 14 {
			return io.ErrUnexpectedEOF
		}
		// Timestamp = buf[1:5]
		eventType := EventType(buf[5])
		// ServerID = buf[6:10]
		eventSize := binary.LittleEndian.Uint32(buf[10:])
		fmt.Printf("EventType: %s EventSize: 0x%02x\n", eventType, eventSize)
		switch eventType {
		case ROTATE_EVENT:
			lr := io.LimitReader(pr, int64(eventSize-13))
			buf, err := ioutil.ReadAll(lr)
			if err != nil {
				return err
			}
			if v > 1 {
				buf = buf[4+2+8 : len(buf)-bl.checksum] // skip EventHeader{LogPos, Flags}, RotateEvent.position
			}
			if f != nil {
				if err := f.Close(); err != nil {
					return err
				}
			}
			fileName := string(buf)
			if bl.requestFile != fileName {
				ignoreFME = false
			}
			f, err = createFile(dir, fileName)
			if err != nil {
				return err
			}
		default:
			var ignore bool
			switch eventType {
			case HEARTBEAT_EVENT, UNKNOWN_EVENT, SLAVE_EVENT:
				ignore = true
			case FORMAT_DESCRIPTION_EVENT:
				ignore = ignoreFME
				ignoreFME = false
			}
			if ignore {
				if _, err := io.Copy(ioutil.Discard, pr); err != nil {
					return err
				}
			} else {
				lr := io.LimitReader(pr, int64(eventSize-13))
				if _, err := f.Write(buf[1:]); err != nil {
					return err
				}
				if _, err := io.Copy(f, lr); err != nil {
					return err
				}
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

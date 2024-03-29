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
	local, err := Open(dir)
	if err != nil {
		return err
	}
	v, err := bl.binlogVersion()
	if err != nil {
		return err
	}
	var f *os.File
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	// ignore FormatDescriptionEvent if it is not the first event in file
	ignoreFME := bl.requestPos > 4
	buf := make([]byte, 14)
	for {
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
				if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
					return err
				}
				return errors.New(ep.errorMessage)
			case eofMarker:
				ep := eofPacket{}
				if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
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
		//fmt.Printf("EventType: %s EventSize: 0x%02x\n", eventType, eventSize)
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
			pos := bl.requestPos
			if bl.requestFile != fileName {
				ignoreFME = false
				pos = 4
			}
			if err := local.addFile(fileName); err != nil {
				return err
			}
			f, err = os.OpenFile(path.Join(dir, fileName), os.O_RDWR, 0)
			if err != nil {
				return err
			}
			if _, err := f.Seek(int64(pos), io.SeekStart); err != nil {
				return err
			}
		default:
			var ignore bool
			switch eventType {
			case HEARTBEAT_EVENT, UNKNOWN_EVENT, SLAVE_EVENT, IGNORABLE_EVENT:
				ignore = true
			case FORMAT_DESCRIPTION_EVENT:
				ignore = ignoreFME
				ignoreFME = false
			}
			if ignore {
				fmt.Println("ignoring...")
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

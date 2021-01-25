package binlog

import "fmt"

const (
	eofMarker = 0xfe
)

type eofPacket struct {
	warnings    uint16
	statusFlags uint16
}

func (e *eofPacket) parse(r *reader) (err error) {
	if header, err := r.int1(); err != nil {
		return err
	} else if header != eofMarker {
		return fmt.Errorf("eofPacket.parse: got header %0xd", header)
	}
	if e.warnings, err = r.int2(); err != nil {
		return err
	}
	if e.statusFlags, err = r.int2(); err != nil {
		return err
	}
	return nil
}

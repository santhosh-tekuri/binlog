package binlog

import "fmt"

const (
	eofMarker = 0xfe
)

type eofPacket struct {
	warnings    uint16
	statusFlags uint16
}

func (e *eofPacket) parse(r *reader) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != eofMarker {
		return fmt.Errorf("eofPacket.parse: got header %0xd", header)
	}
	e.warnings = r.int2()
	e.statusFlags = r.int2()
	return r.err
}

package binlog

import "fmt"

const (
	errMarker = 0xFF
	okMarker  = 0x00
)

type errPacket struct {
	errorCode      uint16
	sqlStateMarker string
	sqlState       string
	errorMessage   string
}

func (e *errPacket) parse(r *reader, capabilities uint32) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != errMarker {
		return fmt.Errorf("errorPacket.parse: got header %0xd", header)
	}
	e.errorCode = r.int2()

	if capabilities&CLIENT_PROTOCOL_41 != 0 {
		e.sqlStateMarker = r.string(1)
		e.sqlState = r.string(5)
	}
	e.errorMessage = r.stringEOF()
	return r.err
}

package binlog

import "fmt"

const errMarker = 0xFF

type errPacket struct {
	errorCode      uint16
	sqlStateMarker string
	sqlState       string
	errorMessage   string
}

func (e *errPacket) parse(r *reader) (err error) {
	if header, err := r.int1(); err != nil {
		return err
	} else if header != errMarker {
		return fmt.Errorf("errorPacket.parse: got header %0xd", header)
	}
	if e.errorCode, err = r.int2(); err != nil {
		return err
	}

	// todo
	// if capabilities & CLIENT_PROTOCOL_41 {
	if e.sqlStateMarker, err = r.string(1); err != nil {
		return err
	}
	if e.sqlState, err = r.string(5); err != nil {
		return err
	}
	//}
	if e.errorMessage, err = r.stringEOF(); err != nil {
		return err
	}
	return nil
}

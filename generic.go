package binlog

import (
	"errors"
	"fmt"
)

// Status Flags: https://dev.mysql.com/doc/internals/en/status-flags.html
const (
	sessionStateChanged = 0x4000
)

// Packet Markers
const (
	okMarker  = 0x00
	eofMarker = 0xfe
	errMarker = 0xff
)

// eofPacket contains warnings and status flags.
// EOF packets are deprecated. From MySQL 5.7.5,
// OK packets are used to indicate EOF.
//
// https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
type eofPacket struct {
	warnings    uint16
	statusFlags uint16
}

func (e *eofPacket) decode(r *reader, capabilities uint32) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != eofMarker {
		return fmt.Errorf("binlog: eofPacket.header is %0xd", header)
	}
	if capabilities&capProtocol41 != 0 {
		e.warnings = r.int2()
		e.statusFlags = r.int2()
	}
	return r.err
}

// errPacket signals that an error occurred.
//
// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
type errPacket struct {
	errorCode      uint16
	sqlStateMarker string
	sqlState       string
	errorMessage   string
}

func (e *errPacket) decode(r *reader, capabilities uint32) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != errMarker {
		return fmt.Errorf("binlog: errPacket.header is %0xd", header)
	}
	e.errorCode = r.int2()

	if capabilities&capProtocol41 != 0 {
		e.sqlStateMarker = r.string(1)
		e.sqlState = r.string(5)
	}
	e.errorMessage = r.stringEOF()
	return r.err
}

// okPacket signals successful completion of a command.
//
// https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
type okPacket struct {
	affectedRows        uint64
	lastInsertID        uint64
	statusFlags         uint16
	numWarnings         uint16
	info                string
	sessionStateChanges string
}

func (p *okPacket) decode(r *reader, capabilities uint32) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != okMarker {
		return fmt.Errorf("binlog: okPacket.header is %0xd", header)
	}
	p.affectedRows = r.intN()
	p.lastInsertID = r.intN()
	if capabilities&capProtocol41 != 0 {
		p.statusFlags = r.int2()
		p.numWarnings = r.int2()
	} else if capabilities&capTransactions != 0 {
		p.statusFlags = r.int2()
	}
	if r.err != nil {
		return r.err
	}
	if capabilities&capSessionTrack != 0 {
		p.info = r.stringN()
		if p.statusFlags&sessionStateChanged != 0 {
			p.sessionStateChanges = r.stringN()
		}
	} else {
		p.info = r.stringEOF()
	}
	return r.err
}

// readOkErr reads ok/err packet based on marker.
func (bl *Remote) readOkErr() error {
	r := newReader(bl.conn, &bl.seq)
	marker, err := r.peek()
	if err != nil {
		return err
	}
	switch marker {
	case okMarker:
		return r.drain()
	case errMarker:
		ep := errPacket{}
		if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
			return err
		}
		return errors.New(ep.errorMessage)
	default:
		return ErrMalformedPacket
	}
}

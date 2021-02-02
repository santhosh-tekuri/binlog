package binlog

import "fmt"

// https://dev.mysql.com/doc/internals/en/status-flags.html
const (
	SERVER_SESSION_STATE_CHANGED = 0x4000
)

// eofPacket ---

// https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html

const eofMarker = 0xfe

type eofPacket struct {
	warnings    uint16
	statusFlags uint16
}

func (e *eofPacket) parse(r *reader, capabilities uint32) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != eofMarker {
		return fmt.Errorf("eofPacket.parse: got header %0xd", header)
	}
	if capabilities&capProtocol41 != 0 {
		e.warnings = r.int2()
		e.statusFlags = r.int2()
	}
	return r.err
}

// errPacket ---

// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html

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

	if capabilities&capProtocol41 != 0 {
		e.sqlStateMarker = r.string(1)
		e.sqlState = r.string(5)
	}
	e.errorMessage = r.stringEOF()
	return r.err
}

// okPacket ---

// https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html

type okPacket struct {
	affectedRows        uint64
	lastInsertID        uint64
	statusFlags         uint16
	numWarnings         uint16
	info                string
	sessionStateChanges string
}

func (p *okPacket) parse(r *reader, capabilities uint32) error {
	header := r.int1()
	if r.err != nil {
		return r.err
	}
	if header != okMarker {
		return fmt.Errorf("okPacket.parse: got header %0xd", header)
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
		if p.statusFlags&SERVER_SESSION_STATE_CHANGED != 0 {
			p.sessionStateChanges = r.stringN()
		}
	} else {
		p.info = r.stringEOF()
	}
	return r.err
}

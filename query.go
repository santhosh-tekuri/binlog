package binlog

import (
	"errors"
	"fmt"
	"io"
)

// queryResponse holds one of the following values
// okPacket, *resultSet
type queryResponse interface{}

func (bl *Remote) queryRows(q string) ([][]interface{}, error) {
	resp, err := bl.query(q)
	if err != nil {
		return nil, err
	}
	rs := resp.(*resultSet)
	return rs.rows()
}

func (bl *Remote) query(q string) (queryResponse, error) {
	bl.seq = 0
	w := newWriter(bl.conn, &bl.seq)
	if err := w.query(q); err != nil {
		return nil, err
	}
	r := newReader(bl.conn, &bl.seq)
	b, err := r.peek()
	if err != nil {
		return nil, err
	}
	switch b {
	case okMarker:
		ok := okPacket{}
		if err := ok.parse(r, bl.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return ok, nil
	case errMarker:
		ep := errPacket{}
		if err := ep.parse(r, bl.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return nil, errors.New(ep.errorMessage)
	default:
		rs := resultSet{}
		if err := rs.parse(r, bl.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return &rs, nil
	}
}

// https://dev.mysql.com/doc/internals/en/com-query-response.html#column-definition

type columnDef struct {
	schema       string
	table        string
	orgTable     string
	name         string
	orgName      string
	charset      uint16
	columnLength uint32
	typ          uint8
	flags        uint16
	decimals     uint8
}

func (cd *columnDef) parse(r *reader, capabilities uint32) error {
	if capabilities&CLIENT_PROTOCOL_41 != 0 {
		_ = r.stringN() // catalog (always "def")
		cd.schema = r.stringN()
		cd.table = r.stringN()
		cd.orgTable = r.stringN()
		cd.name = r.stringN()
		cd.orgName = r.stringN()
		_ = r.intN() // next_length -- length of the following fields (always 0x0c)
		cd.charset = r.int2()
		cd.columnLength = r.int4()
		cd.typ = r.int1()
		cd.flags = r.int2()
		cd.decimals = r.int1()
		_ = r.skip(2) // filler
		return r.err
	} else {
		return fmt.Errorf("Protocol::ColumnDefinition320 not implemented yet")
	}
}

type resultSet struct {
	r            *reader
	capabilities uint32
	columnDefs   []columnDef
}

func (rs *resultSet) parse(r *reader, capabilities uint32) error {
	rs.r, rs.capabilities = r, capabilities

	ncol := r.intN()
	if r.err != nil {
		return r.err
	}
	if r.more() {
		return ErrMalformedPacket
	}

	// Parse Column Definitions.
	for i := uint64(0); i < ncol; i++ {
		r.rd.(*packetReader).reset()
		cd := columnDef{}
		if err := cd.parse(r, capabilities); err != nil {
			return err
		}
		if r.more() {
			return ErrMalformedPacket
		}
		rs.columnDefs = append(rs.columnDefs, cd)
	}

	// Parse EOF Packet.
	r.rd.(*packetReader).reset()
	eof := eofPacket{}
	return eof.parse(r, capabilities)
}

func (rs *resultSet) nextRow() ([]interface{}, error) {
	r := rs.r
	r.rd.(*packetReader).reset()
	b, err := r.peek()
	if err != nil {
		return nil, err
	}
	switch b {
	case eofMarker:
		eof := eofPacket{}
		if err := eof.parse(r, rs.capabilities); err != nil {
			return nil, err
		}
		return nil, io.EOF
	case errMarker:
		ep := errPacket{}
		if err := ep.parse(r, rs.capabilities); err != nil {
			return nil, err
		}
		return nil, errors.New(ep.errorMessage)
	default:
		row := make([]interface{}, len(rs.columnDefs))
		for i, _ := range row {
			b, err := r.peek()
			if err != nil {
				return nil, err
			}
			if b == 0xfb {
				row[i] = Null{}
			} else {
				row[i] = r.stringN()
				if r.err != nil {
					return nil, r.err
				}
			}
		}
		return row, nil
	}
}

func (rs *resultSet) rows() ([][]interface{}, error) {
	var rows [][]interface{}
	for {
		row, err := rs.nextRow()
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		rows = append(rows, row)
	}
	return rows, nil
}

package binlog

import (
	"errors"
	"fmt"
	"io"
)

// queryResponse holds one of the following values:
// okPacket, *resultSet.
//
// https://dev.mysql.com/doc/internals/en/com-query-response.html
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
		if err := ok.decode(r, bl.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return ok, nil
	case errMarker:
		ep := errPacket{}
		if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return nil, errors.New(ep.errorMessage)
	default:
		rs := resultSet{}
		if err := rs.decode(r, bl.hs.capabilityFlags); err != nil {
			return nil, err
		}
		return &rs, nil
	}
}

// columnDef is column definition for resultSet.
//
// https://dev.mysql.com/doc/internals/en/com-query-response.html#column-definition
type columnDef struct {
	schema       string
	table        string // virtual table-name
	orgTable     string // physical table-name
	name         string // virtual column name
	orgName      string // physical column name
	charset      uint16
	columnLength uint32 // maximum length of the field
	typ          uint8
	flags        uint16
	decimals     uint8
}

func (cd *columnDef) decode(r *reader, capabilities uint32) error {
	if capabilities&capProtocol41 != 0 {
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
	}
	return fmt.Errorf("binlog: Protocol::ColumnDefinition320 not implemented yet")
}

// resultSet made up of two parts.
// 1. column definitions
//    - starts with a packet containing the column-count
//    - followed by as many columnDef packets as there are columns
//    - terminated by eofPacket, if the capDeprecateEOF is not set
// 2. rows
//    - each row is a packet
//    - terminated by eofPacket or errPacket
//
// https://dev.mysql.com/doc/internals/en/com-query-response.html#text-resultset
type resultSet struct {
	r            *reader
	capabilities uint32
	columnDefs   []columnDef
}

func (rs *resultSet) decode(r *reader, capabilities uint32) error {
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
		if err := cd.decode(r, capabilities); err != nil {
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
	return eof.decode(r, capabilities)
}

// null represents null in resultSet.
type null struct{}

// nextRow returns data of next row. Returns io.EOF
// if there are no more rows.
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
		if err := eof.decode(r, rs.capabilities); err != nil {
			return nil, err
		}
		return nil, io.EOF
	case errMarker:
		ep := errPacket{}
		if err := ep.decode(r, rs.capabilities); err != nil {
			return nil, err
		}
		return nil, errors.New(ep.errorMessage)
	default:
		row := make([]interface{}, len(rs.columnDefs))
		for i := range row {
			b, err := r.peek()
			if err != nil {
				return nil, err
			}
			if b == 0xfb {
				row[i] = null{}
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

// rows is helper method to collect rows into [][]interface{}.
func (rs *resultSet) rows() ([][]interface{}, error) {
	var rows [][]interface{}
	for {
		row, err := rs.nextRow()
		if err == io.EOF {
			return rows, nil
		} else if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
}

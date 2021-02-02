package binlog

import (
	"fmt"
	"io"
)

// https://dev.mysql.com/doc/internals/en/table-map-event.html

type Column struct {
	Type     byte
	Nullable bool
	Name     *string
	meta     []byte
}

type tableMapEvent struct {
	tableID        uint64
	flags          uint16
	SchemaName     string
	TableName      string
	Columns        []Column
	signedness     []byte // for numeric columns
	defaultCharset []byte
	columnCharset  []byte
}

func (e *tableMapEvent) parse(r *reader) error {
	e.tableID = r.int6()
	e.flags = r.int2()
	_ = r.int1() // schema name length
	e.SchemaName = r.stringNull()
	_ = r.int1() // table name length
	e.TableName = r.stringNull()
	numCol := r.intN()
	if r.err != nil {
		return r.err
	}
	e.Columns = make([]Column, numCol)
	for i := range e.Columns {
		e.Columns[i].Type = r.int1()
	}

	_ = r.intN() // meta length
	for i, col := range e.Columns {
		switch col.Type {
		default:
		case MYSQL_TYPE_BLOB, MYSQL_TYPE_DOUBLE, MYSQL_TYPE_FLOAT, MYSQL_TYPE_GEOMETRY, MYSQL_TYPE_JSON,
			MYSQL_TYPE_TIME2, MYSQL_TYPE_DATETIME2, MYSQL_TYPE_TIMESTAMP2:
			e.Columns[i].meta = r.bytes(1)
		case MYSQL_TYPE_VARCHAR, MYSQL_TYPE_BIT, MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL,
			MYSQL_TYPE_SET, MYSQL_TYPE_ENUM, MYSQL_TYPE_STRING, MYSQL_TYPE_VAR_STRING:
			e.Columns[i].meta = r.bytes(2)
		}
	}

	nullability := bitmap(r.bytes(bitmapSize(numCol)))
	for i := range e.Columns {
		e.Columns[i].Nullable = nullability.isTrue(i)
	}

	for r.more() {
		typ := r.int1()
		len := int(r.intN())
		if r.err != nil {
			break
		}
		switch typ {
		case 1:
			e.signedness = r.bytes(len)
		case 2:
			e.defaultCharset = r.bytes(len)
		case 3:
			e.columnCharset = r.bytes(len)
		case 4:
			for i := range e.Columns {
				name := r.stringN()
				e.Columns[i].Name = &name
			}
		default:
			r.skip(len)
		}
	}

	return r.err
}

// https://dev.mysql.com/doc/internals/en/rows-event.html

type RowsEvent struct {
	eventType  EventType
	tableID    uint64
	tme        *tableMapEvent
	flags      uint16
	numCol     uint64
	present    []bitmap
	colOrdinal [][]int
}

func (e *RowsEvent) parse(r *reader, eventType EventType) error {
	e.eventType = eventType
	if r.fde.postHeaderLength(eventType, 8) == 6 {
		e.tableID = uint64(r.int4())
	} else {
		e.tableID = r.int6()
	}
	if e.tableID == 0x00ffffff {
		// dummy RowsEvent
		r.tme = nil
	} else {
		var ok bool
		if e.tme, ok = r.tmeCache[e.tableID]; !ok {
			return fmt.Errorf("no tableMapEvent for tableID %d", e.tableID)
		}
		r.tme = e.tme
	}

	e.flags = r.int2()
	switch eventType {
	case WRITE_ROWS_EVENTv2, UPDATE_ROWS_EVENTv2, DELETE_ROWS_EVENTv2: // version==2
		extraDataLength := r.int2()
		if r.err != nil {
			return r.err
		}
		_ = r.string(int(extraDataLength - 2))
	}
	e.numCol = r.intN()
	if r.err != nil {
		return r.err
	}
	if e.numCol == 0 {
		// dummy RowsEvent
		r.tme = nil
	}

	e.present = make([]bitmap, 2)
	e.colOrdinal = make([][]int, 2)
	e.present[0] = r.bytes(bitmapSize(e.numCol))
	for i := 0; i < int(e.numCol); i++ {
		if e.present[0].isTrue(i) {
			e.colOrdinal[0] = append(e.colOrdinal[0], i)
		}
	}
	switch eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		e.present[1] = r.bytes(bitmapSize(e.numCol))
		for i := 0; i < int(e.numCol); i++ {
			if e.present[1].isTrue(i) {
				e.colOrdinal[1] = append(e.colOrdinal[1], i)
			}
		}
	}

	return r.err
}

func nextRow(r *reader) ([][]interface{}, error) {
	if r.tme == nil {
		// dummy RowsEvent
		return nil, io.EOF
	}
	if !r.more() {
		if r.err != nil {
			return nil, r.err
		}
		return nil, io.EOF
	}
	row := make([][]interface{}, 2)
	n := 1
	switch r.re.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		n = 2
	}
	for m := 0; m < n; m++ {
		nullValue := bitmap(r.bytes(bitmapSize(r.re.numCol)))
		if r.err != nil {
			return nil, r.err
		}
		var values []interface{}
		for i, skipped := 0, 0; i < int(r.re.numCol); i++ {
			if !r.re.present[m].isTrue(i) {
				skipped++
				continue
			}
			if nullValue.isTrue(i - skipped) {
				values = append(values, nil)
			} else {
				v, err := parseValue(r, r.tme.Columns[i].Type, r.tme.Columns[i].meta)
				if err != nil {
					return row, err
				}
				values = append(values, v)
			}
		}
		row[m] = values
	}
	return row, nil
}

// system variable binlog_rows_query_log_events must be ON for this event
// https://dev.mysql.com/doc/refman/5.7/en/replication-options-binary-log.html#sysvar_binlog_rows_query_log_events

type rowsQueryEvent struct {
	query string
}

func (e *rowsQueryEvent) parse(r *reader) error {
	r.int1() // length ignored
	e.query = r.stringEOF()
	return r.err
}

// bitmap ---

type bitmap []byte

func bitmapSize(numCol uint64) int {
	return int((numCol + 7) / 8)
}

func (bm bitmap) isTrue(colID int) bool {
	return (bm[colID/8]>>uint8(colID%8))&1 == 1
}

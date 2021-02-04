package binlog

import (
	"fmt"
	"io"
)

// https://dev.mysql.com/doc/internals/en/table-map-event.html

type Column struct {
	Type     byte
	Nullable bool
	Unsigned bool
	Name     string
	meta     []byte
}

type tableMapEvent struct {
	tableID        uint64
	flags          uint16
	SchemaName     string
	TableName      string
	Columns        []Column
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
		size := int(r.intN())
		if r.err != nil {
			break
		}
		switch typ {
		case 1:
			signedness := bitmap(r.bytes(size))
			inum := 0
			for i := range e.Columns {
				switch e.Columns[i].Type {
				case MYSQL_TYPE_TINY, MYSQL_TYPE_SHORT, MYSQL_TYPE_INT24, MYSQL_TYPE_LONG, MYSQL_TYPE_LONGLONG,
					MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE, MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL:
					e.Columns[i].Unsigned = signedness.isTrue(inum)
					inum++
				}
			}
		case 2:
			e.defaultCharset = r.bytes(size)
		case 3:
			e.columnCharset = r.bytes(size)
		case 4:
			for i := range e.Columns {
				e.Columns[i].Name = r.stringN()
			}
		default:
			r.skip(size)
		}
	}

	return r.err
}

// https://dev.mysql.com/doc/internals/en/rows-event.html

type RowsEvent struct {
	eventType EventType
	tableID   uint64
	tme       *tableMapEvent
	flags     uint16
	Columns   [][]Column
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
	numCol := r.intN()
	if r.err != nil {
		return r.err
	}
	if numCol == 0 {
		// dummy RowsEvent
		r.tme = nil
	}

	e.Columns = make([][]Column, 2)
	present := bitmap(r.bytes(bitmapSize(numCol)))
	for i := 0; i < int(numCol); i++ {
		if present.isTrue(i) {
			e.Columns[0] = append(e.Columns[0], e.tme.Columns[i])
		}
	}
	switch eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		present = bitmap(r.bytes(bitmapSize(numCol)))
		for i := 0; i < int(numCol); i++ {
			if present.isTrue(i) {
				e.Columns[1] = append(e.Columns[1], e.tme.Columns[i])
			}
		}
	}

	return r.err
}

func nextRow(r *reader) (values []interface{}, valuesBeforeUpdate []interface{}, err error) {
	if r.tme == nil {
		// dummy RowsEvent
		return nil, nil, io.EOF
	}
	if !r.more() {
		if r.err != nil {
			return nil, nil, r.err
		}
		return nil, nil, io.EOF
	}
	row := make([][]interface{}, 2)
	n := 1
	switch r.re.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		n = 2
	}
	for m := 0; m < n; m++ {
		nullValue := bitmap(r.bytes(bitmapSize(uint64(len(r.re.Columns[m])))))
		if r.err != nil {
			return nil, nil, r.err
		}
		var values []interface{}
		for i := range r.re.Columns[m] {
			if nullValue.isTrue(i) {
				values = append(values, nil)
			} else {
				v, err := parseValue(r, r.tme.Columns[i])
				if err != nil {
					return nil, nil, err
				}
				values = append(values, v)
			}
		}
		row[m] = values
	}
	switch r.re.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		return row[1], row[0], nil
	default:
		return row[0], nil, nil
	}
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
	return bm[colID/8]&(1<<uint(7-colID%8)) != 0
}

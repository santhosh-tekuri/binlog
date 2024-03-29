package binlog

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Column captures column info for TableMapEvent and RowsEvent.
type Column struct {
	Ordinal  int
	Type     ColumnType
	Nullable bool
	Unsigned bool
	Meta     uint16
	Charset  uint64 // value zero means unknown.

	// following are populated only if
	// system variable binlog_row_metadata==FULL
	Name   string
	Values []string // permitted values for Enum and Set type.
}

// TableMapEvent is first event used in Row Based Replication declares
// how a table that is about to be changed is defined.
//
// Used for row-based binary logging. This event precedes each row operation event.
// It maps a table definition to a number, where the table definition consists of
// database and table names and column definitions. The purpose of this event is
// to enable replication when a table has different definitions on the master and slave.
//
// Row operation events that belong to the same transaction may be grouped into sequences,
// in which case each such sequence of events begins with a sequence of TABLE_MAP_EVENT events:
// one per table used by events in the sequence.
//
// see https://dev.mysql.com/doc/internals/en/table-map-event.html
type TableMapEvent struct {
	tableID    uint64 // numeric table id
	flags      uint16
	SchemaName string
	TableName  string
	Columns    []Column
}

func (e *TableMapEvent) decode(r *reader) error {
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
		e.Columns[i].Ordinal = i
		e.Columns[i].Type = ColumnType(r.int1())
	}

	_ = r.intN() // meta length
	for i := range e.Columns {
		switch e.Columns[i].Type {
		default:
		case TypeBlob, TypeDouble, TypeFloat, TypeGeometry, TypeJSON,
			TypeTime2, TypeDateTime2, TypeTimestamp2:
			e.Columns[i].Meta = uint16(r.int1())
		case TypeVarchar, TypeBit, TypeDecimal, TypeNewDecimal,
			TypeSet, TypeEnum, TypeVarString:
			e.Columns[i].Meta = r.int2()
		case TypeString:
			meta := r.bytes(2)
			e.Columns[i].Meta = binary.BigEndian.Uint16(meta)
			if e.Columns[i].Meta >= 256 {
				b0, b1 := meta[0], meta[1]
				if b0&0x30 != 0x30 {
					e.Columns[i].Meta = uint16(b1) | (uint16((b0&0x30)^0x30) << 4)
					e.Columns[i].Type = ColumnType(b0 | 0x30)
				} else {
					e.Columns[i].Meta = uint16(b1)
					e.Columns[i].Type = ColumnType(b0)
				}
			}
		}
	}

	nullable := r.nullBitmap(numCol)
	if r.err != nil {
		return r.err
	}
	for i := range e.Columns {
		e.Columns[i].Nullable = nullable.isTrue(i)
	}

	// extended table metadata
	// see https://dev.mysql.com/worklog/task/?id=4618
	// see https://github.com/mysql/mysql-server/blob/8.0/libbinlogevents/include/rows_event.h#L544
	for r.more() {
		typ := r.int1()
		size := int(r.intN())
		if r.err != nil {
			break
		}
		switch typ {
		case 1: // UNSIGNED flag of numeric columns
			unsigned := r.bytesInternal(size)
			inum := 0
			for i := range e.Columns {
				if e.Columns[i].Type.isNumeric() {
					e.Columns[i].Unsigned = unsigned[inum/8]&(1<<uint(7-inum%8)) != 0
					inum++
				}
			}
		case 2: // Default character set of string columns
			if err := e.decodeDefaultCharset(r, size, ColumnType.isString); err != nil {
				return err
			}
		case 3: // Character set of string columns
			if err := e.decodeCharset(r, size, ColumnType.isString); err != nil {
				return err
			}
		case 4: // Column name
			for i := range e.Columns {
				e.Columns[i].Name = r.stringN()
			}
		case 5: // String value of SET columns
			if err := e.decodeValues(r, size, TypeSet); err != nil {
				return err
			}
		case 6: // String value of ENUM columns
			if err := e.decodeValues(r, size, TypeEnum); err != nil {
				return err
			}
		case 10: // Enum and Set default charset
			if err := e.decodeDefaultCharset(r, size, ColumnType.isEnumSet); err != nil {
				return err
			}
		case 11: // Enum and Set column charset
			if err := e.decodeCharset(r, size, ColumnType.isEnumSet); err != nil {
				return err
			}
		default:
			// 7 - Geometry type of geometry columns
			// 8 - Primary key without prefix
			// 9 - Primary key with prefix
			// 12 - Column Visibility
			r.skip(size)
		}
	}

	return r.err
}

func (e *TableMapEvent) decodeDefaultCharset(r *reader, size int, f func(ColumnType) bool) error {
	defCharset, n := r.intPacked()
	size -= n
	if r.err != nil {
		return r.err
	}
	for size > 0 {
		ord, n := r.intPacked()
		size -= n
		if r.err != nil {
			return r.err
		}
		charset, n := r.intPacked()
		size -= n
		e.Columns[ord].Charset = charset
		if r.err != nil {
			return r.err
		}
	}
	if size != 0 {
		return fmt.Errorf("invalid defaultCharset of columns")
	}
	for i := range e.Columns {
		if f(e.Columns[i].Type) && e.Columns[i].Charset == 0 {
			e.Columns[i].Charset = defCharset
		}
	}
	return nil
}

func (e *TableMapEvent) decodeCharset(r *reader, size int, f func(ColumnType) bool) error {
	for i := range e.Columns {
		if f(e.Columns[i].Type) {
			charset, n := r.intPacked()
			e.Columns[i].Charset = charset
			size -= n
			if r.err != nil {
				return r.err
			}
		}
	}
	if size != 0 {
		return fmt.Errorf("invalid columnCharset of columns")
	}
	return nil
}

func (e *TableMapEvent) decodeValues(r *reader, size int, typ ColumnType) error {
	var icol int
	for size > 0 {
		nVal, n := r.intPacked()
		size -= n
		if r.err != nil {
			return r.err
		}
		vals := make([]string, nVal)
		for i := range vals {
			l, n := r.intPacked()
			size -= n
			if r.err != nil {
				return r.err
			}
			vals[i] = r.string(int(l))
			size -= int(l)
			if r.err != nil {
				return r.err
			}
		}
		for e.Columns[icol].Type != typ {
			icol++
		}
		e.Columns[icol].Values = vals
		icol++
	}
	if size != 0 {
		return fmt.Errorf("invalid enum/set values")
	}
	return r.err
}

// RowsEvent captures changed rows in a table.
//
// see https://dev.mysql.com/doc/internals/en/rows-event.html
type RowsEvent struct {
	eventType EventType
	tableID   uint64
	TableMap  *TableMapEvent // associated TableMapEvent
	flags     uint16
	columns   [][]Column // column definitions
}

func (e *RowsEvent) decode(r *reader, eventType EventType) error {
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
		if e.TableMap, ok = r.tmeCache[e.tableID]; !ok {
			return fmt.Errorf("no tableMapEvent for tableID %d", e.tableID)
		}
		r.tme = e.TableMap
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

	e.columns = make([][]Column, 2)
	present := r.nullBitmap(numCol)
	if r.err != nil {
		return r.err
	}
	for i := 0; i < int(numCol); i++ {
		if present.isTrue(i) {
			e.columns[0] = append(e.columns[0], e.TableMap.Columns[i])
		}
	}
	switch eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		present = r.nullBitmap(numCol)
		if r.err != nil {
			return r.err
		}
		for i := 0; i < int(numCol); i++ {
			if present.isTrue(i) {
				e.columns[1] = append(e.columns[1], e.TableMap.Columns[i])
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
		nullValue := r.nullBitmap(uint64(len(r.re.columns[m])))
		if r.err != nil {
			return nil, nil, r.err
		}
		var values []interface{}
		for i := range r.re.columns[m] {
			if nullValue.isTrue(i) {
				values = append(values, nil)
			} else {
				v, err := r.tme.Columns[i].decodeValue(r)
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

// Columns returns columns info after update
func (e RowsEvent) Columns() []Column {
	switch e.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		return e.columns[1]
	default:
		return e.columns[0]
	}
}

// ColumnsBeforeUpdate returns columns after after update.
// returns nil, if rows were inserted.
func (e RowsEvent) ColumnsBeforeUpdate() []Column {
	switch e.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		return e.columns[0]
	default:
		return nil
	}
}

// RowsQueryEvent captures the query that caused the following ROWS_EVENT.
// see https://dev.mysql.com/doc/internals/en/rows-query-event.html
//
// system variable binlog_rows_query_log_events must be ON for this event.
// see https://dev.mysql.com/doc/refman/5.7/en/replication-options-binary-log.html#sysvar_binlog_rows_query_log_events
type RowsQueryEvent struct {
	Query string
}

func (e *RowsQueryEvent) decode(r *reader) error {
	r.int1() // length ignored
	e.Query = r.stringEOF()
	return r.err
}

// nullBitmap captures many NULL values more efficiently.
//
// https://dev.mysql.com/doc/internals/en/null-bitmap.html
type nullBitmap []byte

func (nb nullBitmap) isTrue(icol int) bool {
	return (nb[icol/8]>>uint8(icol%8))&1 == 1
}

func (r *reader) nullBitmap(numCol uint64) nullBitmap {
	size := int((numCol + 7) / 8)
	return r.bytes(size)
}

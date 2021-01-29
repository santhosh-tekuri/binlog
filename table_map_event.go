package binlog

// https://dev.mysql.com/doc/internals/en/table-map-event.html

type tableMapEvent struct {
	tableID           uint64
	flags             uint16
	schemaName        string
	tableName         string
	numCol            uint64
	columnTypes       []byte
	columnMeta        []int
	columnNullability bitmap
}

func (e *tableMapEvent) parse(r *reader) error {
	e.tableID = r.int6()
	e.flags = r.int2()
	_ = r.int1() // schema name length
	e.schemaName = r.stringNull()
	_ = r.int1() // table name length
	e.tableName = r.stringNull()
	e.numCol = r.intN()
	if r.err != nil {
		return r.err
	}
	e.columnTypes = r.bytes(int(e.numCol))

	_ = r.intN() // meta length
	e.columnMeta = make([]int, e.numCol)
	for i, columnType := range e.columnTypes {
		switch columnType {
		case MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE, MYSQL_TYPE_BLOB, MYSQL_TYPE_JSON, MYSQL_TYPE_GEOMETRY:
			e.columnMeta[i] = int(r.int1())
		case MYSQL_TYPE_BIT, MYSQL_TYPE_VARCHAR, MYSQL_TYPE_NEWDECIMAL:
			e.columnMeta[i] = int(r.int2())
		case MYSQL_TYPE_SET, MYSQL_TYPE_ENUM, MYSQL_TYPE_STRING:
			b := r.bytesInternal(2)
			if r.err != nil {
				return r.err
			}
			e.columnMeta[i] = int(uint16(b[1]) | uint16(b[0])<<8)
		case MYSQL_TYPE_TIME2, MYSQL_TYPE_DATETIME2, MYSQL_TYPE_TIMESTAMP2:
			e.columnMeta[i] = int(r.int1())
		}
	}

	e.columnNullability = r.bytes(bitmapSize(e.numCol))
	// todo: read extended metadata
	return r.err
}

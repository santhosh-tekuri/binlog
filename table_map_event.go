package binlog

// https://dev.mysql.com/doc/internals/en/table-map-event.html

type tableMapEvent struct {
	tableID           uint64
	flags             uint16
	schemaName        string
	tableName         string
	numCol            uint64
	columnTypes       []byte
	columnMeta        [][]byte
	columnNullability bitmap
	signedness        []byte // for numeric columns
	defaultCharset    []byte
	columnCharset     []byte
	columnNames       []string
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
	e.columnMeta = make([][]byte, e.numCol)
	for i, columnType := range e.columnTypes {
		switch columnType {
		default:
		case MYSQL_TYPE_BLOB, MYSQL_TYPE_DOUBLE, MYSQL_TYPE_FLOAT, MYSQL_TYPE_GEOMETRY, MYSQL_TYPE_JSON,
			MYSQL_TYPE_TIME2, MYSQL_TYPE_DATETIME2, MYSQL_TYPE_TIMESTAMP2:
			e.columnMeta[i] = r.bytes(1)
		case MYSQL_TYPE_VARCHAR, MYSQL_TYPE_BIT, MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL,
			MYSQL_TYPE_SET, MYSQL_TYPE_ENUM, MYSQL_TYPE_STRING, MYSQL_TYPE_VAR_STRING:
			e.columnMeta[i] = r.bytes(2)
		}
	}

	e.columnNullability = r.bytes(bitmapSize(e.numCol))

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
			e.columnNames = make([]string, e.numCol)
			for i, _ := range e.columnNames {
				e.columnNames[i] = r.stringN()
			}
		default:
			r.skip(len)
		}
	}

	return r.err
}

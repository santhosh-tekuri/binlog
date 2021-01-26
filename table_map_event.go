package binlog

type tableMapEvent struct {
	tableID     uint64
	flags       uint16
	schemaName  string
	tableName   string
	columnTypes []byte
}

func (e *tableMapEvent) parse(r *reader) error {
	e.tableID = r.int6()
	e.flags = r.int2()
	_ = r.int1() // schema name length
	e.schemaName = r.stringNull()
	_ = r.int1() // table name length
	e.tableName = r.stringNull()
	numCol := r.intN()
	if r.err != nil {
		return r.err
	}
	e.columnTypes = r.bytes(int(numCol))
	return r.err
}

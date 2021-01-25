package binlog

type tableMapEvent struct {
	tableID     uint64
	flags       uint16
	schemaName  string
	tableName   string
	columnTypes []byte
}

func (e *tableMapEvent) parse(r *reader) (err error) {
	if e.tableID, err = r.int6(); err != nil {
		return err
	}
	if e.flags, err = r.int2(); err != nil {
		return err
	}
	if _, err = r.int1(); err != nil { // schema name length
		return err
	}
	if e.schemaName, err = r.stringNull(); err != nil {
		return err
	}
	if _, err = r.int1(); err != nil { // table name length
		return err
	}
	if e.tableName, err = r.stringNull(); err != nil {
		return err
	}
	numCol, err := r.intN()
	if err != nil {
		return err
	}
	if e.columnTypes, err = r.bytes(int(numCol)); err != nil {
		return err
	}
	return nil
}

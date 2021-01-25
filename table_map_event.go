package binlog

type tableMapEvent struct {
	tableID    uint64
	flags      uint16
	schemaName string
	tableName  string
	//Columns    []*TableMapEventColumn
}

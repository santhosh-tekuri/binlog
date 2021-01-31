package binlog

// https://dev.mysql.com/doc/internals/en/binlog-event-type.html
// https://dev.mysql.com/doc/internals/en/event-meanings.html

type EventType uint8

const (
	UNKNOWN_EVENT            EventType = 0x00
	START_EVENT_V3           EventType = 0x01
	QUERY_EVENT              EventType = 0x02
	STOP_EVENT               EventType = 0x03
	ROTATE_EVENT             EventType = 0x04
	INTVAR_EVENT             EventType = 0x05
	LOAD_EVENT               EventType = 0x06
	SLAVE_EVENT              EventType = 0x07
	CREATE_FILE_EVENT        EventType = 0x08
	APPEND_BLOCK_EVENT       EventType = 0x09
	EXEC_LOAD_EVENT          EventType = 0x0a
	DELETE_FILE_EVENT        EventType = 0x0b
	NEW_LOAD_EVENT           EventType = 0x0c
	RAND_EVENT               EventType = 0x0d
	USER_VAR_EVENT           EventType = 0x0e
	FORMAT_DESCRIPTION_EVENT EventType = 0x0f
	XID_EVENT                EventType = 0x10
	BEGIN_LOAD_QUERY_EVENT   EventType = 0x11
	EXECUTE_LOAD_QUERY_EVENT EventType = 0x12
	TABLE_MAP_EVENT          EventType = 0x13
	WRITE_ROWS_EVENTv0       EventType = 0x14
	UPDATE_ROWS_EVENTv0      EventType = 0x15
	DELETE_ROWS_EVENTv0      EventType = 0x16
	WRITE_ROWS_EVENTv1       EventType = 0x17
	UPDATE_ROWS_EVENTv1      EventType = 0x18
	DELETE_ROWS_EVENTv1      EventType = 0x19
	INCIDENT_EVENT           EventType = 0x1a
	HEARTBEAT_EVENT          EventType = 0x1b
	IGNORABLE_EVENT          EventType = 0x1c
	ROWS_QUERY_EVENT         EventType = 0x1d
	WRITE_ROWS_EVENTv2       EventType = 0x1e
	UPDATE_ROWS_EVENTv2      EventType = 0x1f
	DELETE_ROWS_EVENTv2      EventType = 0x20
	GTID_EVENT               EventType = 0x21
	ANONYMOUS_GTID_EVENT     EventType = 0x22
	PREVIOUS_GTIDS_EVENT     EventType = 0x23
)

type Event struct {
	Header EventHeader
	Data   interface{}
}

var eventTypeNames = map[EventType]string{
	UNKNOWN_EVENT:            "unknown",
	START_EVENT_V3:           "startV3",
	QUERY_EVENT:              "query",
	STOP_EVENT:               "stop",
	ROTATE_EVENT:             "rotate",
	INTVAR_EVENT:             "inVar",
	LOAD_EVENT:               "load",
	SLAVE_EVENT:              "slave",
	CREATE_FILE_EVENT:        "createFile",
	APPEND_BLOCK_EVENT:       "appendBlock",
	EXEC_LOAD_EVENT:          "execLoad",
	DELETE_FILE_EVENT:        "deleteFile",
	NEW_LOAD_EVENT:           "newLoad",
	RAND_EVENT:               "rand",
	USER_VAR_EVENT:           "userVar",
	FORMAT_DESCRIPTION_EVENT: "formatDescription",
	XID_EVENT:                "xid",
	BEGIN_LOAD_QUERY_EVENT:   "beginLoadQuery",
	EXECUTE_LOAD_QUERY_EVENT: "executeLoadQuery",
	TABLE_MAP_EVENT:          "tableMap",
	WRITE_ROWS_EVENTv0:       "writeRowsV0",
	UPDATE_ROWS_EVENTv0:      "updateRowsV0",
	DELETE_ROWS_EVENTv0:      "deleteRowsV0",
	WRITE_ROWS_EVENTv1:       "writeRowsV1",
	UPDATE_ROWS_EVENTv1:      "updateRowsV1",
	DELETE_ROWS_EVENTv1:      "deleteRowsV1",
	INCIDENT_EVENT:           "incident",
	HEARTBEAT_EVENT:          "heartbeat",
	IGNORABLE_EVENT:          "ignorable",
	ROWS_QUERY_EVENT:         "rowsQuery",
	WRITE_ROWS_EVENTv2:       "writeRowsV2",
	UPDATE_ROWS_EVENTv2:      "updateRowsV2",
	DELETE_ROWS_EVENTv2:      "deleteRowsV2",
	GTID_EVENT:               "gtid",
	ANONYMOUS_GTID_EVENT:     "anonymousGTID",
	PREVIOUS_GTIDS_EVENT:     "previousGTID",
}

func (t EventType) String() string {
	return eventTypeNames[t]
}

func (t EventType) IsWriteRows() bool {
	return t == WRITE_ROWS_EVENTv0 || t == WRITE_ROWS_EVENTv1 || t == WRITE_ROWS_EVENTv2
}

func (t EventType) IsUpdateRows() bool {
	return t == UPDATE_ROWS_EVENTv0 || t == UPDATE_ROWS_EVENTv1 || t == UPDATE_ROWS_EVENTv2
}

func (t EventType) IsDeleteRows() bool {
	return t == DELETE_ROWS_EVENTv0 || t == DELETE_ROWS_EVENTv1 || t == DELETE_ROWS_EVENTv2
}

// https://dev.mysql.com/doc/internals/en/binlog-event-header.html
// https://dev.mysql.com/doc/internals/en/event-header-fields.html

type EventHeader struct {
	Timestamp uint32
	EventType EventType
	ServerID  uint32
	EventSize uint32
	LogPos    uint32
	Flags     uint16
}

func (h *EventHeader) parse(r *reader) error {
	h.Timestamp = r.int4()
	h.EventType = EventType(r.int1())
	h.ServerID = r.int4()
	h.EventSize = r.int4()
	if r.fde.binlogVersion > 1 {
		h.LogPos = r.int4()
		h.Flags = r.int2()
	}
	return r.err
}

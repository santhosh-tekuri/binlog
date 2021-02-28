package binlog

import (
	"fmt"
	"strings"
)

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
	if s, ok := eventTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("0x%02x", uint8(t))
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
	LogFile   string
	NextPos   uint32
	Flags     uint16
}

func (h *EventHeader) decode(r *reader) error {
	h.Timestamp = r.int4()
	h.EventType = EventType(r.int1())
	h.ServerID = r.int4()
	h.EventSize = r.int4()
	if r.fde.BinlogVersion > 1 {
		h.NextPos = r.int4()
		h.Flags = r.int2()
	}
	return r.err
}

// FormatDescriptionEvent is written to the beginning of the each binary log file.
// This event is used as of MySQL 5.0; it supersedes START_EVENT_V3.
//
// https://dev.mysql.com/doc/internals/en/format-description-event.html
type FormatDescriptionEvent struct {
	BinlogVersion          uint16
	ServerVersion          string
	CreateTimestamp        uint32
	EventHeaderLength      uint8
	EventTypeHeaderLengths []byte
}

func (e *FormatDescriptionEvent) decode(r *reader, eventSize uint32) error {
	e.BinlogVersion = r.int2()
	e.ServerVersion = r.string(50)
	if i := strings.IndexByte(e.ServerVersion, 0); i != -1 {
		e.ServerVersion = e.ServerVersion[:i]
	}
	e.CreateTimestamp = r.int4()
	e.EventHeaderLength = r.int1()
	if err := r.ensure(int(FORMAT_DESCRIPTION_EVENT)); err != nil {
		return err
	}
	fmeSize := r.buffer()[FORMAT_DESCRIPTION_EVENT-1]
	r.checksum = int(eventSize - 19 /*eventHeader*/ - uint32(fmeSize) - 1 /*checksumType*/)
	r.limit -= r.checksum
	e.EventTypeHeaderLengths = r.bytesEOF()
	e.EventTypeHeaderLengths = e.EventTypeHeaderLengths[:len(e.EventTypeHeaderLengths)-1] // exclude checksum type
	return r.err
}

func (e *FormatDescriptionEvent) postHeaderLength(typ EventType, def int) int {
	if len(e.EventTypeHeaderLengths) >= int(typ) {
		return int(e.EventTypeHeaderLengths[typ-1])
	}
	return def
}

// RotateEvent is written when mysqld switches to a new binary log file.
// This occurs when someone issues a FLUSH LOGS statement or
// the current binary log file becomes too large.
// The maximum size is determined by max_binlog_size.
//
// https://dev.mysql.com/doc/internals/en/rotate-event.html
type RotateEvent struct {
	Position   uint64
	NextBinlog string
}

func (e *RotateEvent) decode(r *reader) error {
	if r.fde.BinlogVersion > 1 {
		e.Position = r.int8()
	}
	e.NextBinlog = r.stringEOF()
	return r.err
}

// QueryEvent is written when an updating statement is done.
// The query event is used to send text query right the binlog.
//
// https://dev.mysql.com/doc/internals/en/query-event.html
type QueryEvent struct {
	SlaveProxyID  uint32
	ExecutionTIme uint32
	ErrorCode     uint16
	StatusVars    []byte
	Schema        string
	Query         string
}

func (e *QueryEvent) decode(r *reader) error {
	e.SlaveProxyID = r.int4()
	e.ExecutionTIme = r.int4()
	schemaLen := r.int1()
	if r.err != nil {
		return r.err
	}
	e.ErrorCode = r.int2()
	statusVarsLen := r.int2()
	if r.err != nil {
		return r.err
	}
	e.StatusVars = r.bytes(int(statusVarsLen))
	e.Schema = r.string(int(schemaLen))
	r.skip(1)
	e.Query = r.stringEOF()
	return r.err
}

// IncidentEvent used to log an out of the ordinary event that
// occurred on the master. It notifies the slave that something
// happened on the master that might cause data to be in an
// inconsistent state.
//
// https://dev.mysql.com/doc/internals/en/incident-event.html
type IncidentEvent struct {
	Type    uint16
	Message string
}

func (e *IncidentEvent) decode(r *reader) error {
	e.Type = r.int2()
	size := r.int1()
	e.Message = r.string(int(size))
	return r.err
}

// RandEvent is written every time a statement uses the RAND() function.
// It precedes other events for the statement. Indicates the seed values
// to use for generating a random number with RAND() in the next statement.
// This is written only before a QUERY_EVENT and is not used with row-based logging.
//
// https://dev.mysql.com/doc/internals/en/rand-event.html
type RandEvent struct {
	Seed1 uint64
	Seed2 uint64
}

func (e *RandEvent) decode(r *reader) error {
	e.Seed1 = r.int8()
	e.Seed2 = r.int8()
	return r.err
}

// StopEvent signals last event in the file.
//
// https://dev.mysql.com/doc/internals/en/stop-event.html
type StopEvent struct{}

// IntVarEvent written every time a statement uses an AUTO_INCREMENT column
// or the LAST_INSERT_ID() function. It precedes other events for the statement.
// This is written only before a QUERY_EVENT and is not used with row-based logging.
//
// https://dev.mysql.com/doc/internals/en/intvar-event.html
type IntVarEvent struct {
	// Type indicates subtype.
	//
	// INSERT_ID_EVENT(0x02) indicates the value to use for an AUTO_INCREMENT column in the next statement.
	//
	// LAST_INSERT_ID_EVENT(0x01) indicates the value to use for the LAST_INSERT_ID() function in the next statement.
	Type  uint8
	Value uint64
}

func (e *IntVarEvent) decode(r *reader) error {
	e.Type = r.int1()
	e.Value = r.int8()
	return r.err
}

// UserVarEvent is written every time a statement uses a user variable.
// It precedes other events for the statement. Indicates the value to
// use for the user variable in the next statement. This is written only
// before a QUERY_EVENT and is not used with row-based logging.
//
// https://dev.mysql.com/doc/internals/en/user-var-event.html
type UserVarEvent struct {
	Name     string
	Null     bool
	Type     uint8
	Charset  uint32
	Value    []byte
	Unsigned bool
}

func (e *UserVarEvent) decode(r *reader) error {
	nameLen := r.int4()
	if r.err != nil {
		return r.err
	}
	e.Name = r.string(int(nameLen))
	e.Null = r.int1() == 0
	if r.err != nil {
		return r.err
	}
	if !e.Null {
		e.Type = r.int1()
		e.Charset = r.int4()
		valueLen := r.int4()
		if r.err != nil {
			return r.err
		}
		e.Value = r.bytes(int(valueLen))
		if r.more() {
			e.Unsigned = (r.int1() | 0x01) != 0
		}
	}
	return r.err
}

// HeartbeatEvent sent by a master to a slave to let the slave
// know that the master is still alive. Not written to log files.
//
// https://dev.mysql.com/doc/internals/en/heartbeat-event.html
type HeartbeatEvent struct{}

// UnknownEvent should never occur. It is never written to a binary log.
// If an event is read from a binary log that cannot be recognized as
// something else, it is treated as UNKNOWN_EVENT.
type UnknownEvent struct{}

type previousGTIDsEvent struct{}
type anonymousGTIDEvent struct{}
type xidEvent struct{}
type gtidEvent struct{}
type loadEvent struct{}
type slaveEvent struct{}
type createFileEvent struct{}
type deleteFileEvent struct{}
type beginLoadQueryEvent struct{}
type executeLoadQueryEvent struct{}
type newLoadEvent struct{}
type execLoadEvent struct{}
type appendBlockEvent struct{}
type ignorableEvent struct{}

package binlog

const (
	UNKNOWN_EVENT = 0x00 + iota
	START_EVENT_V3
	QUERY_EVENT
	STOP_EVENT
	ROTATE_EVENT
	INTVAR_EVENT
	LOAD_EVENT
	SLAVE_EVENT
	CREATE_FILE_EVENT
	APPEND_BLOCK_EVENT
	EXEC_LOAD_EVENT
	DELETE_FILE_EVENT
	NEW_LOAD_EVENT
	RAND_EVENT
	USER_VAR_EVENT
	FORMAT_DESCRIPTION_EVENT
	XID_EVENT
	BEGIN_LOAD_QUERY_EVENT
	EXECUTE_LOAD_QUERY_EVENT
	TABLE_MAP_EVENT
	WRITE_ROWS_EVENTv0
	UPDATE_ROWS_EVENTv0
	DELETE_ROWS_EVENTv0
	WRITE_ROWS_EVENTv1
	UPDATE_ROWS_EVENTv1
	DELETE_ROWS_EVENTv1
	INCIDENT_EVENT
	HEARTBEAT_EVENT
	IGNORABLE_EVENT
	ROWS_QUERY_EVENT
	WRITE_ROWS_EVENTv2
	UPDATE_ROWS_EVENTv2
	DELETE_ROWS_EVENTv2
	GTID_EVENT
	ANONYMOUS_GTID_EVENT
	PREVIOUS_GTIDS_EVENT
)

type binaryEventHeader struct {
	timestamp uint32
	eventType uint8
	serverID  uint32
	eventSize uint32
	logPos    uint32
	flags     uint16
}

func (h *binaryEventHeader) parse(r *reader) (err error) {
	if h.timestamp, err = r.int4(); err != nil {
		return err
	}
	if h.eventType, err = r.int1(); err != nil {
		return err
	}
	if h.serverID, err = r.int4(); err != nil {
		return err
	}
	if h.eventSize, err = r.int4(); err != nil {
		return err
	}
	if h.logPos, err = r.int4(); err != nil {
		return err
	}
	if h.flags, err = r.int2(); err != nil {
		return err
	}
	return nil
}

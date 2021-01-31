package binlog

import "fmt"

func nextEvent(r *reader) (interface{}, error) {
	h := eventHeader{}
	if err := h.parse(r); err != nil {
		return nil, err
	}
	fmt.Printf("%#v\n", h)
	headerSize := uint32(13)
	if r.fde.binlogVersion > 1 {
		headerSize = 19
	}
	r.limit = int(h.eventSize-headerSize) - 4 // checksum = 4

	if h.logPos != 0 {
		r.binlogPos = h.logPos
	}
	// Read event body
	switch h.eventType {
	case FORMAT_DESCRIPTION_EVENT:
		r.fde = formatDescriptionEvent{}
		err := r.fde.parse(r)
		return r.fde, err
	case STOP_EVENT:
		return stopEvent{}, nil
	case ROTATE_EVENT:
		re := rotateEvent{}
		err := re.parse(r)
		if err != nil {
			r.binlogFile, r.binlogPos = re.nextBinlog, uint32(re.position)
		}
		return re, err
	case TABLE_MAP_EVENT:
		r.tme = tableMapEvent{}
		err := r.tme.parse(r)
		return r.tme, err
	case WRITE_ROWS_EVENTv0, WRITE_ROWS_EVENTv1, WRITE_ROWS_EVENTv2,
		UPDATE_ROWS_EVENTv0, UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2,
		DELETE_ROWS_EVENTv0, DELETE_ROWS_EVENTv1, DELETE_ROWS_EVENTv2:
		re := rowsEvent{}
		err := re.parse(r, h.eventType)
		re.reader = r
		return &re, err
	case PREVIOUS_GTIDS_EVENT:
		return previousGTIDsEvent{}, nil
	case ANONYMOUS_GTID_EVENT:
		return anonymousGTIDEvent{}, nil
	case QUERY_EVENT:
		return queryEvent{}, nil
	case XID_EVENT:
		return xidEvent{}, nil
	case GTID_EVENT:
		return gtidEvent{}, nil
	case UNKNOWN_EVENT:
		return unknownEvent{}, nil
	case INTVAR_EVENT:
		return intVarEvent{}, nil
	case LOAD_EVENT:
		return loadEvent{}, nil
	case SLAVE_EVENT:
		return slaveEvent{}, nil
	case CREATE_FILE_EVENT:
		return createFileEvent{}, nil
	case DELETE_FILE_EVENT:
		return deleteFileEvent{}, nil
	case BEGIN_LOAD_QUERY_EVENT:
		return beginLoadQueryEvent{}, nil
	case EXECUTE_LOAD_QUERY_EVENT:
		return executeLoadQueryEvent{}, nil
	case RAND_EVENT:
		return randEvent{}, nil
	case USER_VAR_EVENT:
		return userVarEvent{}, nil
	case NEW_LOAD_EVENT:
		return newLoadEvent{}, nil
	case EXEC_LOAD_EVENT:
		return execLoadEvent{}, nil
	case APPEND_BLOCK_EVENT:
		return appendBlockEvent{}, nil
	case INCIDENT_EVENT:
		return incidentEvent{}, nil
	case HEARTBEAT_EVENT:
		return heartbeatEvent{}, nil
	case IGNORABLE_EVENT:
		return ignorableEvent{}, nil
	case ROWS_QUERY_EVENT:
		rqe := rowsQueryEvent{}
		err := rqe.parse(r)
		return rqe, err
	default:
		fmt.Printf("%#v\n", h)
		return nil, nil
	}
}

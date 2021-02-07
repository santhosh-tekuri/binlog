package binlog

func nextEvent(r *reader, checksum int) (Event, error) {
	h := EventHeader{}
	if err := h.parse(r); err != nil {
		return Event{}, err
	}
	headerSize := uint32(13)
	if r.fde.BinlogVersion > 1 {
		headerSize = 19
	}
	r.limit = int(h.EventSize-headerSize) - checksum

	if h.NextPos != 0 {
		r.binlogPos = h.NextPos
		h.LogFile, h.NextPos = r.binlogFile, r.binlogPos
	}
	// Read event body
	switch h.EventType {
	case FORMAT_DESCRIPTION_EVENT:
		r.fde = FormatDescriptionEvent{}
		err := r.fde.parse(r)
		return Event{h, r.fde}, err
	case STOP_EVENT:
		return Event{h, stopEvent{}}, nil
	case ROTATE_EVENT:
		re := RotateEvent{}
		err := re.parse(r)
		if err == nil {
			r.binlogFile, r.binlogPos = re.NextBinlog, uint32(re.Position)
			h.LogFile, h.NextPos = r.binlogFile, r.binlogPos
		}
		r.tmeCache = make(map[uint64]*TableMapEvent)
		return Event{h, re}, err
	case TABLE_MAP_EVENT:
		tme := TableMapEvent{}
		err := tme.parse(r)
		r.tmeCache[tme.tableID] = &tme
		return Event{h, tme}, err
	case WRITE_ROWS_EVENTv0, WRITE_ROWS_EVENTv1, WRITE_ROWS_EVENTv2,
		UPDATE_ROWS_EVENTv0, UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2,
		DELETE_ROWS_EVENTv0, DELETE_ROWS_EVENTv1, DELETE_ROWS_EVENTv2:
		r.re = RowsEvent{}
		err := r.re.parse(r, h.EventType)
		return Event{h, r.re}, err
	case PREVIOUS_GTIDS_EVENT:
		return Event{h, previousGTIDsEvent{}}, nil
	case ANONYMOUS_GTID_EVENT:
		return Event{h, anonymousGTIDEvent{}}, nil
	case QUERY_EVENT:
		return Event{h, queryEvent{}}, nil
	case XID_EVENT:
		return Event{h, xidEvent{}}, nil
	case GTID_EVENT:
		return Event{h, gtidEvent{}}, nil
	case UNKNOWN_EVENT:
		return Event{h, unknownEvent{}}, nil
	case INTVAR_EVENT:
		return Event{h, intVarEvent{}}, nil
	case LOAD_EVENT:
		return Event{h, loadEvent{}}, nil
	case SLAVE_EVENT:
		return Event{h, slaveEvent{}}, nil
	case CREATE_FILE_EVENT:
		return Event{h, createFileEvent{}}, nil
	case DELETE_FILE_EVENT:
		return Event{h, deleteFileEvent{}}, nil
	case BEGIN_LOAD_QUERY_EVENT:
		return Event{h, beginLoadQueryEvent{}}, nil
	case EXECUTE_LOAD_QUERY_EVENT:
		return Event{h, executeLoadQueryEvent{}}, nil
	case RAND_EVENT:
		return Event{h, randEvent{}}, nil
	case USER_VAR_EVENT:
		return Event{h, userVarEvent{}}, nil
	case NEW_LOAD_EVENT:
		return Event{h, newLoadEvent{}}, nil
	case EXEC_LOAD_EVENT:
		return Event{h, execLoadEvent{}}, nil
	case APPEND_BLOCK_EVENT:
		return Event{h, appendBlockEvent{}}, nil
	case INCIDENT_EVENT:
		return Event{h, incidentEvent{}}, nil
	case HEARTBEAT_EVENT:
		return Event{h, heartbeatEvent{}}, nil
	case IGNORABLE_EVENT:
		return Event{h, ignorableEvent{}}, nil
	case ROWS_QUERY_EVENT:
		rqe := RowsQueryEvent{}
		err := rqe.parse(r)
		return Event{h, rqe}, err
	default:
		return Event{h, unknownEvent{}}, nil
	}
}

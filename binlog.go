package binlog

func nextEvent(r *reader, rotateChecksum int) (Event, error) {
	if r.hash != nil {
		r.hash.Reset()
	}
	h := EventHeader{}
	if err := h.decode(r); err != nil {
		return Event{}, err
	}
	switch h.EventType {
	case FORMAT_DESCRIPTION_EVENT:
		r.checksum = 0 // computed in decode
	case ROTATE_EVENT:
		r.checksum = rotateChecksum
	}
	headerSize := uint32(13)
	if r.fde.BinlogVersion > 1 {
		headerSize = 19
	}
	r.limit = int(h.EventSize-headerSize) - r.checksum

	if h.NextPos != 0 {
		r.binlogPos = h.NextPos
		h.LogFile, h.NextPos = r.binlogFile, r.binlogPos
	}
	// Read event body
	switch h.EventType {
	case FORMAT_DESCRIPTION_EVENT:
		r.fde = FormatDescriptionEvent{}
		err := r.fde.decode(r, h.EventSize)
		return Event{h, r.fde}, err
	case STOP_EVENT:
		return Event{h, stopEvent{}}, nil
	case ROTATE_EVENT:
		re := RotateEvent{}
		err := re.decode(r)
		if err == nil {
			r.binlogFile, r.binlogPos = re.NextBinlog, uint32(re.Position)
			h.LogFile, h.NextPos = r.binlogFile, r.binlogPos
		}
		r.tmeCache = make(map[uint64]*TableMapEvent)
		return Event{h, re}, err
	case TABLE_MAP_EVENT:
		tme := TableMapEvent{}
		err := tme.decode(r)
		r.tmeCache[tme.tableID] = &tme
		return Event{h, tme}, err
	case WRITE_ROWS_EVENTv0, WRITE_ROWS_EVENTv1, WRITE_ROWS_EVENTv2,
		UPDATE_ROWS_EVENTv0, UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2,
		DELETE_ROWS_EVENTv0, DELETE_ROWS_EVENTv1, DELETE_ROWS_EVENTv2:
		r.re = RowsEvent{}
		err := r.re.decode(r, h.EventType)
		return Event{h, r.re}, err
	case PREVIOUS_GTIDS_EVENT:
		return Event{h, previousGTIDsEvent{}}, nil
	case ANONYMOUS_GTID_EVENT:
		return Event{h, anonymousGTIDEvent{}}, nil
	case QUERY_EVENT:
		qe := QueryEvent{}
		err := qe.decode(r)
		return Event{h, qe}, err
	case XID_EVENT:
		return Event{h, xidEvent{}}, nil
	case GTID_EVENT:
		return Event{h, gtidEvent{}}, nil
	case UNKNOWN_EVENT:
		return Event{h, unknownEvent{}}, nil
	case INTVAR_EVENT:
		ive := IntVarEvent{}
		err := ive.decode(r)
		return Event{h, ive}, err
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
		re := RandEvent{}
		err := re.decode(r)
		return Event{h, re}, err
	case USER_VAR_EVENT:
		return Event{h, userVarEvent{}}, nil
	case NEW_LOAD_EVENT:
		return Event{h, newLoadEvent{}}, nil
	case EXEC_LOAD_EVENT:
		return Event{h, execLoadEvent{}}, nil
	case APPEND_BLOCK_EVENT:
		return Event{h, appendBlockEvent{}}, nil
	case INCIDENT_EVENT:
		ie := IncidentEvent{}
		err := ie.decode(r)
		return Event{h, ie}, err
	case HEARTBEAT_EVENT:
		return Event{h, heartbeatEvent{}}, nil
	case IGNORABLE_EVENT:
		return Event{h, ignorableEvent{}}, nil
	case ROWS_QUERY_EVENT:
		rqe := RowsQueryEvent{}
		err := rqe.decode(r)
		return Event{h, rqe}, err
	default:
		return Event{h, unknownEvent{}}, nil
	}
}

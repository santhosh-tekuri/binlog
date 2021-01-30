package binlog

import (
	"fmt"
)

func nextEvent(r *reader) (interface{}, error) {
	h := binaryEventHeader{}
	if err := h.parse(r); err != nil {
		return nil, err
	}
	fmt.Printf("%#v\n", h)

	headerSize := uint32(13)
	if r.fde.binlogVersion > 1 {
		headerSize = 19
	}
	r.limit = int(h.eventSize-headerSize) - 4 // checksum = 4

	r.binlogPos = h.logPos
	// Read event body
	switch h.eventType {
	case FORMAT_DESCRIPTION_EVENT:
		r.fde = formatDescriptionEvent{}
		err := r.fde.parse(r)
		return r.fde, err
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
		re.reader = r
		err := re.parse(r, h.eventType)
		return &re, err
	default:
		return nil, nil
	}
}

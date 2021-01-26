package binlog

import (
	"io"
)

type rowsEvent struct {
	eventType  uint8
	tme        *tableMapEvent
	tableID    uint64
	flags      uint16
	numCol     uint64
	present    []bitmap
	colOrdinal [][]int
	numRow     uint64

	reader *reader
}

func (e *rowsEvent) parse(r *reader, fde *formatDescriptionEvent, eventType uint8, tme *tableMapEvent) error {
	e.eventType, e.tme = eventType, tme
	if fde.postHeaderLength(eventType, 8) == 6 {
		e.tableID = uint64(r.int4())
	} else {
		e.tableID = r.int6()
	}
	e.flags = r.int2()
	switch eventType {
	case WRITE_ROWS_EVENTv2, UPDATE_ROWS_EVENTv2, DELETE_ROWS_EVENTv2: // version==2
		extraDataLength := r.int2()
		if r.err != nil {
			return r.err
		}
		_ = r.string(int(extraDataLength - 2))
	}
	e.numCol = r.intN()
	if r.err != nil {
		return r.err
	}

	e.present = make([]bitmap, 2)
	e.colOrdinal = make([][]int, 2)
	e.present[0] = r.bytes(bitmapSize(e.numCol))
	for i := 0; i < int(e.numCol); i++ {
		if e.present[0].isTrue(i) {
			e.colOrdinal[0] = append(e.colOrdinal[0], i)
		}
	}
	switch eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		e.present[1] = r.bytes(bitmapSize(e.numCol))
		for i := 0; i < int(e.numCol); i++ {
			if e.present[1].isTrue(i) {
				e.colOrdinal[1] = append(e.colOrdinal[1], i)
			}
		}
	}

	return r.err
}

func (e *rowsEvent) nextRow() ([][]interface{}, error) {
	r := e.reader
	if !r.more() {
		if r.err != nil {
			return nil, r.err
		}
		return nil, io.EOF
	}
	row := make([][]interface{}, 2)
	n := 1
	switch e.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		n = 2
	}
	for m := 0; m < n; m++ {
		nullValue := r.bytes(bitmapSize(e.numCol))
		if r.err != nil {
			return nil, r.err
		}
		var values []interface{}
		for i := 0; i < int(e.numCol); i++ {
			if !e.present[m].isTrue(i) {
				continue
			}
			if bitmap(nullValue).isTrue(i) {
				values = append(values, nil)
			} else {
				v, err := parseValue(r, e.tme.columnTypes[i])
				if err != nil {
					return row, err
				}
				values = append(values, v)
			}
		}
		row[m] = values
	}
	e.numRow++
	return row, nil
}

// bitmap ---

type bitmap []byte

func bitmapSize(numCol uint64) int {
	return int((numCol + 7) / 8)
}

func (bm bitmap) isTrue(colID int) bool {
	return (bm[colID/8]>>uint8(colID%8))&1 == 1
}

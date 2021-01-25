package binlog

import (
	"io"
)

type rowsEvent struct {
	eventType uint8
	tme       *tableMapEvent
	tableID   uint64
	flags     uint16
	numCol    uint64
	present   []bitmap
	numRow    uint64
}

func (e *rowsEvent) parse(r *reader, eventType uint8, tme *tableMapEvent) (err error) {
	e.eventType, e.tme = eventType, tme
	if e.tableID, err = r.int6(); err != nil {
		return err
	}
	if e.flags, err = r.int2(); err != nil {
		return err
	}
	switch eventType {
	case WRITE_ROWS_EVENTv2, UPDATE_ROWS_EVENTv2, DELETE_ROWS_EVENTv2: // version==2
		extraDataLength, err := r.int2()
		if err != nil {
			return err
		}
		if _, err := r.string(int(extraDataLength - 2)); err != nil { // extra-data
			return err
		}
	}
	if e.numCol, err = r.intN(); err != nil {
		return err
	}
	e.present = make([]bitmap, 2)
	if e.present[0], err = r.bytes(bitmapSize(e.numCol)); err != nil {
		return err
	}
	switch eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		if e.present[1], err = r.bytes(bitmapSize(e.numCol)); err != nil {
			return err
		}
	}
	return nil
}

func (e *rowsEvent) nextRow(r *reader) ([][]interface{}, error) {
	row := make([][]interface{}, 2)
	n := 1
	switch e.eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		n = 2
	}
	for m := 0; m < n; m++ {
		nullValue, err := r.bytes(bitmapSize(e.numCol))
		if err != nil {
			if err == io.EOF {
				return nil, io.EOF
			}
			return row, err
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

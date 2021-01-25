package binlog

import (
	"io"
)

type rowsEvent struct {
	tableID uint64
	flags   uint16
	present []bitmap
	rows    [][][]interface{}
}

func (e *rowsEvent) parse(r *reader, eventType uint8, tme *tableMapEvent) (err error) {
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
	numCol, err := r.intN()
	if err != nil {
		return err
	}
	e.present = make([]bitmap, 2)
	if e.present[0], err = r.bytes(bitmapSize(numCol)); err != nil {
		return err
	}
	switch eventType {
	case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
		if e.present[1], err = r.bytes(bitmapSize(numCol)); err != nil {
			return err
		}
	}
	row := 0
	index := func() int {
		switch eventType {
		case UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2:
			return row % 2
		}
		return 0
	}
	e.rows = make([][][]interface{}, 2)
	for {
		nullValue, err := r.bytes(bitmapSize(numCol))
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var values []interface{}
		for i := 0; i < int(numCol); i++ {
			if !e.present[index()].isTrue(i) {
				continue
			}
			if bitmap(nullValue).isTrue(i) {
				values = append(values, nil)
			} else {
				v, err := parseValue(r, tme.columnTypes[i])
				if err != nil {
					return err
				}
				values = append(values, v)
			}
		}
		e.rows[index()] = append(e.rows[index()], values)
		row++
	}
	return nil
}

// bitmap ---

type bitmap []byte

func bitmapSize(numCol uint64) int {
	return int((numCol + 7) / 8)
}

func (bm bitmap) isTrue(colID int) bool {
	return (bm[colID/8]>>uint8(colID%8))&1 == 1
}

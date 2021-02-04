package binlog

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	MYSQL_TYPE_DECIMAL     = 0x00
	MYSQL_TYPE_TINY        = 0x01
	MYSQL_TYPE_SHORT       = 0x02
	MYSQL_TYPE_LONG        = 0x03
	MYSQL_TYPE_FLOAT       = 0x04
	MYSQL_TYPE_DOUBLE      = 0x05
	MYSQL_TYPE_NULL        = 0x06
	MYSQL_TYPE_TIMESTAMP   = 0x07
	MYSQL_TYPE_LONGLONG    = 0x08
	MYSQL_TYPE_INT24       = 0x09
	MYSQL_TYPE_DATE        = 0x0a
	MYSQL_TYPE_TIME        = 0x0b
	MYSQL_TYPE_DATETIME    = 0x0c
	MYSQL_TYPE_YEAR        = 0x0d
	MYSQL_TYPE_NEWDATE     = 0x0e
	MYSQL_TYPE_VARCHAR     = 0x0f
	MYSQL_TYPE_BIT         = 0x10
	MYSQL_TYPE_TIMESTAMP2  = 0x11
	MYSQL_TYPE_DATETIME2   = 0x12
	MYSQL_TYPE_TIME2       = 0x13
	MYSQL_TYPE_JSON        = 0xf5
	MYSQL_TYPE_NEWDECIMAL  = 0xf6
	MYSQL_TYPE_ENUM        = 0xf7
	MYSQL_TYPE_SET         = 0xf8
	MYSQL_TYPE_TINY_BLOB   = 0xf9
	MYSQL_TYPE_MEDIUM_BLOB = 0xfa
	MYSQL_TYPE_LONG_BLOB   = 0xfb
	MYSQL_TYPE_BLOB        = 0xfc
	MYSQL_TYPE_VAR_STRING  = 0xfd
	MYSQL_TYPE_STRING      = 0xfe
	MYSQL_TYPE_GEOMETRY    = 0xff
)

// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
// todo: test with table with all types, especially negative numbers
func (col Column) decode(r *reader) (interface{}, error) {
	switch col.Type {
	case MYSQL_TYPE_TINY:
		if col.Unsigned {
			return r.int1(), r.err
		}
		return int8(r.int1()), r.err
	case MYSQL_TYPE_SHORT:
		if col.Unsigned {
			return r.int2(), r.err
		}
		return int16(r.int2()), r.err
	case MYSQL_TYPE_INT24:
		v := r.int3()
		if v&0x00800000 != 0 {
			v |= 0xFF000000
		}
		if col.Unsigned {
			return v, r.err
		}
		return int32(v), r.err
	case MYSQL_TYPE_LONG:
		if col.Unsigned {
			return r.int4(), r.err
		}
		return int32(r.int4()), r.err
	case MYSQL_TYPE_LONGLONG:
		if col.Unsigned {
			return r.int8(), r.err
		}
		return int64(r.int8()), r.err
	case MYSQL_TYPE_FLOAT:
		return math.Float32frombits(r.int4()), r.err
	case MYSQL_TYPE_DOUBLE:
		return math.Float64frombits(r.int8()), r.err
	case MYSQL_TYPE_VARCHAR:
		var len int
		if binary.LittleEndian.Uint16(col.meta) < 256 {
			len = int(r.int1())
		} else {
			len = int(r.int2())
		}
		return r.string(len), r.err
	case MYSQL_TYPE_BLOB, MYSQL_TYPE_JSON:
		len := r.intFixed(int(col.meta[0]))
		return r.bytes(int(len)), r.err
	case MYSQL_TYPE_DATETIME2:
		b := r.bytesInternal(5)
		if r.err != nil {
			return nil, r.err
		}
		datetime := uint64(b[4]) | uint64(b[3])<<8 | uint64(b[2])<<16 | uint64(b[1])<<24 | uint64(b[0])<<32
		slice := func(off, len int) int {
			v := datetime >> (40 - (off + len))
			return int(v & ((1 << len) - 1))
		}
		yearMonth := slice(1, 17)
		year, month := yearMonth/13, yearMonth%13
		day := slice(18, 5)
		hour := slice(23, 5)
		minute := slice(28, 6)
		second := slice(34, 6)

		frac, err := fractionalSeconds(col.meta[0], r)
		if err != nil {
			return nil, err
		}
		return time.Date(year, time.Month(month), day, hour, minute, second, frac*1000, time.UTC), r.err
	case MYSQL_TYPE_TIMESTAMP2:
		b := r.bytesInternal(4)
		if r.err != nil {
			return nil, r.err
		}
		sec := binary.BigEndian.Uint32(b)

		frac, err := fractionalSeconds(col.meta[0], r)
		if err != nil {
			return nil, err
		}
		return time.Unix(int64(sec), int64(frac)*1000), r.err
	case MYSQL_TYPE_TIME2:
		b := r.bytesInternal(3)
		if r.err != nil {
			return nil, r.err
		}
		t := uint64(b[2]) | uint64(b[1])<<8 | uint64(b[0])<<16
		slice := func(off, len int) int {
			v := t >> (24 - (off + len))
			return int(v & ((1 << len) - 1))
		}
		sign := slice(1, 1)
		hour := slice(2, 10)
		min := slice(12, 6)
		sec := slice(18, 6)
		frac, err := fractionalSeconds(col.meta[0], r)
		if err != nil {
			return nil, err
		}
		v := time.Duration(hour)*time.Hour +
			time.Duration(min)*time.Minute +
			time.Duration(sec)*time.Second +
			time.Duration(frac)*time.Microsecond
		if sign == 1 {
			v = -v
		}
		return v, r.err
	}
	return nil, fmt.Errorf("unmarshal of mysql type 0x%x is not implemented", col.Type)
}

func fractionalSeconds(meta byte, r *reader) (int, error) {
	dec := int(meta+1) / 2
	if dec == 0 {
		return 0, nil
	}
	b := r.bytesInternal(dec)
	if r.err != nil {
		return 0, r.err
	}
	switch dec {
	case 1, 2:
		return int(b[0]) * 10000, nil
	case 3, 4:
		return int(uint16(b[1])|uint16(b[0])<<8) * 100, nil
	case 5, 6:
		return int(uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16), nil
	}
	return 0, fmt.Errorf("binlog.fractionalSeconds: meta=%d must be less than 6", meta)
}

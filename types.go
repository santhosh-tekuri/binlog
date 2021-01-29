package binlog

import (
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
func parseValue(r *reader, typ byte, meta []byte) (interface{}, error) {
	switch typ {
	case MYSQL_TYPE_TINY:
		return r.int1(), r.err
	case MYSQL_TYPE_SHORT:
		return r.int2(), r.err
	case MYSQL_TYPE_INT24:
		return r.int3(), r.err
	case MYSQL_TYPE_LONG:
		return r.int4(), r.err
	case MYSQL_TYPE_LONGLONG:
		return r.int8(), r.err
	case MYSQL_TYPE_FLOAT:
		return math.Float32frombits(r.int4()), r.err
	case MYSQL_TYPE_DOUBLE:
		return math.Float64frombits(r.int8()), r.err
	case MYSQL_TYPE_VARCHAR:
		return r.stringN(), r.err // todo: check length >256
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

		frac := 0
		if dec := int(meta[0]+1) / 2; dec > 0 {
			b := r.bytesInternal(dec)
			if r.err != nil {
				return nil, r.err
			}
			switch dec {
			case 1, 2:
				frac = int(b[0]) * 10000
			case 3, 4:
				frac = int(uint16(b[1]) | uint16(b[0])<<8)
			case 5, 6:
				frac = int(uint16(b[2]) | uint16(b[1])<<8 | uint16(b[0])<<16)
			}
		}
		return time.Date(year, time.Month(month), day, hour, minute, second, frac*1000, time.UTC), r.err
	}
	return nil, fmt.Errorf("unmarshal of mysql type 0x%x is not implemented", typ)
}

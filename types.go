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
func parseValue(r *reader, typ byte) (interface{}, error) {
	switch typ {
	case MYSQL_TYPE_STRING, MYSQL_TYPE_VARCHAR, MYSQL_TYPE_VAR_STRING,
		MYSQL_TYPE_ENUM, MYSQL_TYPE_SET,
		MYSQL_TYPE_LONG_BLOB, MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_BLOB, MYSQL_TYPE_TINY_BLOB,
		MYSQL_TYPE_GEOMETRY, MYSQL_TYPE_BIT, MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL:
		return r.stringN()
	case MYSQL_TYPE_LONGLONG:
		return r.int8()
	case MYSQL_TYPE_LONG, MYSQL_TYPE_INT24:
		return r.int4()
	case MYSQL_TYPE_SHORT, MYSQL_TYPE_YEAR:
		return r.int2()
	case MYSQL_TYPE_TINY:
		return r.int1()
	case MYSQL_TYPE_DOUBLE:
		v, err := r.int8()
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(v), nil
	case MYSQL_TYPE_FLOAT:
		v, err := r.int4()
		if err != nil {
			return nil, err
		}
		return math.Float32frombits(v), nil
	case MYSQL_TYPE_DATE, MYSQL_TYPE_DATETIME, MYSQL_TYPE_TIMESTAMP:
		l, err := r.int1()
		if err != nil {
			return nil, err
		}
		var year uint16
		var month, day, hour, minute, second uint8
		var microsecond uint32
		if l >= 4 {
			if year, err = r.int2(); err != nil {
				return nil, err
			}
			if month, err = r.int1(); err != nil {
				return nil, err
			}
			if day, err = r.int1(); err != nil {
				return nil, err
			}
		}
		if l >= 7 {
			if hour, err = r.int1(); err != nil {
				return nil, err
			}
			if minute, err = r.int1(); err != nil {
				return nil, err
			}
			if second, err = r.int1(); err != nil {
				return nil, err
			}
		}
		if l == 11 {
			if microsecond, err = r.int4(); err != nil {
				return nil, err
			}
		}
		return time.Date(
			int(year), time.Month(month), int(day),
			int(hour), int(minute), int(second),
			int(microsecond*1000), time.Local), nil
	case MYSQL_TYPE_TIME:
		l, err := r.int1()
		if err != nil {
			return nil, err
		}
		var isNegative, hours, minutes, seconds uint8
		var days, microseconds uint32
		if l >= 8 {
			if isNegative, err = r.int1(); err != nil {
				return nil, err
			}
			if days, err = r.int4(); err != nil {
				return nil, err
			}
			if hours, err = r.int1(); err != nil {
				return nil, err
			}
			if minutes, err = r.int1(); err != nil {
				return nil, err
			}
			if seconds, err = r.int1(); err != nil {
				return nil, err
			}
		}
		if l == 12 {
			if microseconds, err = r.int4(); err != nil {
				return nil, err
			}
		}
		d := time.Duration(days)*24*time.Hour +
			time.Duration(hours)*time.Hour +
			time.Duration(minutes)*time.Minute +
			time.Duration(seconds)*time.Second +
			time.Duration(microseconds)*time.Microsecond
		if isNegative == 1 {
			d = -d
		}
		return d, nil
	}
	return nil, fmt.Errorf("unmarshal of mysql type %0x is not implemented", typ)
}

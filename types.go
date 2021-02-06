package binlog

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	TypeDecimal    = 0x00
	TypeTiny       = 0x01
	TypeShort      = 0x02
	TypeLong       = 0x03
	TypeFloat      = 0x04
	TypeDouble     = 0x05
	TypeNull       = 0x06
	TypeTimestamp  = 0x07
	TypeLongLong   = 0x08
	TypeInt24      = 0x09
	TypeDate       = 0x0a
	TypeTime       = 0x0b
	TypeDateTime   = 0x0c
	TypeYear       = 0x0d
	TypeNewDate    = 0x0e
	TypeVarchar    = 0x0f
	TypeBit        = 0x10
	TypeTimestamp2 = 0x11
	TypeDateTime2  = 0x12
	TypeTime2      = 0x13
	TypeJSON       = 0xf5
	TypeNewDecimal = 0xf6
	TypeEnum       = 0xf7
	TypeSet        = 0xf8
	TypeTinyBlob   = 0xf9
	TypeMediumBlob = 0xfa
	TypeLongBlob   = 0xfb
	TypeBlob       = 0xfc
	TypeVarString  = 0xfd
	TypeString     = 0xfe
	TypeGeometry   = 0xff
)

// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
// todo: test with table with all types, especially negative numbers
func (col Column) decodeValue(r *reader) (interface{}, error) {
	switch col.Type {
	case TypeTiny:
		if col.Unsigned {
			return r.int1(), r.err
		}
		return int8(r.int1()), r.err
	case TypeShort:
		if col.Unsigned {
			return r.int2(), r.err
		}
		return int16(r.int2()), r.err
	case TypeInt24:
		v := r.int3()
		if v&0x00800000 != 0 {
			v |= 0xFF000000
		}
		if col.Unsigned {
			return v, r.err
		}
		return int32(v), r.err
	case TypeLong:
		if col.Unsigned {
			return r.int4(), r.err
		}
		return int32(r.int4()), r.err
	case TypeLongLong:
		if col.Unsigned {
			return r.int8(), r.err
		}
		return int64(r.int8()), r.err
	case TypeFloat:
		return math.Float32frombits(r.int4()), r.err
	case TypeDouble:
		return math.Float64frombits(r.int8()), r.err
	case TypeVarchar:
		var size int
		if binary.LittleEndian.Uint16(col.meta) < 256 {
			size = int(r.int1())
		} else {
			size = int(r.int2())
		}
		return r.string(size), r.err
	case TypeBlob:
		size := r.intFixed(int(col.meta[0]))
		return r.bytes(int(size)), r.err
	case TypeJSON:
		size := r.intFixed(int(col.meta[0]))
		data := r.bytesInternal(int(size))
		if r.err != nil {
			return nil, r.err
		}
		return new(jsonDecoder).decodeValue(data)
	case TypeDateTime2:
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
	case TypeTimestamp2:
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
	case TypeTime2:
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
	case TypeYear:
		return 1900 + int(r.int1()), r.err
	}
	return nil, fmt.Errorf("unmarshal of mysql type 0x%x is not implemented", col.Type)
}

func fractionalSeconds(meta byte, r *reader) (int, error) {
	switch meta {
	case 0:
		return 0, nil
	case 1, 2:
		return int(r.int1()) * 10000, r.err
	case 3, 4:
		b := r.bytesInternal(2)
		return int(uint16(b[1])|uint16(b[0])<<8) * 100, r.err
	case 5, 6:
		b := r.bytesInternal(3)
		return int(uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16), r.err
	}
	return 0, fmt.Errorf("binlog.fractionalSeconds: meta=%d must be less than 6", meta)
}

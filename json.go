package binlog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// https://dev.mysql.com/worklog/task/?id=8132#tabs-8132-4
type jsonDecoder struct{}

const (
	jsonSmallObj byte = iota
	jsonLargeObj
	jsonSmallArr
	jsonLargeArr
	jsonLiteral
	jsonInt16
	jsonUInt16
	jsonInt32
	jsonUInt32
	jsonInt64
	jsonUInt64
	jsonDouble
	jsonString
	jsonCustom = 0x0f
)

func (d *jsonDecoder) decodeValue(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	return d.decodeValueType(data[0], data[1:])
}

func (d *jsonDecoder) decodeValueType(typ byte, data []byte) (interface{}, error) {
	switch typ {
	case jsonSmallObj:
		return d.decodeComposite(data, true, true)
	case jsonLargeObj:
		return d.decodeComposite(data, false, true)
	case jsonSmallArr:
		return d.decodeComposite(data, true, false)
	case jsonLargeArr:
		return d.decodeComposite(data, false, false)
	case jsonLiteral:
		return d.decodeLiteral(data)
	case jsonInt16:
		v, err := d.decodeUInt16(data)
		return int16(v), err
	case jsonUInt16:
		return d.decodeUInt16(data)
	case jsonInt32:
		v, err := d.decodeUInt32(data)
		return int32(v), err
	case jsonUInt32:
		return d.decodeUInt32(data)
	case jsonInt64:
		v, err := d.decodeUInt64(data)
		return int64(v), err
	case jsonUInt64:
		return d.decodeUInt64(data)
	case jsonDouble:
		v, err := d.decodeUInt64(data)
		return math.Float64frombits(v), err
	case jsonString:
		return d.decodeString(data)
	case jsonCustom:
		return d.decodeCustom(data)
	}
	return nil, fmt.Errorf("invalid json value type: 0x%02x", typ)
}

func (d *jsonDecoder) decodeComposite(data []byte, small bool, obj bool) (interface{}, error) {
	var off int
	decodeUInt := func() (uint32, error) {
		if small {
			v, err := d.decodeUInt16(data[off:])
			if err != nil {
				return 0, err
			}
			off += 2
			return uint32(v), nil
		} else {
			v, err := d.decodeUInt32(data[off:])
			off += 4
			return v, err
		}
	}
	elemCount, err := decodeUInt()
	if err != nil {
		return nil, err
	}
	size, err := decodeUInt()
	if err != nil {
		return nil, err
	}
	_ = size
	var keys []string
	if obj {
		keys = make([]string, elemCount)
		for i := uint32(0); i < elemCount; i++ {
			keyOff, err := decodeUInt()
			if err != nil {
				return nil, err
			}
			keyLen, err := d.decodeUInt16(data[off:])
			if err != nil {
				return nil, err
			}
			off += 2
			if len(data) < int(keyOff+uint32(keyLen)) {
				return nil, io.ErrUnexpectedEOF
			}
			keys[i] = string(data[keyOff : keyOff+uint32(keyLen)])
		}
	}

	inlineValue := func(typ byte) bool {
		switch typ {
		case jsonLiteral, jsonInt16, jsonUInt16:
			return true
		case jsonInt32, jsonUInt32:
			return !small
		}
		return false
	}
	vals := make([]interface{}, elemCount)
	for i := uint32(0); i < elemCount; i++ {
		typ := data[off]
		off++
		if inlineValue(typ) {
			v, err := d.decodeValueType(typ, data[off:])
			if err != nil {
				return nil, err
			}
			vals[i] = v
			if small {
				off += 2
			} else {
				off += 4
			}
		} else {
			valueOff, err := decodeUInt()
			if err != nil {
				return nil, err
			}
			v, err := d.decodeValueType(typ, data[valueOff:])
			if err != nil {
				return nil, err
			}
			vals[i] = v
		}
	}

	if obj {
		m := make(map[string]interface{})
		for i, key := range keys {
			m[key] = vals[i]
		}
		return m, nil
	}
	return vals, nil
}

func (d *jsonDecoder) decodeLiteral(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	switch data[0] {
	case 0x00:
		return nil, nil
	case 0x01:
		return true, nil
	case 0x02:
		return false, nil
	}
	return nil, fmt.Errorf("invalid json literal type: 0x%02x", data[0])
}

func (d *jsonDecoder) decodeUInt16(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint16(data), nil
}

func (d *jsonDecoder) decodeUInt32(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (d *jsonDecoder) decodeUInt64(data []byte) (uint64, error) {
	if len(data) < 8 {
		return 0, io.ErrUnexpectedEOF
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (d *jsonDecoder) decodeDataLen(data []byte) (uint64, []byte, error) {
	const max = 5 // math.MaxUint32 can be encoded in 5 bytes
	var size uint64
	for i := 0; i < max; i++ {
		if len(data) == 0 {
			return 0, data, io.ErrUnexpectedEOF
		}
		v := data[0]
		data = data[1:]
		size |= uint64(v&0x7F) << uint(7*i)
		if highBit := v & (1 << 7); highBit == 0 {
			return size, data, nil
		}
	}
	return 0, nil, errors.New("invalid dataLen")
}

func (d *jsonDecoder) decodeString(data []byte) (string, error) {
	size, data, err := d.decodeDataLen(data)
	if err != nil {
		return "", err
	}
	if len(data) < int(size) {
		return "", io.ErrUnexpectedEOF
	}
	return string(data[:size]), nil
}

func (d *jsonDecoder) decodeCustom(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	typ := data[0]
	data = data[1:]
	size, data, err := d.decodeDataLen(data)
	if err != nil {
		return nil, err
	}
	if len(data) < int(size) {
		return nil, io.ErrUnexpectedEOF
	}

	switch ColumnType(typ) {
	case TypeNewDecimal:
		precision := int(data[0])
		scale := int(data[1])
		return decodeDecimal(data[2:], precision, scale)
	case TypeTime:
		if len(data) < 8 {
			return nil, io.ErrUnexpectedEOF
		}
		v := int64(binary.LittleEndian.Uint64(data))
		var hour, min, sec, frac int64
		var sign = 1
		if v != 0 {
			if v < 0 {
				v = -v
				sign = -1
			}
			frac = v % (1 << 24)
			v = v >> 24
			hour = (v >> 12) % (1 << 10)
			min = (v >> 6) % (1 << 6)
			sec = v % (1 << 6)
		}
		return time.Duration(sign) * (time.Duration(hour)*time.Hour +
			time.Duration(min)*time.Minute +
			time.Duration(sec)*time.Second +
			time.Duration(frac)*time.Microsecond), nil
	case TypeDate, TypeDateTime, TypeTimestamp:
		if len(data) < 8 {
			return nil, io.ErrUnexpectedEOF
		}
		v := binary.LittleEndian.Uint64(data)
		var year, month, day, hour, min, sec, frac uint64
		if v != 0 {
			if v < 0 {
				v = -v
			}
			frac = v % (1 << 24)
			v = v >> 24
			ymd := v >> 17
			ym := ymd >> 5
			year, month, day = ym/13, ym%13, ymd%(1<<5)
			hms := v % (1 << 17)
			hour, min, sec = hms>>12, (hms>>6)%(1<<6), hms%(1<<6)
		}
		var loc = time.UTC
		if ColumnType(typ) == TypeTimestamp {
			loc = time.Local
		}
		return time.Date(int(year), time.Month(month), int(day), int(hour), int(min), int(sec), int(frac*1000), loc), nil
	default:
		return string(data), nil
	}
}

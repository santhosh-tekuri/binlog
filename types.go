package binlog

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

type ColumnType uint8

const (
	TypeDecimal    ColumnType = 0x00
	TypeTiny       ColumnType = 0x01
	TypeShort      ColumnType = 0x02
	TypeLong       ColumnType = 0x03
	TypeFloat      ColumnType = 0x04
	TypeDouble     ColumnType = 0x05
	TypeNull       ColumnType = 0x06
	TypeTimestamp  ColumnType = 0x07
	TypeLongLong   ColumnType = 0x08
	TypeInt24      ColumnType = 0x09
	TypeDate       ColumnType = 0x0a
	TypeTime       ColumnType = 0x0b
	TypeDateTime   ColumnType = 0x0c
	TypeYear       ColumnType = 0x0d // YEAR(1901 to 2155, and 0000)
	TypeNewDate    ColumnType = 0x0e
	TypeVarchar    ColumnType = 0x0f // VARCHAR(65535)
	TypeBit        ColumnType = 0x10
	TypeTimestamp2 ColumnType = 0x11
	TypeDateTime2  ColumnType = 0x12
	TypeTime2      ColumnType = 0x13
	TypeJSON       ColumnType = 0xf5
	TypeNewDecimal ColumnType = 0xf6 // DECIMAL NUMERIC
	TypeEnum       ColumnType = 0xf7
	TypeSet        ColumnType = 0xf8
	TypeTinyBlob   ColumnType = 0xf9
	TypeMediumBlob ColumnType = 0xfa
	TypeLongBlob   ColumnType = 0xfb
	TypeBlob       ColumnType = 0xfc // TINYTEXT TEXT MEDIUMTEXT LONGTEXT TINYBLOB BLOB MEDIUMBLOB LONGBLOB
	TypeVarString  ColumnType = 0xfd
	TypeString     ColumnType = 0xfe // CHAR(255) ENUM(65535) SET(64)
	TypeGeometry   ColumnType = 0xff
)

var typeNames = map[ColumnType]string{
	TypeDecimal:    "decimal",
	TypeTiny:       "tiny",
	TypeShort:      "short",
	TypeLong:       "long",
	TypeFloat:      "float",
	TypeDouble:     "double",
	TypeNull:       "null",
	TypeTimestamp:  "timestamp",
	TypeLongLong:   "longLong",
	TypeInt24:      "int24",
	TypeDate:       "date",
	TypeTime:       "time",
	TypeDateTime:   "dateTime",
	TypeYear:       "year",
	TypeNewDate:    "newDate",
	TypeVarchar:    "varchar",
	TypeBit:        "bit",
	TypeTimestamp2: "timestamp2",
	TypeDateTime2:  "dateTime2",
	TypeTime2:      "time2",
	TypeJSON:       "json",
	TypeNewDecimal: "newDecimal",
	TypeEnum:       "enum",
	TypeSet:        "set",
	TypeTinyBlob:   "tinyBlob",
	TypeMediumBlob: "mediumBlob",
	TypeLongBlob:   "longBlob",
	TypeBlob:       "blob",
	TypeVarString:  "varString",
	TypeString:     "string",
	TypeGeometry:   "geometry",
}

func (t ColumnType) isNumeric() bool {
	switch t {
	case TypeTiny, TypeShort, TypeInt24, TypeLong, TypeLongLong,
		TypeFloat, TypeDouble, TypeDecimal, TypeNewDecimal:
		return true
	}
	return false
}

func (t ColumnType) isString() bool {
	switch t {
	case TypeVarchar, TypeBlob, TypeVarString, TypeString:
		return true
	}
	return false
}

func (t ColumnType) isEnumSet() bool {
	return t == TypeEnum || t == TypeSet
}

func (t ColumnType) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("0x%02x", uint8(t))
}

// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
// todo: test with table with all types, especially negative numbers
func (col Column) decodeValue(r *reader) (interface{}, error) {
	fmt.Println("coltype:", col.Type, col.Charset)
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
		if col.Unsigned {
			return v, r.err
		}
		if v&0x00800000 != 0 {
			// negative number
			v |= 0xFF000000
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
	case TypeNewDecimal:
		precision := int(byte(col.Meta))
		scale := int(byte(col.Meta >> 8))
		buff := r.bytes(decimalSize(precision, scale))
		if r.err != nil {
			return nil, r.err
		}
		return decodeDecimal(buff, precision, scale)
	case TypeFloat:
		return math.Float32frombits(r.int4()), r.err
	case TypeDouble:
		return math.Float64frombits(r.int8()), r.err
	case TypeVarchar, TypeString:
		var size int
		if col.Meta < 256 {
			size = int(r.int1())
		} else {
			size = int(r.int2())
		}
		return r.string(size), r.err
	case TypeEnum:
		switch col.Meta {
		case 1:
			return uint16(r.int1()), r.err
		case 2:
			return r.int2(), r.err
		default:
			return nil, fmt.Errorf("binlog.decodeValue: invalid enum length %d", col.Meta)
		}
	case TypeSet:
		n := col.Meta // == length
		if n == 0 || n > 8 {
			return nil, fmt.Errorf("binlog.decodeValue: invalid num bits in set %d", n)
		}
		return r.intFixed(int(n)), r.err
	case TypeBit:
		nbits := ((col.Meta >> 8) * 8) + (col.Meta & 0xFF)
		buf := r.bytesInternal(int(nbits+7) / 8)
		return bigEndian(buf), r.err
	case TypeBlob, TypeGeometry:
		size := r.intFixed(int(col.Meta))
		return r.bytes(int(size)), r.err
	case TypeJSON:
		size := r.intFixed(int(col.Meta))
		data := r.bytesInternal(int(size))
		if r.err != nil {
			return nil, r.err
		}
		return new(jsonDecoder).decodeValue(data)
	case TypeDate:
		v := r.int3()
		var year, month, day uint32
		if v != 0 {
			year, month, day = v/(16*32), v/32%16, v%32
		}
		return time.Date(int(year), time.Month(month), int(day), 0, 0, 0, 0, time.UTC), r.err
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

		frac, err := fractionalSeconds(col.Meta, r)
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

		frac, err := fractionalSeconds(col.Meta, r)
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
		frac, err := fractionalSeconds(col.Meta, r)
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
		v := int(r.int1())
		if v == 0 {
			return 0, r.err
		}
		return 1900 + v, r.err
	}
	return nil, fmt.Errorf("unmarshal of mysql type %s is not implemented", col.Type)
}

func fractionalSeconds(meta uint16, r *reader) (int, error) {
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

func (col Column) ValueLiteral(v interface{}) string {
	if v == nil {
		return "NULL"
	}
	switch col.Type {
	case TypeEnum:
		v := int(v.(uint16))
		if v == 0 {
			return `""`
		}
		if v-1 < len(col.Values) {
			return strconv.Quote(col.Values[v-1])
		}
	case TypeSet:
		if len(col.Values) > 0 {
			v := v.(uint64)
			var buf strings.Builder
			for i, val := range col.Values {
				if v&(1<<i) != 0 {
					if buf.Len() > 0 {
						buf.WriteByte(',')
					}
					buf.WriteString(val)
				}
			}
			return strconv.Quote(buf.String())
		}
	case TypeJSON:
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(v)
		s := buf.String()
		return strconv.Quote(s[:len(s)-1]) // remove trailing newline
	case TypeBlob:
		v := v.([]byte)
		if col.Charset == 0 || col.Charset == 63 { // 63 = binary charset
			return fmt.Sprintf(`x"%s"`, hex.EncodeToString(v))
		}
		return strconv.Quote(string(v))
	}
	switch v := v.(type) {
	case time.Time:
		return strconv.Quote(v.String())
	}
	return fmt.Sprintf("%#v", v)
}

// Decimal ---

const digitsPerInteger int = 9

var compressedBytes = []int{0, 1, 1, 2, 2, 3, 3, 4, 4, 4}

func decodeDecimalDecompressValue(compIndex int, data []byte, mask uint8) (size int, value uint32) {
	size = compressedBytes[compIndex]
	buff := make([]byte, size)
	for i := 0; i < size; i++ {
		buff[i] = data[i] ^ mask
	}
	value = uint32(bigEndian(buff))
	return
}

func decimalSize(precision int, scale int) int {
	integral := precision - scale
	uncompIntegral := integral / digitsPerInteger
	uncompFractional := scale / digitsPerInteger
	compIntegral := integral - (uncompIntegral * digitsPerInteger)
	compFractional := scale - (uncompFractional * digitsPerInteger)

	return uncompIntegral*4 + compressedBytes[compIntegral] +
		uncompFractional*4 + compressedBytes[compFractional]
}

func decodeDecimal(data []byte, precision int, scale int) (*big.Float, error) {
	integral := precision - scale
	uncompIntegral := integral / digitsPerInteger
	uncompFractional := scale / digitsPerInteger
	compIntegral := integral - (uncompIntegral * digitsPerInteger)
	compFractional := scale - (uncompFractional * digitsPerInteger)

	binSize := uncompIntegral*4 + compressedBytes[compIntegral] +
		uncompFractional*4 + compressedBytes[compFractional]

	buf := make([]byte, binSize)
	copy(buf, data[:binSize])

	//must copy the data for later change
	data = buf

	// Support negative
	// The sign is encoded in the high bit of the the byte
	// But this bit can also be used in the value
	value := uint32(data[0])
	var res bytes.Buffer
	var mask uint32 = 0
	if value&0x80 == 0 {
		mask = uint32((1 << 32) - 1)
		res.WriteString("-")
	}

	//clear sign
	data[0] ^= 0x80

	pos, value := decodeDecimalDecompressValue(compIntegral, data, uint8(mask))
	res.WriteString(fmt.Sprintf("%d", value))

	for i := 0; i < uncompIntegral; i++ {
		value = binary.BigEndian.Uint32(data[pos:]) ^ mask
		pos += 4
		res.WriteString(fmt.Sprintf("%09d", value))
	}

	res.WriteString(".")

	for i := 0; i < uncompFractional; i++ {
		value = binary.BigEndian.Uint32(data[pos:]) ^ mask
		pos += 4
		res.WriteString(fmt.Sprintf("%09d", value))
	}

	if size, value := decodeDecimalDecompressValue(compFractional, data[pos:], uint8(mask)); size > 0 {
		res.WriteString(fmt.Sprintf("%0*d", compFractional, value))
		pos += size
	}

	f, _, err := new(big.Float).Parse(string(res.Bytes()), 0)
	return f, err
}

func bigEndian(buf []byte) uint64 {
	var num uint64 = 0
	for i, b := range buf {
		num |= uint64(b) << (uint(len(buf)-i-1) * 8)
	}
	return num
}

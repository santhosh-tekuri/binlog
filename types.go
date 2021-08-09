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

// ColumnType used in TableMapEvent and RowsEvent.
type ColumnType uint8

// ColumnType Constants
//
// https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnType
const (
	TypeDecimal    ColumnType = 0x00
	TypeTiny       ColumnType = 0x01 // int8 or uint8. TINYINT
	TypeShort      ColumnType = 0x02 // int16 or uint16. SMALLINT
	TypeLong       ColumnType = 0x03 // int32 or uint32. INT
	TypeFloat      ColumnType = 0x04 // float32. FLOAT
	TypeDouble     ColumnType = 0x05 // float64. DOUBLE
	TypeNull       ColumnType = 0x06
	TypeTimestamp  ColumnType = 0x07
	TypeLongLong   ColumnType = 0x08 // int64 or uint64. BIGINT
	TypeInt24      ColumnType = 0x09 // int32 or uint32. MEDIUMINT
	TypeDate       ColumnType = 0x0a // time.Time(UTC). DATE
	TypeTime       ColumnType = 0x0b
	TypeDateTime   ColumnType = 0x0c
	TypeYear       ColumnType = 0x0d // int. YEAR
	TypeNewDate    ColumnType = 0x0e
	TypeVarchar    ColumnType = 0x0f // string. VARCHAR
	TypeBit        ColumnType = 0x10 // uint64. BIT
	TypeTimestamp2 ColumnType = 0x11 // time.Time(LOCAL). TIMESTAMP
	TypeDateTime2  ColumnType = 0x12 // time.Time(UTC). DATETIME
	TypeTime2      ColumnType = 0x13 // time.Duration. TIME
	TypeJSON       ColumnType = 0xf5 // JSON, JSON
	TypeNewDecimal ColumnType = 0xf6 // Decimal. DECIMAL NUMERIC
	TypeEnum       ColumnType = 0xf7 // Enum. ENUM
	TypeSet        ColumnType = 0xf8 // Set. SET
	TypeTinyBlob   ColumnType = 0xf9
	TypeMediumBlob ColumnType = 0xfa
	TypeLongBlob   ColumnType = 0xfb
	TypeBlob       ColumnType = 0xfc // []byte or string. TINYBLOB BLOB MEDIUMBLOB LONGBLOB TINYTEXT TEXT MEDIUMTEXT LONGTEXT
	TypeVarString  ColumnType = 0xfd
	TypeString     ColumnType = 0xfe // string. CHAR
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
			return Enum{uint16(r.int1()), col.Values}, r.err
		case 2:
			return Enum{r.int2(), col.Values}, r.err
		default:
			return nil, fmt.Errorf("binlog.decodeValue: invalid enum length %d", col.Meta)
		}
	case TypeSet:
		n := col.Meta // == length
		if n == 0 || n > 8 {
			return nil, fmt.Errorf("binlog.decodeValue: invalid num bits in set %d", n)
		}
		return Set{r.intFixed(int(n)), col.Values}, r.err
	case TypeBit:
		nbits := ((col.Meta >> 8) * 8) + (col.Meta & 0xFF)
		buf := r.bytesInternal(int(nbits+7) / 8)
		return bigEndian(buf), r.err
	case TypeBlob, TypeGeometry:
		size := r.intFixed(int(col.Meta))
		v := r.bytes(int(size))
		if col.Charset == 0 || col.Charset == 63 {
			return v, r.err
		}
		return string(v), r.err
	case TypeJSON:
		size := r.intFixed(int(col.Meta))
		buf := r.bytesInternal(int(size))
		if r.err != nil {
			return nil, r.err
		}
		v, err := new(jsonDecoder).decodeValue(buf)
		return JSON{v}, err
	case TypeDate:
		v := r.int3()
		var year, month, day uint32
		if v != 0 {
			year, month, day = v/(16*32), v/32%16, v%32
		}
		return time.Date(int(year), time.Month(month), int(day), 0, 0, 0, 0, time.UTC), r.err
	case TypeDateTime2:
		buf := r.bytesInternal(5)
		if r.err != nil {
			return nil, r.err
		}
		dt := bigEndian(buf)
		ym := bitSlice(dt, 40, 1, 17)
		year, month := ym/13, ym%13
		day := bitSlice(dt, 40, 18, 5)
		hour := bitSlice(dt, 40, 23, 5)
		min := bitSlice(dt, 40, 28, 6)
		sec := bitSlice(dt, 40, 34, 6)

		frac, err := fractionalSeconds(col.Meta, r)
		if err != nil {
			return nil, err
		}
		return time.Date(year, time.Month(month), day, hour, min, sec, frac*1000, time.UTC), r.err
	case TypeTimestamp2:
		buf := r.bytesInternal(4)
		if r.err != nil {
			return nil, r.err
		}
		sec := binary.BigEndian.Uint32(buf)

		frac, err := fractionalSeconds(col.Meta, r)
		if err != nil {
			return nil, err
		}
		return time.Unix(int64(sec), int64(frac)*1000), r.err
	case TypeTime2:
		// https://github.com/debezium/debezium/blob/master/debezium-connector-mysql/src/main/java/io/debezium/connector/mysql/RowDeserializers.java#L314
		//
		// (in big endian)
		//
		// 1 bit sign (1= non-negative, 0= negative)
		// 1 bit unused (reserved for future extensions)
		// 10 bits hour (0-838)
		// 6 bits minute (0-59)
		// 6 bits second (0-59)
		//
		// (3 bytes in total)
		//
		// + fractional-seconds storage (size depends on meta)
		buf := r.bytesInternal(3)
		if r.err != nil {
			return nil, r.err
		}
		t := bigEndian(buf)
		sign := bitSlice(t, 24, 0, 1)
		hour := bitSlice(t, 24, 2, 10)
		min := bitSlice(t, 24, 12, 6)
		sec := bitSlice(t, 24, 18, 6)
		var frac int
		var err error
		if sign == 0 {
			// -ve
			hour = ^hour & mask(10)
			hour = hour & unsetSignMask(10) // unset sign bit
			min = ^min & mask(6)
			min = min & unsetSignMask(6) // unset sign bit
			sec = ^sec & mask(6)
			sec = sec & unsetSignMask(6) // unset sign bit

			frac, err = fractionalSecondsNegative(col.Meta, r)
			if err != nil {
				return nil, err
			}
			if frac == 0 && sec < 59 { // weird duration behavior
				sec++
			}
		} else {
			frac, err = fractionalSeconds(col.Meta, r)
			if err != nil {
				return nil, err
			}
		}
		v := time.Duration(hour)*time.Hour +
			time.Duration(min)*time.Minute +
			time.Duration(sec)*time.Second +
			time.Duration(frac)*time.Microsecond
		if sign == 0 {
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
	return nil, fmt.Errorf("decode of mysql type %s is not implemented", col.Type)
}

func bitSlice(v uint64, bits, off, len int) int {
	v >>= bits - (off + len)
	return int(v & ((1 << len) - 1))
}

func fractionalSeconds(meta uint16, r *reader) (int, error) {
	n := (meta + 1) / 2
	v := bigEndian(r.bytesInternal(int(n)))
	return int(v * uint64(math.Pow(100, float64(3-n)))), r.err
}

func fractionalSecondsNegative(meta uint16, r *reader) (int, error) {
	n := (meta + 1) / 2
	v := int(bigEndian(r.bytesInternal(int(n))))
	if v != 0 {
		bits := int(n * 8)
		v = ^v & mask(bits)
		v = (v & unsetSignMask(bits)) + 1
	}
	return v * int(math.Pow(100, float64(3-n))), r.err
}

func mask(bits int) int {
	return (1 << bits) - 1
}

func unsetSignMask(bits int) int {
	return ^(1 << bits)
}

func (col Column) valueLiteral(v interface{}) string {
	if v == nil {
		return "NULL"
	}
	switch col.Type {
	case TypeEnum:
		v := v.(Enum)
		if len(v.Values) > 0 {
			return strconv.Quote(v.String())
		}
	case TypeSet:
		v := v.(Set)
		if len(v.Values) > 0 {
			return strconv.Quote(v.String())
		}
	case TypeJSON:
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(v)
		s := buf.String()
		return strconv.Quote(s[:len(s)-1]) // remove trailing newline
	case TypeBlob:
		if v, ok := v.([]byte); ok { // 63 = binary charset
			return fmt.Sprintf(`x"%s"`, hex.EncodeToString(v))
		}
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

func decodeDecimal(data []byte, precision int, scale int) (Decimal, error) {
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

	// remove leading zeros & trailing dot
	s := res.String()
	res.Reset()
	if s[0] == '-' {
		res.WriteString("-")
		s = s[1:]
	}
	for len(s) > 1 && s[0] == '0' && s[1] != '.' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	res.WriteString(s)

	return Decimal(res.String()), nil
}

func bigEndian(buf []byte) uint64 {
	var num uint64 = 0
	for i, b := range buf {
		num |= uint64(b) << (uint(len(buf)-i-1) * 8)
	}
	return num
}

// Enum represents value of TypeEnum.
//
// https://dev.mysql.com/doc/refman/8.0/en/enum.html
type Enum struct {
	// index value. refers to a position in list of permitted values.
	// begins with 1.
	// 0 means empty string invalid value.
	Val uint16

	// list of permitted values.
	// will be populated only if system
	// variable binlog_row_metadata==FULL
	Values []string
}

func (e Enum) String() string {
	if len(e.Values) > 0 {
		if e.Val == 0 {
			return ""
		}
		return e.Values[e.Val-1]
	}
	return fmt.Sprintf("%d", e.Val)
}

func (e Enum) MarshalJSON() ([]byte, error) {
	if len(e.Values) > 0 {
		return []byte(strconv.Quote(e.String())), nil
	}
	return []byte(e.String()), nil
}

// Set represents value of TypeSet.
//
// https://dev.mysql.com/doc/refman/8.0/en/set.html
type Set struct {
	// set's numerical value with bits set corresponding
	// to the set members that make up the column value.
	// 0 means empty string invalid value.
	Val uint64

	// list of permitted values.
	// will be populated only if system
	// variable binlog_row_metadata==FULL
	Values []string
}

// Members returns the values in this set.
func (s Set) Members() []string {
	var m []string
	if len(s.Values) > 0 {
		for i, val := range s.Values {
			if s.Val&(1<<i) != 0 {
				m = append(m, val)
			}
		}
	}
	return m
}

func (s Set) String() string {
	if len(s.Values) > 0 {
		if s.Val == 0 {
			return ""
		}
		var buf strings.Builder
		for i, val := range s.Values {
			if s.Val&(1<<i) != 0 {
				if buf.Len() > 0 {
					buf.WriteByte(',')
				}
				buf.WriteString(val)
			}
		}
		return buf.String()
	}
	return fmt.Sprintf("%d", s.Val)
}

func (s Set) MarshalJSON() ([]byte, error) {
	if len(s.Values) > 0 {
		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(s.Members())
		return buf.Bytes(), err
	}
	return []byte(s.String()), nil
}

// A Decimal represents a MySQL Decimal/Numeric literal.
//
// https://dev.mysql.com/doc/refman/8.0/en/fixed-point-types.html
type Decimal string

func (d Decimal) String() string { return string(d) }

// Float64 returns the number as a float64.
func (d Decimal) Float64() (float64, error) {
	return strconv.ParseFloat(string(d), 64)
}

// BigFloat returns the number as a *big.Float.
func (d Decimal) BigFloat() (*big.Float, error) {
	f, _, err := new(big.Float).Parse(string(d), 0)
	return f, err
}

func (d Decimal) MarshalJSON() ([]byte, error) {
	return []byte(d), nil
}

// Json represents value of TypeJSON
//
// https://dev.mysql.com/doc/refman/8.0/en/json.html
type JSON struct{ Val interface{} }

func (j JSON) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(j.Val)
	return buf.Bytes(), err
}

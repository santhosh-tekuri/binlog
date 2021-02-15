package binlog

import (
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func TestColumn_decodeValue(t *testing.T) {
	testCases := []struct {
		sqlType string
		val     string
		want    interface{}
	}{
		{"tinyint", "23", int8(23)},
		{"tinyint", "-23", int8(-23)},
		{"tinyint", "-128", int8(-128)},
		{"tinyint", "127", int8(127)},
		{"tinyint unsigned", "23", uint8(23)},
		{"tinyint unsigned", "0", uint8(0)},
		{"tinyint unsigned", "255", uint8(255)},
		{"smallint", "23", int16(23)},
		{"smallint", "-23", int16(-23)},
		{"smallint", "-32768", int16(-32768)},
		{"smallint", "32767", int16(32767)},
		{"smallint unsigned", "23", uint16(23)},
		{"smallint unsigned", "0", uint16(0)},
		{"smallint unsigned", "65535", uint16(65535)},
		{"mediumint", "23", int32(23)},
		{"mediumint", "-23", int32(-23)},
		{"mediumint", "-8388608", int32(-8388608)},
		{"mediumint", "8388607", int32(8388607)},
		{"mediumint unsigned", "23", uint32(23)},
		{"mediumint unsigned", "0", uint32(0)},
		{"mediumint unsigned", "16777215", uint32(16777215)},
		{"int", "23", int32(23)},
		{"int", "-23", int32(-23)},
		{"int", "-2147483648", int32(-2147483648)},
		{"int", "2147483647", int32(2147483647)},
		{"int unsigned", "23", uint32(23)},
		{"int unsigned", "0", uint32(0)},
		{"int unsigned", "4294967295", uint32(4294967295)},
		{"bigint", "23", int64(23)},
		{"bigint", "-23", int64(-23)},
		{"bigint", "-9223372036854775808", int64(-9223372036854775808)},
		{"bigint", "9223372036854775807", int64(9223372036854775807)},
		{"bigint unsigned", "23", uint64(23)},
		{"bigint unsigned", "0", uint64(0)},
		{"bigint unsigned", "18446744073709551615", uint64(18446744073709551615)},
		{"float", "1.2345", float32(1.2345)},
		{"float", "-1.2345", float32(-1.2345)},
		{"double", "1.2345", float64(1.2345)},
		{"double", "-1.2345", float64(-1.2345)},
		{"decimal(6,3)", "123.456", Decimal("123.456")},
		{"decimal(6,3)", "12.45", Decimal("12.450")},
		{"decimal(6,3)", "-123.456", Decimal("-123.456")},
		{"decimal(6,3)", "-12.45", Decimal("-12.450")},
		{"numeric(6,3)", "123.456", Decimal("123.456")},
		{"numeric(6,3)", "12.45", Decimal("12.450")},
		{"numeric(6,3)", "-123.456", Decimal("-123.456")},
		{"numeric(6,3)", "-12.45", Decimal("-12.450")},
		{"bit(5)", "11", uint64(11)},
		{"bit(5)", "0", uint64(0)},
		{"bit(5)", "31", uint64(31)},
		{"bit(64)", "11", uint64(11)},
		{"bit(64)", "0", uint64(0)},
		{"bit(64)", "18446744073709551615", uint64(18446744073709551615)},
		{"char(5)", "'abc'", "abc"},
		{"char(5)", "'abcde'", "abcde"},
		{"char(255)", "'abc'", "abc"},
		{"char(255)", "''", ""},
		{"char(255)", "'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"},
		{"varchar(5)", "'abc'", "abc"},
		{"varchar(5)", "'abcde'", "abcde"},
		{"varchar(16383)", "'abc'", "abc"},
		{"varchar(16383)", "''", ""},
		{"varchar(16383)", "'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"},
		{"tinyblob", "BINARY('hello world!!!')", []byte("hello world!!!")},
		{"blob", "BINARY('hello world!!!')", []byte("hello world!!!")},
		{"blob(100)", "BINARY('hello world!!!')", []byte("hello world!!!")},
		{"mediumblob", "BINARY('hello world!!!')", []byte("hello world!!!")},
		{"longblob", "BINARY('hello world!!!')", []byte("hello world!!!")},
		{"tinytext", "'hello world!!!'", "hello world!!!"},
		{"text", "'hello world!!!'", "hello world!!!"},
		{"text(100)", "'hello world!!!'", "hello world!!!"},
		{"mediumtext", "'hello world!!!'", "hello world!!!"},
		{"longtext", "'hello world!!!'", "hello world!!!"},
		{"enum('x-small', 'small', 'medium', 'large', 'x-large')", "'x-small'", Enum{1, nil}},
		{"enum('x-small', 'small', 'medium', 'large', 'x-large')", "'x-large'", Enum{5, nil}},
		{"set('x-small', 'small', 'medium', 'large', 'x-large')", "'x-small,medium'", Set{0b101, nil}},
		{"set('x-small', 'small', 'medium', 'large', 'x-large')", "'medium,x-small'", Set{0b101, nil}},
		{"set('x-small', 'small', 'medium', 'large', 'x-large')", "''", Set{0b0, nil}},
		{"set('x-small', 'small', 'medium', 'large', 'x-large')", "'x-small,small,medium,large,x-large'", Set{0b11111, nil}},
		{"year", "0", int(0)},
		{"year", "1901", int(1901)},
		{"year", "1", int(2001)},
		{"year", "2155", int(2155)},
		{"year", "99", int(1999)},
		{"date", "'2021-02-14'", time.Date(2021, time.February, 14, 0, 0, 0, 0, time.UTC)},
		{"date", "'1000-01-01'", time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)},   // min
		{"date", "'9999-12-31'", time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)}, // max
		{"datetime(3)", "'2021-02-14 20:37:12.123'", time.Date(2021, time.February, 14, 20, 37, 12, 123000000, time.UTC)},
		{"datetime(6)", "'2021-02-14 20:37:12.123456'", time.Date(2021, time.February, 14, 20, 37, 12, 123456000, time.UTC)},
		{"datetime(6)", "'1000-01-01 00:00:00.000000'", time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)},              // min
		{"datetime(6)", "'9999-12-31 23:59:59.999999'", time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC)}, // max
		{"timestamp(3)", "'2021-02-14 20:37:12.123'", time.Date(2021, time.February, 14, 20, 37, 12, 123000000, time.Local)},
		{"timestamp(6)", "'2021-02-14 20:37:12.123456'", time.Date(2021, time.February, 14, 20, 37, 12, 123456000, time.Local)},
		{"timestamp(6)", "convert_tz('1970-01-01 00:00:01.000000', '+00:00', @@session.time_zone)", time.Date(1970, time.January, 1, 0, 0, 1, 0, time.UTC).Local()},           // min
		{"timestamp(6)", "convert_tz('2038-01-19 03:14:07.999999', '+00:00', @@session.time_zone)", time.Date(2038, time.January, 19, 3, 14, 7, 999999000, time.UTC).Local()}, // max
		{"time(6)", "'-838:59:59.000000'", -(838*time.Hour + 59*time.Minute + 59*time.Second)},                                                                                // min
		{"time(6)", "'838:59:59.000000'", 838*time.Hour + 59*time.Minute + 59*time.Second},                                                                                    // max
		{"time(6)", "'-838:51:59.000000'", -(838*time.Hour + 51*time.Minute + 59*time.Second)},
		{"time(6)", "'-838:51:58.000000'", -(838*time.Hour + 51*time.Minute + 58*time.Second)},
		{"time(6)", "'-838:51:58.123456'", -(838*time.Hour + 51*time.Minute + 58*time.Second + 123456*time.Microsecond)},
		{"time(3)", "'-838:51:58.123'", -(838*time.Hour + 51*time.Minute + 58*time.Second + 123000*time.Microsecond)},
		{"time(2)", "'-838:51:58.12'", -(838*time.Hour + 51*time.Minute + 58*time.Second + 120000*time.Microsecond)},
		{"time(1)", "'-838:51:58.1'", -(838*time.Hour + 51*time.Minute + 58*time.Second + 100000*time.Microsecond)},
		{"time(6)", "'838:51:59.000000'", 838*time.Hour + 51*time.Minute + 59*time.Second},
		{"time(6)", "'838:51:58.000000'", 838*time.Hour + 51*time.Minute + 58*time.Second},
		{"time(6)", "'838:51:58.123456'", 838*time.Hour + 51*time.Minute + 58*time.Second + 123456*time.Microsecond},
		{"time(3)", "'838:51:58.123'", 838*time.Hour + 51*time.Minute + 58*time.Second + 123000*time.Microsecond},
		{"time(2)", "'838:51:58.12'", 838*time.Hour + 51*time.Minute + 58*time.Second + 120000*time.Microsecond},
		{"time(1)", "'838:51:58.1'", 838*time.Hour + 51*time.Minute + 58*time.Second + 100000*time.Microsecond},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s %s", tc.sqlType, tc.val), func(t *testing.T) {
			v := testInsert(t, tc.sqlType, tc.val)
			var equal bool
			switch want := tc.want.(type) {
			case time.Time:
				got, ok := v.(time.Time)
				equal = ok && want.Equal(got)
			case Enum:
				got, ok := v.(Enum)
				equal = ok && want.Val == got.Val
			case Set:
				got, ok := v.(Set)
				equal = ok && want.Val == got.Val
			default:
				equal = reflect.DeepEqual(v, tc.want)
			}
			if !equal {
				t.Logf(" got: %T %v %#v", v, v, v)
				t.Logf("want: %T %v %#v", tc.want, tc.want, tc.want)
				t.Fail()
			}
		})
	}
}

func testInsert(t *testing.T, sqlType, value string) interface{} {
	t.Helper()
	r, err := Dial("tcp", "localhost:3306")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Authenticate("root", "password"); err != nil {
		t.Fatal(err)
	}
	file, pos, err := r.MasterStatus()
	if err != nil {
		t.Fatal(err)
	}
	insertValue(t, sqlType, value)
	if err := r.Seek(0, file, pos); err != nil {
		t.Fatal(err)
	}
	for {
		e, err := r.NextEvent()
		if err != nil {
			t.Fatal(err)
		}
		if !e.Header.EventType.IsWriteRows() {
			continue
		}
		re := e.Data.(RowsEvent)
		if re.TableMap.SchemaName != "binlog" || re.TableMap.TableName != "binlog_table" {
			continue
		}
		vals, _, err := r.NextRow()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		return vals[0]
	}
}

func insertValue(t *testing.T, sqlType, value string) {
	t.Helper()
	db, err := sql.Open("mysql", "root:password@tcp(localhost:3306)/binlog")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`drop table if exists binlog_table`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf(`create table binlog_table(value %s)`, sqlType)); err != nil {
		t.Fatal(err)
	}
	r, err := db.Exec(fmt.Sprintf(`insert into binlog_table values(%s)`, value))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("rowsAffected: got %d, want %d", got, 1)
	}
}

package binlog

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

func TestReader_LessThanMaxPacketSize(t *testing.T) {
	first, firstPayload := newPacket(10, 0)
	last, _ := newPacket(0, 1)
	var seq uint8
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), &seq)
	got, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, firstPayload) {
		t.Log(" got: ", got)
		t.Log("want: ", firstPayload)
		t.Fatal("payload did not match")
	}
}

func TestReader_EqualToMaxPayloadSize(t *testing.T) {
	first, firstPayload := newPacket(maxPacketSize, 0)
	last, _ := newPacket(0, 1)
	var seq uint8
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), &seq)
	got, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, firstPayload) {
		t.Fatal("payload did not match")
	}
}

func TestReader_MultipleOfMaxPayloadSize(t *testing.T) {
	first, firstPayload := newPacket(maxPacketSize, 0)
	second, secondPayload := newPacket(maxPacketSize, 1)
	last, _ := newPacket(0, 2)
	var seq uint8
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), &seq)
	got, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:maxPacketSize], firstPayload) {
		t.Fatal("first payload did not match")
	}
	if !bytes.Equal(got[maxPacketSize:], secondPayload) {
		t.Fatal("second payload did not match")
	}
}

func TestReader_NotMultipleOfMaxPayloadSize(t *testing.T) {
	first, firstPayload := newPacket(maxPacketSize, 0)
	second, secondPayload := newPacket(maxPacketSize, 1)
	third, thirdPayload := newPacket(10, 2)
	last, _ := newPacket(0, 3)
	var seq uint8
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
		bytes.NewReader(third),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), &seq)
	got, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:maxPacketSize], firstPayload) {
		t.Fatal("first payload did not match")
	}
	if !bytes.Equal(got[maxPacketSize:2*maxPacketSize], secondPayload) {
		t.Fatal("second payload did not match")
	}
	if !bytes.Equal(got[2*maxPacketSize:], thirdPayload) {
		t.Fatal("third payload did not match")
	}
}

func TestReader_stringNull(t *testing.T) {
	data := append([]byte("hello"), 0)
	data = append(append(data, []byte("world")...), 0)
	packet := newPacketData(data)
	var seq uint8
	r := newReader(bytes.NewReader(packet), &seq)

	s := r.stringNull()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if s != "hello" {
		t.Fatal("got", s, "want", "hello")
	}

	s = r.stringNull()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if s != "world" {
		t.Fatal("got", s, "want", "world")
	}
}

func TestUsage(t *testing.T) {
	conn, err := Dial("tcp", "localhost:3306")
	if err != nil {
		t.Fatal(err)
	}
	if conn.IsSSLSupported() {
		t.Log("using ssl...")
		if err = conn.UpgradeSSL(); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Authenticate("root", "password"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Seek(10, "binlog.000002", 4); err != nil {
		t.Fatal(err)
	}
	for {
		t.Log("-------------------------")
		e, err := conn.NextEvent()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", e.Header)
		t.Logf("%#v", e.Data)
		if _, ok := e.Data.(RowsEvent); ok {
			for {
				row, before, err := conn.NextRow()
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				t.Log("        ", row, "        ", before)
			}
		}
	}
}

func TestDump(t *testing.T) {
	conn, err := Dial("tcp", "localhost:3306")
	if err != nil {
		t.Fatal(err)
	}
	if conn.IsSSLSupported() {
		t.Log("using ssl...")
		if err = conn.UpgradeSSL(); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Authenticate("root", "password"); err != nil {
		t.Fatal(err)
	}
	if err := conn.confirmChecksumSupport(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Seek(10, "binlog.000001", 4); err != nil {
		t.Fatal(err)
	}
	if err := conn.Dump("/Users/santhosh/go/src/binlog/Dump"); err != nil {
		t.Fatal(err)
	}
}

func TestFileUsage(t *testing.T) {
	conn, err := Open("/Users/santhosh/go/src/binlog/Dump/binlog.000002")
	if err != nil {
		t.Fatal(err)
	}
	for {
		t.Log("-------------------------")
		e, err := conn.NextEvent()
		if err != nil {
			t.Fatal(err)
		}
		t.Log(conn.binlogFile, conn.binlogReader.binlogPos)
		t.Logf("%#v", e)
		if _, ok := e.Data.(RowsEvent); ok {
			for {
				row, before, err := conn.NextRow()
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				t.Log("        ", row, "        ", before)
			}
		}
	}
}

// Helpers ---

func newPacket(size int, seq byte) (packet, payload []byte) {
	b := make([]byte, headerSize+maxPacketSize)
	b[0] = byte(size)
	b[1] = byte(size >> 8)
	b[2] = byte(size >> 16)
	b[3] = seq
	// payload markers
	b[4] = 2*seq + 1
	b[len(b)-1] = 2*seq + 2
	return b, b[4 : 4+size]
}

func newPacketData(data []byte) []byte {
	b := make([]byte, headerSize+len(data)+headerSize)
	b[0] = byte(len(data))
	b[1] = byte(len(data) >> 8)
	b[2] = byte(len(data) >> 16)
	b[3] = 0
	copy(b[4:], data)
	b[headerSize+len(data)+headerSize-1] = 1
	return b
}

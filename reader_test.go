package binlog

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"testing"
)

func TestReader_LessThanMaxPacketSize(t *testing.T) {
	first, firstPayload := newPacket(10, 0)
	last, _ := newPacket(0, 1)
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	))
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
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	))
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
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	))
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
	r := newReader(io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
		bytes.NewReader(third),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	))
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
	r := newReader(bytes.NewReader(packet))

	s, err := r.stringNull()
	if err != nil {
		t.Fatal(err)
	}
	if s != "hello" {
		t.Fatal("got", s, "want", "hello")
	}

	s, err = r.stringNull()
	if err != nil {
		t.Fatal(err)
	}
	if s != "world" {
		t.Fatal("got", s, "want", "world")
	}
}

func TestHandshakeV10(t *testing.T) {
	conn, err := net.Dial("tcp", "localhost:3306")
	if err != nil {
		t.Fatal(err)
	}
	r := newReader(conn)
	hs := handshakeV10{}
	if err = hs.parse(r); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", hs)

	w := newWriter(conn)
	w.seq = r.seq
	resp := handshakeResponse41{
		capabilityFlags: CLIENT_LONG_FLAG | CLIENT_SECURE_CONNECTION,
		maxPacketSize:   maxPacketSize,
		characterSet:    hs.characterSet,
		username:        "root",
		authResponse:    encryptedPasswd("password", append(hs.authPluginDataPart1, hs.authPluginDataPart2...)),
		database:        "",
		authPluginName:  "",
		connectAttrs:    nil,
	}
	if err := resp.writeTo(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r = newReader(conn)
	r.seq = w.seq
	marker, err := r.int1()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("marker", marker)
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

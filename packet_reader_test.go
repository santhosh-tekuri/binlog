package binlog

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

func TestPacketReader_LessThanMaxPacketSize(t *testing.T) {
	first, firstPayload := newPacket(10, 0)
	last, _ := newPacket(0, 1)
	var seq uint8
	r := &packetReader{rd: io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), seq: &seq}
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

func TestPacketReader_EqualToMaxPayloadSize(t *testing.T) {
	first, firstPayload := newPacket(maxPacketSize, 0)
	last, _ := newPacket(0, 1)
	var seq uint8
	r := &packetReader{rd: io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), seq: &seq}
	got, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, firstPayload) {
		t.Fatal("payload did not match")
	}
}

func TestPacketReader_MultipleOfMaxPayloadSize(t *testing.T) {
	first, firstPayload := newPacket(maxPacketSize, 0)
	second, secondPayload := newPacket(maxPacketSize, 1)
	last, _ := newPacket(0, 2)
	var seq uint8
	r := &packetReader{rd: io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), seq: &seq}
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

func TestPacketReader_NotMultipleOfMaxPayloadSize(t *testing.T) {
	first, firstPayload := newPacket(maxPacketSize, 0)
	second, secondPayload := newPacket(maxPacketSize, 1)
	third, thirdPayload := newPacket(10, 2)
	last, _ := newPacket(0, 3)
	var seq uint8
	r := &packetReader{rd: io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
		bytes.NewReader(third),
		bytes.NewReader(last),
		bytes.NewReader(make([]byte, 10)),
	), seq: &seq}
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

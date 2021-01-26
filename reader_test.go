package binlog

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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

func TestHandshakeV10(t *testing.T) {
	conn, err := net.Dial("tcp", "localhost:3306")
	if err != nil {
		t.Fatal(err)
	}
	var seq uint8
	r := newReader(conn, &seq)
	hs := handshakeV10{}
	if err = hs.parse(r); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v\n", hs)

	w := newWriter(conn, &seq)
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

	r = newReader(conn, &seq)
	marker, err := r.peek()
	if err != nil {
		t.Fatal(err)
	}
	if marker == errMarker {
		ep := errPacket{}
		if err := ep.parse(r); err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", ep)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	seq = 0
	w = newWriter(conn, &seq)
	w.query("set @master_binlog_checksum = @@global.binlog_checksum")
	r = newReader(conn, &seq)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	seq = 0
	w = newWriter(conn, &seq)
	dump := comBinlogDump{
		binlogPos:      4,
		flags:          0,
		serverID:       10,
		binlogFilename: "binlog.000002",
	}
	if err := dump.writeTo(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var fde formatDescriptionEvent
	var tme tableMapEvent
	for {
		t.Log("------------------------", seq)
		r = newReader(conn, &seq)
		r.checksum = 4

		b, err := r.peek()
		if err != nil {
			t.Fatal(err)
		}
		switch b {
		case okMarker:
			r.int1()
		case errMarker:
			ep := errPacket{}
			if err := ep.parse(r); err != nil {
				t.Fatal(err)
			}
			t.Logf("%#v", ep)
			fallthrough
		default:
			t.Fatalf("binlogStream: got %0x want OK-byte", b)
		}

		h := binaryEventHeader{}
		if err := h.parse(r); err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", h)
		switch h.eventType {
		case FORMAT_DESCRIPTION_EVENT:
			fde = formatDescriptionEvent{}
			if err := fde.parse(r); err != nil {
				t.Fatal(err)
			}
			t.Logf("%#v", fde)
		case ROTATE_EVENT:
			re := rotateEvent{}
			if err := re.parse(r); err != nil {
				t.Fatal(err)
			}
			t.Logf("%#v", re)
		case TABLE_MAP_EVENT:
			tme = tableMapEvent{}
			if err := tme.parse(r); err != nil {
				t.Fatal(err)
			}
			t.Logf("%#v", tme)
		case WRITE_ROWS_EVENTv0, WRITE_ROWS_EVENTv1, WRITE_ROWS_EVENTv2,
			UPDATE_ROWS_EVENTv0, UPDATE_ROWS_EVENTv1, UPDATE_ROWS_EVENTv2,
			DELETE_ROWS_EVENTv0, DELETE_ROWS_EVENTv1, DELETE_ROWS_EVENTv2:
			re := rowsEvent{}
			if err := re.parse(r, &fde, h.eventType, &tme); err != nil {
				t.Fatal(err)
			}
			t.Logf("%#v", re)
			for {
				row, err := re.nextRow(r)
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				fmt.Println("        ", row)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(h.eventType, err)
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

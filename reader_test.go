package binlog

import (
	"bytes"
	"io"
	"testing"
)

func TestReader_stringNull(t *testing.T) {
	data := []byte("hello world\x00hello binlog\x00hello")
	r := &reader{rd: bytes.NewReader(data), limit: -1}

	s := r.stringNull()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if s != "hello world" {
		t.Fatal("got", s, "want", "hello world")
	}

	s = r.stringNull()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if s != "hello binlog" {
		t.Fatal("got", s, "want", "hello binlog")
	}

	r.stringNull()
	if r.err != io.ErrUnexpectedEOF {
		t.Fatal("got", r.err, "want", io.ErrUnexpectedEOF)
	}
}

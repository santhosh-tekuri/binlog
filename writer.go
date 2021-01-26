package binlog

import (
	"io"
)

type writer struct {
	wd  io.Writer
	buf []byte
	seq *uint8
	err error
}

func newWriter(w io.Writer, seq *uint8) *writer {
	return &writer{
		wd:  w,
		buf: make([]byte, 4, headerSize+maxPacketSize),
		seq: seq,
	}
}

func (w *writer) flush() error {
	if w.err != nil {
		return w.err
	}
	for len(w.buf) >= headerSize+maxPacketSize {
		w.buf[0], w.buf[1], w.buf[2], w.buf[3] = 0xff, 0xff, 0xff, *w.seq
		*w.seq++
		if _, w.err = w.wd.Write(w.buf[:headerSize+maxPacketSize]); w.err != nil {
			return w.err
		}
		copy(w.buf[4:], w.buf[headerSize+maxPacketSize:])
		w.buf = w.buf[0 : headerSize+len(w.buf)-(headerSize+maxPacketSize)]
	}
	return nil
}

func (w *writer) Close() error {
	if err := w.flush(); err != nil {
		return err
	}
	payload := len(w.buf) - headerSize
	w.buf[0], w.buf[1], w.buf[2], w.buf[3] = byte(payload), byte(payload>>8), byte(payload>>16), *w.seq
	*w.seq++
	_, err := w.wd.Write(w.buf)
	return err
}

func (w *writer) Write(b []byte) (n int, err error) {
	for {
		if err := w.flush(); err != nil {
			return 0, err
		}
		available := headerSize + maxPacketSize - len(w.buf)
		if len(b) < available {
			available = len(b)
		}
		w.buf = append(w.buf, b[:available]...)
		n += available
		b = b[available:]
		if len(b) == 0 {
			return n, nil
		}
	}
}

func (w *writer) int1(v uint8) error {
	_, err := w.Write([]byte{v})
	return err
}

func (w *writer) int2(v uint16) error {
	_, err := w.Write([]byte{byte(v), byte(v >> 8)})
	return err
}

func (w *writer) int4(v uint32) error {
	_, err := w.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	return err
}

// https://dev.mysql.com/doc/internals/en/integer.html#length-encoded-integer
func (w *writer) intN(v uint64) error {
	var b []byte
	switch {
	case v < 251:
		b = []byte{byte(v)}
	case v < 1<<16:
		b = []byte{0xFC, byte(v), byte(v >> 8)}
	case v < 1<<24:
		b = []byte{0xFD, byte(v), byte(v >> 8), byte(v >> 16)}
	default:
		b = []byte{0xFE, byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	}
	_, err := w.Write(b)
	return err
}

func (w *writer) string(v string) error {
	_, err := w.Write([]byte(v))
	return err
}

func (w *writer) stringNull(v string) error {
	if _, err := w.Write([]byte(v)); err != nil {
		return err
	}
	return w.int1(0)
}

func (w *writer) bytesNull(v []byte) error {
	if _, err := w.Write(v); err != nil {
		return err
	}
	return w.int1(0)
}

func (w *writer) string1(v string) error {
	if err := w.int1(uint8(len(v))); err != nil {
		return err
	}
	_, err := w.Write([]byte(v))
	return err
}

func (w *writer) stringN(v string) error {
	if err := w.intN(uint64(len(v))); err != nil {
		return err
	}
	_, err := w.Write([]byte(v))
	return err
}

func (w *writer) bytes1(v []byte) error {
	if err := w.int1(uint8(len(v))); err != nil {
		return err
	}
	_, err := w.Write(v)
	return err
}

func (w *writer) bytesN(v []byte) error {
	if err := w.intN(uint64(len(v))); err != nil {
		return err
	}
	_, err := w.Write(v)
	return err
}

const COM_QUERY = 0x03

func (w *writer) query(q string) error {
	w.int1(COM_QUERY)
	w.string(q)
	return w.Close()
}

package binlog

import (
	"bytes"
	"io"
)

const (
	headerSize    = 4
	maxPacketSize = 1<<24 - 1
)

func newReader(r io.Reader, seq *uint8) *reader {
	return &reader{
		rd:       &packetReader{rd: r, seq: seq},
		tmeCache: make(map[uint64]*TableMapEvent),
		limit:    -1,
	}
}

type reader struct {
	rd    io.Reader
	err   error
	buf   []byte // contents are the bytes buf[off:]
	off   int    // read at &buf[off], write at &buf[len(buf)]
	limit int

	// context for unmarshallers
	binlogFile string
	binlogPos  uint32
	fde        FormatDescriptionEvent
	tmeCache   map[uint64]*TableMapEvent
	tme        *TableMapEvent
	re         RowsEvent
}

func (r *reader) Read(p []byte) (int, error) {
	if len(r.buffer()) == 0 {
		if err := r.readMore(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buffer())
	r.skip(n)
	return n, nil
}

func (r *reader) readMore() error {
	if r.err != nil {
		return r.err
	}
	if r.limit >= 0 && len(r.buf)-r.off >= r.limit {
		return io.EOF
	}
	if len(r.buf) == cap(r.buf) {
		if r.off > 0 {
			copy(r.buf, r.buf[r.off:])
			r.buf = r.buf[0 : len(r.buf)-r.off]
			r.off = 0
		} else {
			buf := make([]byte, cap(r.buf)+1<<20)
			copy(buf, r.buf[r.off:])
			r.buf = buf[:len(r.buf)-r.off]
			r.off = 0
		}
	}
	n, err := r.rd.Read(r.buf[len(r.buf):cap(r.buf)])
	r.buf = r.buf[:len(r.buf)+n]
	if err == io.EOF {
		return io.EOF
	}
	r.err = err
	return r.err
}

func (r *reader) buffer() []byte {
	buf := r.buf[r.off:]
	if r.limit >= 0 && len(buf) > r.limit {
		return buf[:r.limit]
	}
	return buf
}

func (r *reader) ensure(n int) error {
	if r.limit >= 0 && n > r.limit {
		r.err = io.ErrUnexpectedEOF
		return r.err
	}
	for r.err == nil && n > len(r.buffer()) {
		if r.readMore() == io.EOF {
			r.err = io.ErrUnexpectedEOF
			break
		}
	}
	return r.err
}

func (r *reader) peek() (byte, error) {
	if err := r.ensure(1); err != nil {
		return 0, err
	}
	return r.buffer()[0], nil
}

func (r *reader) skip(n int) error {
	if r.err != nil {
		return r.err
	}
	if r.limit >= 0 && n > r.limit {
		r.err = io.ErrUnexpectedEOF
		return r.err
	}
	for n > 0 {
		if len(r.buffer()) == 0 {
			if r.readMore() == io.EOF {
				r.err = io.ErrUnexpectedEOF
			}
			if r.err != nil {
				return r.err
			}
		}
		m := n
		if m > len(r.buffer()) {
			m = len(r.buffer())
		}
		r.off += m
		n -= m
		if r.limit >= 0 {
			r.limit -= m
		}
	}
	return nil
}

func (r *reader) drain() error {
	if r.err == io.ErrUnexpectedEOF {
		r.err = nil
	}
	for r.err == nil {
		r.skip(len(r.buffer()))
		if r.readMore() == io.EOF {
			return nil
		}
	}
	return r.err
}

func (r *reader) more() bool {
	if r.err != nil {
		return false
	}
	if len(r.buffer()) > 0 || r.limit > 0 {
		return true
	}

	return r.readMore() == nil
}

// int ---

func (r *reader) int1() byte {
	if err := r.ensure(1); err != nil {
		return 0
	}
	v := r.buffer()[0]
	r.skip(1)
	return v
}

func (r *reader) int2() uint16 {
	if err := r.ensure(2); err != nil {
		return 0
	}
	buf := r.buffer()
	v := uint16(buf[0]) | uint16(buf[1])<<8
	r.skip(2)
	return v
}

func (r *reader) int3() uint32 {
	if err := r.ensure(3); err != nil {
		return 0
	}
	buf := r.buffer()
	v := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16
	r.skip(3)
	return v
}

func (r *reader) int4() uint32 {
	if err := r.ensure(4); err != nil {
		return 0
	}
	buf := r.buffer()
	v := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	r.skip(4)
	return v
}

func (r *reader) int6() uint64 {
	if err := r.ensure(6); err != nil {
		return 0
	}
	buf := r.buffer()
	v := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 |
		uint64(buf[3])<<24 | uint64(buf[4])<<32 | uint64(buf[5])<<40
	r.skip(6)
	return v
}

func (r *reader) int8() uint64 {
	if err := r.ensure(8); err != nil {
		return 0
	}
	buf := r.buffer()
	v := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
	r.skip(8)
	return v
}

func (r *reader) intFixed(n int) uint64 {
	if err := r.ensure(n); err != nil {
		return 0
	}
	buf := r.buffer()[:n]
	var v uint64
	for i, b := range buf {
		v |= uint64(b) << (uint(i) * 8)
	}
	r.skip(n)
	return v
}

func (r *reader) intN() uint64 {
	b := r.int1()
	if r.err != nil {
		return 0
	}
	switch b {
	case 0xfc:
		return uint64(r.int2())
	case 0xfd:
		return uint64(r.int3())
	case 0xfe:
		return r.int8()
	default:
		return uint64(b)
	}
}

// bytes, strings ---

func (r *reader) bytesInternal(len int) []byte {
	if err := r.ensure(len); err != nil {
		return nil
	}
	v := r.buffer()[:len]
	r.skip(len)
	return v
}

func (r *reader) bytes(len int) []byte {
	return append([]byte(nil), r.bytesInternal(len)...)
}

func (r *reader) string(len int) string {
	return string(r.bytesInternal(len))
}

// todo: unit test loop more than one iter
func (r *reader) bytesNullInternal() []byte {
	if r.err != nil {
		return nil
	}
	i := 0
	for {
		if i == len(r.buffer()) {
			if r.readMore() != nil {
				return nil
			}
		}
		j := bytes.IndexByte(r.buffer()[i:], 0)
		if j != -1 {
			v := r.buffer()[:i+j]
			r.skip(i + j + 1)
			return v
		}
		i = len(r.buffer())
	}
}

func (r *reader) bytesNull() []byte {
	return append([]byte(nil), r.bytesNullInternal()...)
}

func (r *reader) stringNull() string {
	return string(r.bytesNullInternal())
}

func (r *reader) bytesEOFInternal() []byte {
	for {
		if r.err != nil {
			return nil
		}
		if r.readMore() == io.EOF {
			v := r.buffer()
			r.skip(len(v))
			return v
		}
	}
}

func (r *reader) bytesEOF() []byte {
	return append([]byte(nil), r.bytesEOFInternal()...)
}

func (r *reader) stringEOF() string {
	return string(r.bytesEOFInternal())
}

func (r *reader) stringN() string {
	l := r.intN()
	if r.err != nil {
		return ""
	}
	return r.string(int(l))
}

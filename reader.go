package binlog

import (
	"io"
)

const (
	headerSize    = 4
	maxPacketSize = 1<<24 - 1
)

type reader struct {
	rd       io.Reader
	buf      []byte
	r, w     int
	payload  int    // payload to be read, initially 0
	seq      *uint8 // sequence of packet
	last     bool   // is last packet
	header   []byte
	checksum int
	ww       int
}

func newReader(r io.Reader, seq *uint8) *reader {
	return &reader{
		rd:     r,
		buf:    make([]byte, headerSize+maxPacketSize),
		header: make([]byte, headerSize),
		seq:    seq,
	}
}

func (r *reader) readHeader() (int, error) {
	n, err := io.ReadAtLeast(r.rd, r.header, headerSize)
	if n < headerSize {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n, err
	}
	r.payload = int(uint32(r.header[0]) | uint32(r.header[1])<<8 | uint32(r.header[2])<<16)
	*r.seq = r.header[3] + 1
	if r.payload < maxPacketSize {
		r.last = true
	}
	return n, err
}

func (r *reader) fill() error {
	if r.checksum > 0 {
		r.w = r.ww
		defer func() {
			r.ww = r.w
			r.w -= r.checksum
			if r.w < r.r {
				r.w = r.r
			}
		}()
	}
	if r.payload == 0 {
		if r.last {
			return io.EOF
		}
		// Slide existing data to beginning.
		if r.r > 0 {
			copy(r.buf, r.buf[r.r:r.w])
			r.w -= r.r
			r.r = 0
		}
		// Not enough space anywhere, we need to allocate.
		if r.w == len(r.buf) {
			buf := makeSlice(len(r.buf) + 1<<20)
			copy(buf, r.buf[r.r:r.w])
			r.buf = buf
		}
		// Read header.
		n, err := r.readHeader()
		if n < headerSize {
			return err
		}
	}
	if r.payload == 0 && r.last {
		return io.EOF
	}
	available := len(r.buf) - r.w
	if available > r.payload {
		available = r.payload
	}
	n, err := r.rd.Read(r.buf[r.w : r.w+available])
	r.payload -= n
	r.w += n
	if n == 0 && err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func (r *reader) more() (bool, error) {
	if r.w-r.r > 0 || r.payload > 0 {
		return true, nil
	}
	err := r.fill()
	if err == io.EOF {
		return false, nil
	}
	return true, err
}

func (r *reader) ensure(n int) error {
	for n > r.w-r.r {
		if err := r.fill(); err != nil {
			return err
		}
	}
	return nil
}

func (r *reader) peek() (byte, error) {
	if err := r.ensure(1); err != nil {
		return 0, err
	}
	return r.buf[r.r], nil
}

func (r *reader) Read(p []byte) (int, error) {
	if err := r.ensure(1); err != nil {
		return 0, err
	}
	n := copy(p, r.buf[r.r:r.w])
	r.r += n
	return n, nil
}

func (r *reader) int1() (byte, error) {
	if err := r.ensure(1); err != nil {
		return 0, err
	}
	b := r.buf[r.r]
	r.r++
	return b, nil
}

func (r *reader) int2() (uint16, error) {
	if err := r.ensure(2); err != nil {
		return 0, err
	}
	buf := r.buf[r.r:]
	r.r += 2
	return uint16(buf[0]) | uint16(buf[1])<<8, nil
}

func (r *reader) int3() (int, error) {
	if err := r.ensure(3); err != nil {
		return 0, err
	}
	buf := r.buf[r.r:]
	r.r += 3
	return int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16), nil
}

func (r *reader) int4() (uint32, error) {
	if err := r.ensure(4); err != nil {
		return 0, err
	}
	buf := r.buf[r.r:]
	r.r += 4
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24, nil
}

func (r *reader) int8() (uint64, error) {
	if err := r.ensure(8); err != nil {
		return 0, err
	}
	buf := r.buf[r.r:]
	r.r += 8
	return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56, nil
}

func (r *reader) bytes(len int) ([]byte, error) {
	if err := r.ensure(len); err != nil {
		return nil, err
	}
	buf := r.buf[r.r : r.r+len]
	r.r += len
	return append([]byte(nil), buf...), nil
}

func (r *reader) string(len int) (string, error) {
	if err := r.ensure(len); err != nil {
		return "", err
	}
	buf := r.buf[r.r : r.r+len]
	r.r += len
	return string(buf), nil
}

func (r *reader) skip(n int) error {
	if err := r.ensure(n); err != nil {
		return err
	}
	r.r += n
	return nil
}

func (r *reader) bytesNull() ([]byte, error) {
	i := 0
	for {
		if r.r+i >= r.w {
			if err := r.fill(); err != nil {
				return nil, err
			}
		}
		if r.buf[r.r+i] == 0 {
			v := append([]byte(nil), r.buf[r.r:r.r+i]...)
			r.r += i + 1
			return v, nil
		}
		i++
	}
}

func (r *reader) stringNull() (string, error) {
	i := 0
	for {
		if r.r+i >= r.w {
			if err := r.fill(); err != nil {
				return "", err
			}
		}
		if r.buf[r.r+i] == 0 {
			s := string(r.buf[r.r : r.r+i])
			r.r += i + 1
			return s, nil
		}
		i++
	}
}

func (r *reader) stringEOF() (string, error) {
	for {
		err := r.fill()
		if err == io.EOF {
			v := string(r.buf[r.r:r.w])
			r.r = r.w
			return v, nil
		}
		if err != nil {
			return "", err
		}
	}
}

func (r *reader) Close() error {
	for {
		r.r = r.w
		err := r.fill()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func makeSlice(n int) []byte {
	// If the make fails, give a known error.
	defer func() {
		if recover() != nil {
			panic("binlog.reader: too large")
		}
	}()
	return make([]byte, n)
}

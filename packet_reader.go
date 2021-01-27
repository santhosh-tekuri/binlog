package binlog

import (
	"io"
)

type packetReader struct {
	rd   io.Reader
	seq  *uint8
	last bool
	size int
}

func (r *packetReader) Read(p []byte) (int, error) {
	if r.size == 0 {
		if r.last {
			return 0, io.EOF
		}
		h := make([]byte, headerSize)
		_, err := io.ReadFull(r.rd, h)
		if err != nil {
			if err == io.EOF {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		r.size = int(uint32(h[0]) | uint32(h[1])<<8 | uint32(h[2])<<16)
		*r.seq = h[3] + 1
		if r.size < maxPacketSize {
			r.last = true
			if r.size == 0 {
				return 0, io.EOF
			}
		}
	}
	n, err := io.LimitReader(r.rd, int64(r.size)).Read(p)
	r.size -= n
	if n > 0 {
		return n, nil
	}
	if err == io.EOF {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, err
}

func (r *packetReader) reset() {
	r.last = false
	r.size = 0
}

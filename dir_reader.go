package binlog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type dirReader struct {
	file     *os.File
	name     *string
	tmeCache map[uint64]*tableMapEvent
}

func newDirReader(dir string, file *string) (*dirReader, error) {
	if _, err := nextBinlogFile(path.Join(dir, *file)); err != nil {
		return nil, err
	}
	f, err := openBinlogFile(path.Join(dir, *file))
	if err != nil {
		return nil, err
	}
	return &dirReader{f, file, make(map[uint64]*tableMapEvent)}, nil
}

func (r *dirReader) Read(p []byte) (int, error) {
	for {
		n, err := r.file.Read(p)
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		if err == nil {
			return n, nil
		}
		if err != io.EOF {
			panic("bug")
		}
		next, err := nextBinlogFile(r.file.Name())
		if _, err := os.Stat(next); err == nil {
			f, err := openBinlogFile(next)
			if err != nil {
				return 0, err
			}
			_ = r.file.Close()
			r.file = f
			*r.name = path.Base(next)
			for k, _ := range r.tmeCache {
				delete(r.tmeCache, k)
			}
			fmt.Println("*********************", next)
		} else if os.IsNotExist(err) {
			time.Sleep(time.Second)
		} else {
			return 0, err
		}
	}
}

func openBinlogFile(file string) (*os.File, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	_, err = io.ReadAtLeast(f, header, len(header))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header, []byte{0xfe, 'b', 'i', 'n'}) {
		return nil, fmt.Errorf("binlog.Open: %s has invalid fileheader", file)
	}
	return f, nil
}

func nextBinlogFile(name string) (string, error) {
	dot := strings.LastIndexByte(name, '.')
	if dot == -1 {
		return "", errors.New("no dot in Dir")
	}
	suffix := name[dot+1:]
	for len(suffix) > 1 && suffix[0] == '0' {
		suffix = suffix[1:]
	}
	i, err := strconv.Atoi(suffix)
	if err != nil {
		return "", errors.New("invalid Dir suffix")
	}
	return fmt.Sprintf("%s%06d", name[:dot+1], i+1), nil
}

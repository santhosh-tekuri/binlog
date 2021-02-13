package binlog

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
)

var fileHeader = []byte{0xfe, 'b', 'i', 'n'}

type dirReader struct {
	file     *os.File
	name     *string
	nonBlock bool
	tmeCache map[uint64]*TableMapEvent
}

func newDirReader(dir string, file *string, pos uint32, nonBlock bool) (*dirReader, error) {
	f, err := openBinlogFile(path.Join(dir, *file))
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(int64(pos), io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &dirReader{f, file, nonBlock, make(map[uint64]*TableMapEvent)}, nil
}

func (r *dirReader) Read(p []byte) (int, error) {
	delay := time.Second
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

		// Check for next file.
		next, err := nextBinlogFile(r.file.Name())
		if err != nil {
			return 0, err
		}
		if next == "" {
			if r.nonBlock {
				return 0, io.EOF
			}
			time.Sleep(delay)
			continue
		}
		if _, err = os.Stat(next); err != nil {
			if os.IsNotExist(err) {
				if r.nonBlock {
					return 0, io.EOF
				}
				time.Sleep(delay)
				continue
			} else {
				return 0, err
			}
		}

		// Switch to next file.
		f, err := openBinlogFile(next)
		if err != nil {
			return 0, err
		}
		_ = r.file.Close()
		r.file = f
		*r.name = path.Base(next)
		for k := range r.tmeCache {
			delete(r.tmeCache, k)
		}
		fmt.Println("*********************", next)
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
	if !bytes.Equal(header, fileHeader) {
		return nil, fmt.Errorf("binlog.Open: %s has invalid fileheader", file)
	}
	return f, nil
}

func nextBinlogFile(name string) (string, error) {
	dir, file := path.Split(name)
	f, err := os.Open(path.Join(dir, file+".next"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	buff, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}
	return path.Join(dir, strings.TrimSpace(string(buff))), nil
}

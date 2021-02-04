package binlog

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"time"
)

var fileHeader = []byte{0xfe, 'b', 'i', 'n'}

type dirReader struct {
	file     *os.File
	name     *string
	tmeCache map[uint64]*TableMapEvent
}

func newDirReader(dir string, file *string) (*dirReader, error) {
	if _, err := nextBinlogFile(path.Join(dir, *file)); err != nil {
		return nil, err
	}
	f, err := openBinlogFile(path.Join(dir, *file))
	if err != nil {
		return nil, err
	}
	return &dirReader{f, file, make(map[uint64]*TableMapEvent)}, nil
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
			time.Sleep(delay)
			continue
		}
		if _, err = os.Stat(next); err != nil {
			if os.IsNotExist(err) {
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
	index, err := os.Open(path.Join(dir, "binlog.index"))
	if err != nil {
		return "", err
	}
	defer index.Close()
	r := bufio.NewScanner(index)
	var text string
	for r.Scan() {
		if text == file {
			return path.Join(dir, r.Text()), nil
		}
		text = r.Text()
	}
	return "", nil
}

package binlog

import (
	"errors"
	"strconv"
	"strings"
)

type serverVersion []int

func newServerVersion(s string) (serverVersion, error) {
	if i := strings.IndexByte(s, '-'); i != -1 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '+'); i != -1 {
		s = s[:i]
	}
	var sv serverVersion
	for _, v := range strings.Split(s, ".") {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
		sv = append(sv, n)
	}
	if len(sv) != 3 {
		return nil, errors.New("invalid serverVersion: " + s)
	}
	return sv, nil
}

func (sv serverVersion) eq(v serverVersion) bool {
	return sv[0] == v[0] && sv[1] == v[1] && sv[2] == v[2]
}

func (sv serverVersion) lt(v serverVersion) bool {
	for i, _ := range sv {
		if sv[i] < v[i] {
			return true
		}
		if sv[i] == v[i] {
			continue
		}
		return false
	}
	return false
}

// https://dev.mysql.com/doc/internals/en/binlog-version.html

func (sv serverVersion) binlogVersion() uint16 {
	switch {
	case sv.lt([]int{4, 0, 0}):
		return 1
	case sv.lt([]int{4, 0, 2}):
		return 2
	case sv.lt([]int{5, 0, 0}):
		return 3
	default:
		return 4
	}
}

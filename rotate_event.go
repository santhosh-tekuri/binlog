package binlog

import (
	"strings"
)

// https://dev.mysql.com/doc/internals/en/format-description-event.html

type FormatDescriptionEvent struct {
	BinlogVersion          uint16
	ServerVersion          string
	CreateTimestamp        uint32
	EventHeaderLength      uint8
	EventTypeHeaderLengths []byte
}

func (e *FormatDescriptionEvent) parse(r *reader) error {
	e.BinlogVersion = r.int2()
	e.ServerVersion = r.string(50)
	if i := strings.IndexByte(e.ServerVersion, 0); i != -1 {
		e.ServerVersion = e.ServerVersion[:i]
	}
	e.CreateTimestamp = r.int4()
	e.EventHeaderLength = r.int1()
	e.EventTypeHeaderLengths = r.bytesEOF()
	return r.err
}

func (e *FormatDescriptionEvent) postHeaderLength(typ EventType, def int) int {
	if len(e.EventTypeHeaderLengths) >= int(typ) {
		return int(e.EventTypeHeaderLengths[typ])
	}
	return def
}

// https://dev.mysql.com/doc/internals/en/rotate-event.html

type RotateEvent struct {
	Position   uint64
	NextBinlog string
}

func (e *RotateEvent) parse(r *reader) error {
	if r.fde.BinlogVersion > 1 {
		e.Position = r.int8()
	}
	e.NextBinlog = r.stringEOF()
	return r.err
}

// https://dev.mysql.com/doc/internals/en/stop-event.html

type stopEvent struct{}
type previousGTIDsEvent struct{}
type anonymousGTIDEvent struct{}
type queryEvent struct{}
type xidEvent struct{}
type gtidEvent struct{}
type unknownEvent struct{}
type intVarEvent struct{}
type loadEvent struct{}
type slaveEvent struct{}
type createFileEvent struct{}
type deleteFileEvent struct{}
type beginLoadQueryEvent struct{}
type executeLoadQueryEvent struct{}
type randEvent struct{}
type userVarEvent struct{}
type newLoadEvent struct{}
type execLoadEvent struct{}
type appendBlockEvent struct{}
type incidentEvent struct{}
type heartbeatEvent struct{}
type ignorableEvent struct{}

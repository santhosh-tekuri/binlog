package binlog

import (
	"strings"
)

// https://dev.mysql.com/doc/internals/en/format-description-event.html

type formatDescriptionEvent struct {
	binlogVersion          uint16
	serverVersion          string
	createTimestamp        uint32
	eventHeaderLength      uint8
	eventTypeHeaderLengths []byte
}

func (e *formatDescriptionEvent) parse(r *reader) error {
	e.binlogVersion = r.int2()
	e.serverVersion = r.string(50)
	if i := strings.IndexByte(e.serverVersion, 0); i != -1 {
		e.serverVersion = e.serverVersion[:i]
	}
	e.createTimestamp = r.int4()
	e.eventHeaderLength = r.int1()
	e.eventTypeHeaderLengths = r.bytesEOF()
	return r.err
}

func (e *formatDescriptionEvent) postHeaderLength(typ EventType, def int) int {
	if len(e.eventTypeHeaderLengths) >= int(typ) {
		return int(e.eventTypeHeaderLengths[typ])
	}
	return def
}

// https://dev.mysql.com/doc/internals/en/rotate-event.html

type rotateEvent struct {
	position   uint64
	nextBinlog string
}

func (e *rotateEvent) parse(r *reader) error {
	if r.fde.binlogVersion > 1 {
		e.position = r.int8()
	}
	e.nextBinlog = r.stringEOF()
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

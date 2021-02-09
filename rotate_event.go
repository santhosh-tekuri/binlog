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

type QueryEvent struct {
	SlaveProxyID  uint32
	ExecutionTIme uint32
	ErrorCode     uint16
	StatusVars    []byte
	Schema        string
	Query         string
}

func (e *QueryEvent) parse(r *reader) error {
	e.SlaveProxyID = r.int4()
	e.ExecutionTIme = r.int4()
	schemaLen := r.int1()
	if r.err != nil {
		return r.err
	}
	e.ErrorCode = r.int2()
	statusVarsLen := r.int2()
	if r.err != nil {
		return r.err
	}
	e.StatusVars = r.bytes(int(statusVarsLen))
	e.Schema = r.string(int(schemaLen))
	r.skip(1)
	e.Query = r.stringEOF()
	return r.err
}

// https://dev.mysql.com/doc/internals/en/incident-event.html

type IncidentEvent struct {
	Type    uint16
	Message string
}

func (e *IncidentEvent) parse(r *reader) error {
	e.Type = r.int2()
	size := r.int1()
	e.Message = r.string(int(size))
	return r.err
}

// RandEvent captures internal state of the RAND() function.
//
// https://dev.mysql.com/doc/internals/en/rand-event.html
type RandEvent struct {
	Seed1 uint64
	Seed2 uint64
}

func (e *RandEvent) parse(r *reader) error {
	e.Seed1 = r.int8()
	e.Seed2 = r.int8()
	return r.err
}

// https://dev.mysql.com/doc/internals/en/stop-event.html

type stopEvent struct{}
type previousGTIDsEvent struct{}
type anonymousGTIDEvent struct{}
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
type userVarEvent struct{}
type newLoadEvent struct{}
type execLoadEvent struct{}
type appendBlockEvent struct{}
type heartbeatEvent struct{}
type ignorableEvent struct{}

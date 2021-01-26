package binlog

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
	e.createTimestamp = r.int4()
	e.eventHeaderLength = r.int1()
	e.eventTypeHeaderLengths = r.bytesEOF()
	return r.err
}

func (e *formatDescriptionEvent) postHeaderLength(typ uint8, def int) int {
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

func (e *rotateEvent) parse(r *reader, fde *formatDescriptionEvent) error {
	if fde.binlogVersion > 1 {
		e.position = r.int8()
	}
	e.nextBinlog = r.stringEOF()
	return r.err
}

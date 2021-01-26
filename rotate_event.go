package binlog

type rotateEvent struct {
	position   uint64
	nextBinlog string
}

func (e *rotateEvent) parse(r *reader) error {
	e.position = r.int8()
	e.nextBinlog = r.stringEOF()
	return r.err
}

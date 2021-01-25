package binlog

type rotateEvent struct {
	position   uint64
	nextBinlog string
}

func (e *rotateEvent) parse(r *reader) (err error) {
	if e.position, err = r.int8(); err != nil {
		return err
	}
	if e.nextBinlog, err = r.stringEOF(); err != nil {
		return err
	}
	return nil
}

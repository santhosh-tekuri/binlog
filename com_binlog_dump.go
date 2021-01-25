package binlog

const (
	COM_BINLOG_DUMP       = 0x12
	BINLOG_DUMP_NON_BLOCK = 0x01
)

type comBinlogDump struct {
	binlogPos      uint32
	flags          uint16
	serverID       uint32
	binlogFilename string
}

func (e comBinlogDump) writeTo(w *writer) error {
	if err := w.int1(COM_BINLOG_DUMP); err != nil {
		return err
	}
	if err := w.int4(e.binlogPos); err != nil {
		return err
	}
	if err := w.int2(e.flags); err != nil {
		return err
	}
	if err := w.int4(e.serverID); err != nil {
		return err
	}
	if err := w.string(e.binlogFilename); err != nil {
		return err
	}
	return nil
}

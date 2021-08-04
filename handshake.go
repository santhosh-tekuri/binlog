package binlog

// Capability Flags: https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
const (
	capLongPassword               = 0x00000001
	capFoundRows                  = 0x00000002
	capLongFlag                   = 0x00000004
	capConnectWithDB              = 0x00000008
	capNoSchema                   = 0x00000010
	capCompress                   = 0x00000020
	capODBC                       = 0x00000040
	capPluginAuth                 = 0x00080000
	capSSL                        = 0x00000800
	capSecureConnection           = 0x00008000
	capPluginAuthLenencClientData = 0x00200000
	capConnectAttrs               = 0x00100000
	capProtocol41                 = 0x00000200
	capTransactions               = 0x00002000
	capSessionTrack               = 0x00800000
)

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html

type handshake struct {
	// common to v9 and v10
	protocolVersion uint8
	serverVersion   string
	connectionID    uint32
	authPluginData  []byte

	// v10 specific fields
	capabilityFlags uint32
	characterSet    uint8
	statusFlags     uint16
	authPluginName  string
}

func (e *handshake) decode(r *reader) error {
	e.protocolVersion = r.int1()
	e.serverVersion = r.stringNull()
	e.connectionID = r.int4()
	if e.protocolVersion == 9 {
		e.authPluginData = r.bytesNull()
		return r.err
	}

	// v10 ---
	e.authPluginData = r.bytes(8)
	r.skip(1) // filler
	e.capabilityFlags = uint32(r.int2())
	if !r.more() {
		return r.err
	}
	e.characterSet = r.int1()
	e.statusFlags = r.int2()
	e.capabilityFlags |= uint32(r.int2()) << 16
	if r.err != nil {
		return r.err
	}
	var authPluginDataLength uint8
	if e.capabilityFlags&capPluginAuth != 0 {
		authPluginDataLength = r.int1()
	} else {
		r.skip(1)
	}
	r.skip(10) // reserved
	if r.err != nil {
		return r.err
	}
	if e.capabilityFlags&capSecureConnection != 0 {
		if authPluginDataLength > 0 && (13 < authPluginDataLength-8) {
			authPluginDataLength -= 8
		} else {
			authPluginDataLength = 13
		}
		e.authPluginData = append(e.authPluginData, r.bytes(int(authPluginDataLength))...)
	}
	if e.capabilityFlags&capPluginAuth != 0 {
		e.authPluginName = r.stringNull()
	}
	return r.err
}

// sslRequest ---

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest

type sslRequest struct {
	capabilityFlags uint32
	maxPacketSize   uint32
	characterSet    uint8
}

func (e sslRequest) encode(w *writer) error {
	w.int4(e.capabilityFlags | capProtocol41 | capSSL | capPluginAuth)
	w.int4(e.maxPacketSize)
	w.int1(e.characterSet)
	w.Write(make([]byte, 23))
	return w.err
}

// handshakeResponse ---

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse

type handshakeResponse41 struct {
	capabilityFlags uint32
	maxPacketSize   uint32
	characterSet    uint8
	username        string
	authResponse    []byte
	database        string
	authPluginName  string
	connectAttrs    map[string]string
}

func (e handshakeResponse41) encode(w *writer) error {
	capabilities := e.capabilityFlags | capProtocol41
	if e.database != "" {
		capabilities |= capConnectWithDB
	}
	if e.authPluginName != "" {
		capabilities |= capPluginAuth
	}
	if len(e.connectAttrs) > 0 {
		capabilities |= capConnectAttrs
	}

	w.int4(capabilities)
	w.int4(e.maxPacketSize)
	w.int1(e.characterSet)
	w.Write(make([]byte, 23))
	w.stringNull(e.username)
	switch {
	case capabilities&capPluginAuthLenencClientData != 0:
		w.bytesN(e.authResponse)
	case capabilities&capSecureConnection != 0:
		w.bytes1(e.authResponse)
	default:
		w.bytesNull(e.authResponse)
	}
	if capabilities&capConnectWithDB != 0 {
		w.stringNull(e.database)
	}
	if capabilities&capPluginAuth != 0 {
		w.stringNull(e.authPluginName)
	}
	if capabilities&capConnectAttrs != 0 {
		w.intN(uint64(len(e.connectAttrs)))
		for k, v := range e.connectAttrs {
			w.stringN(k)
			w.stringN(v)
		}
	}
	return w.err
}
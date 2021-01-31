package binlog

import "crypto/sha1"

// Capability Flags: https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
const (
	CLIENT_LONG_PASSWORD                  = 0x00000001
	CLIENT_FOUND_ROWS                     = 0x00000002
	CLIENT_LONG_FLAG                      = 0x00000004
	CLIENT_CONNECT_WITH_DB                = 0x00000008
	CLIENT_NO_SCHEMA                      = 0x00000010
	CLIENT_COMPRESS                       = 0x00000020
	CLIENT_ODBC                           = 0x00000040
	CLIENT_PLUGIN_AUTH                    = 0x00080000
	CLIENT_SSL                            = 0x00000800
	CLIENT_SECURE_CONNECTION              = 0x00008000
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
	CLIENT_CONNECT_ATTRS                  = 0x00100000
	CLIENT_PROTOCOL_41                    = 0x00000200
	CLIENT_TRANSACTIONS                   = 0x00002000
	CLIENT_SESSION_TRACK                  = 0x00800000
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

func (e *handshake) parse(r *reader) error {
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
	// todo: guess no if check needed
	if e.capabilityFlags&CLIENT_PLUGIN_AUTH != 0 {
		authPluginDataLength = r.int1()
	} else {
		r.skip(1)
	}
	r.skip(10) // reserved
	if r.err != nil {
		return r.err
	}
	if e.capabilityFlags&CLIENT_SECURE_CONNECTION != 0 {
		if authPluginDataLength > 0 && (13 < authPluginDataLength-8) {
			authPluginDataLength -= 8
		} else {
			authPluginDataLength = 13
		}
		e.authPluginData = append(e.authPluginData, r.bytes(int(authPluginDataLength))...)
	}
	if e.capabilityFlags&CLIENT_PLUGIN_AUTH != 0 {
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

func (e sslRequest) writeTo(w *writer) error {
	w.int4(e.capabilityFlags | CLIENT_PROTOCOL_41 | CLIENT_SSL)
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

func (e handshakeResponse41) writeTo(w *writer) error {
	capabilities := e.capabilityFlags | CLIENT_PROTOCOL_41
	if e.database != "" {
		capabilities |= CLIENT_CONNECT_WITH_DB
	}
	if e.authPluginName != "" {
		capabilities |= CLIENT_PLUGIN_AUTH
	}
	if len(e.connectAttrs) > 0 {
		capabilities |= CLIENT_CONNECT_ATTRS
	}

	w.int4(capabilities)
	w.int4(e.maxPacketSize)
	w.int1(e.characterSet)
	w.Write(make([]byte, 23))
	w.stringNull(e.username)
	switch {
	case capabilities&CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0:
		w.bytesN(e.authResponse)
	case capabilities&CLIENT_SECURE_CONNECTION != 0:
		w.bytes1(e.authResponse)
	default:
		w.bytesNull(e.authResponse)
	}
	if capabilities&CLIENT_CONNECT_WITH_DB != 0 {
		w.stringNull(e.database)
	}
	if capabilities&CLIENT_PLUGIN_AUTH != 0 {
		w.stringNull(e.authPluginName)
	}
	if capabilities&CLIENT_CONNECT_ATTRS != 0 {
		w.intN(uint64(len(e.connectAttrs)))
		for k, v := range e.connectAttrs {
			w.stringN(k)
			w.stringN(v)
		}
	}
	return w.err
}

// https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
// SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
func encryptedPasswd(password, scramble []byte) []byte {
	hash := sha1.New()
	sha1 := func(b []byte) []byte {
		hash.Reset()
		hash.Write(b)
		return hash.Sum(nil)
	}

	x := sha1(password)
	y := sha1(append(scramble[:20], sha1(sha1(password))...))
	for i, b := range y {
		x[i] ^= b
	}
	return x
}

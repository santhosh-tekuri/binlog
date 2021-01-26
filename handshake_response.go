package binlog

import (
	"crypto/sha1"
)

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

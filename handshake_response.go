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
	capabilities := e.capabilityFlags
	capabilities |= CLIENT_PROTOCOL_41
	if e.database != "" {
		capabilities |= CLIENT_CONNECT_WITH_DB
	}
	if e.authPluginName != "" {
		capabilities |= CLIENT_PLUGIN_AUTH
	}
	if len(e.connectAttrs) > 0 {
		capabilities |= CLIENT_CONNECT_ATTRS
	}

	if err := w.int4(capabilities); err != nil {
		return err
	}
	if err := w.int4(e.maxPacketSize); err != nil {
		return err
	}
	if err := w.int1(e.characterSet); err != nil {
		return err
	}
	if _, err := w.Write(make([]byte, 23)); err != nil { // reserved
		return err
	}
	if err := w.stringNull(e.username); err != nil {
		return err
	}
	switch {
	case capabilities&CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0:
		if err := w.bytesN(e.authResponse); err != nil {
			return err
		}
	case capabilities&CLIENT_SECURE_CONNECTION != 0:
		if err := w.bytes1(e.authResponse); err != nil {
			return err
		}
	default:
		if err := w.bytesNull(e.authResponse); err != nil {
			return err
		}
	}
	if capabilities&CLIENT_CONNECT_WITH_DB != 0 {
		if err := w.stringNull(e.database); err != nil {
			return err
		}
	}
	if capabilities&CLIENT_PLUGIN_AUTH != 0 {
		if err := w.stringNull(e.authPluginName); err != nil {
			return err
		}
	}
	if capabilities&CLIENT_CONNECT_ATTRS != 0 {
		if err := w.intN(uint64(len(e.connectAttrs))); err != nil {
			return err
		}
		for k, v := range e.connectAttrs {
			if err := w.stringN(k); err != nil {
				return err
			}
			if err := w.stringN(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
// SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
func encryptedPasswd(password string, scramble []byte) (out []byte) {
	hash := sha1.New()
	hash.Write([]byte(password))
	sha1Pwd := hash.Sum(nil)

	hash.Reset()
	hash.Write(sha1Pwd)
	sha1sha1Pwd := hash.Sum(nil)

	hash.Reset()
	hash.Write(scramble[:20])
	hash.Write(sha1sha1Pwd)
	sha1Scramble := hash.Sum(nil)

	for i, b := range sha1Scramble {
		sha1Pwd[i] ^= b
	}
	return sha1Pwd
}

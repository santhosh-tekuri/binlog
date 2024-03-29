package binlog

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
)

// Authenticate sends the credentials to MySQL.
func (bl *Remote) Authenticate(username, password string) error {
	bl.authFlow = nil
	var plugin string
	switch bl.hs.authPluginName {
	case "mysql_native_password", "mysql_clear_password", "sha256_password", "caching_sha2_password": // supported
		plugin = bl.hs.authPluginName
	case "": // unspecified
		plugin = "mysql_native_password" // todo: make it configurable
	default:
		return fmt.Errorf("binlog: unsupported authPlugin %q", bl.hs.authPluginName)
	}
	bl.authFlow = append(bl.authFlow, plugin)
	authPluginData := bl.hs.authPluginData
	authResponse, err := bl.encryptPassword(plugin, []byte(password), authPluginData)
	if err != nil {
		return err
	}

	err = bl.write(handshakeResponse41{
		capabilityFlags: capLongFlag | capSecureConnection,
		maxPacketSize:   maxPacketSize,
		characterSet:    bl.hs.characterSet,
		username:        username,
		authResponse:    authResponse,
		database:        "",
		authPluginName:  plugin,
		connectAttrs:    nil,
	})
	if err != nil {
		return err
	}
	var numAuthSwitches = 0
AuthSuccess:
	for {
		r := newReader(bl.conn, &bl.seq)
		marker, err := r.peek()
		if err != nil {
			return err
		}
		switch marker {
		case okMarker:
			if err := r.drain(); err != nil {
				return err
			}
			break AuthSuccess
		case errMarker:
			ep := errPacket{}
			if err := ep.decode(r, bl.hs.capabilityFlags); err != nil {
				return err
			}
			return errors.New(ep.errorMessage)
		case 0x01:
			amd := authMoreData{}
			if err := amd.decode(r); err != nil {
				return err
			}
			switch plugin {
			case "caching_sha2_password":
				switch len(amd.pluginData) {
				case 0:
					break AuthSuccess
				case 1:
					switch amd.pluginData[0] {
					case 3:
						bl.authFlow = append(bl.authFlow, "fastAuthSuccess")
						if err := bl.readOkErr(); err != nil {
							return err
						}
						break AuthSuccess
					case 4:
						bl.authFlow = append(bl.authFlow, "performFullAuthentication")
						switch bl.conn.(type) {
						case *tls.Conn, *net.UnixConn:
							authResponse = append([]byte(password), 0)
						default:
							if bl.pubKey == nil {
								bl.authFlow = append(bl.authFlow, "requestPublicKey2")
								if err := bl.write(requestPublicKey{}); err != nil {
									return err
								}
								r := newReader(bl.conn, &bl.seq)
								amd := authMoreData{}
								if err := amd.decode(r); err != nil {
									return err
								}
								if bl.pubKey, err = decodePEM(amd.pluginData); err != nil {
									return err
								}
							}
							if authResponse, err = encryptPasswordPubKey([]byte(password), authPluginData, bl.pubKey); err != nil {
								return err
							}
						}
						if err := bl.write(authSwitchResponse{authResponse}); err != nil {
							return err
						}
						if err := bl.readOkErr(); err != nil {
							return err
						}
						break AuthSuccess
					}
				default:
					return ErrMalformedPacket
				}
			case "sha256_password":
				if len(amd.pluginData) == 0 {
					break AuthSuccess
				}
				if bl.pubKey, err = decodePEM(amd.pluginData); err != nil {
					return err
				}
				if authResponse, err = encryptPasswordPubKey([]byte(password), authPluginData, bl.pubKey); err != nil {
					return err
				}
				if err := bl.write(authSwitchResponse{authResponse}); err != nil {
					return err
				}
				if err := bl.readOkErr(); err != nil {
					return err
				}
				break AuthSuccess
			default:
				break AuthSuccess
			}
		case 0xFE:
			if numAuthSwitches != 0 {
				return errors.New("binlog: authSwitch more than once")
			}
			numAuthSwitches++
			asr := authSwitchRequest{}
			if err := asr.decode(r); err != nil {
				return err
			}
			plugin = asr.pluginName
			bl.authFlow = append(bl.authFlow, plugin)
			authPluginData = asr.pluginData
			authResponse, err = bl.encryptPassword(plugin, []byte(password), asr.pluginData)
			if err != nil {
				return err
			}
			if err := bl.write(authSwitchResponse{authResponse}); err != nil {
				return err
			}
		default:
			return ErrMalformedPacket
		}
	}
	// authentication succeeded

	// query serverVersion. seems azure reports wrong serverVersion in handshake
	// Azure Database for MySQL service that is created with version 5.7
	// reports its version as "5.6.26.0" in initial handshake packet.
	rows, err := bl.queryRows(`select version()`)
	if err != nil {
		return err
	}
	bl.hs.serverVersion = rows[0][0].(string)
	return nil
}

// password encryption ---

func (bl *Remote) encryptPassword(plugin string, password, scramble []byte) ([]byte, error) {
	switch plugin {
	case "sha256_password":
		if len(password) == 0 {
			return []byte{0}, nil
		}
		switch bl.conn.(type) {
		case *tls.Conn:
			// unlike caching_sha2_password, sha256_password does not accept
			// cleartext password on unix transport
			return append(password, 0), nil
		default:
			if bl.pubKey == nil {
				bl.authFlow = append(bl.authFlow, "requestPublicKey1")
				// request public key from server
				return []byte{1}, nil
			}
			return encryptPasswordPubKey(password, scramble, bl.pubKey)
		}
	case "caching_sha2_password":
		if len(password) == 0 {
			return nil, nil
		}
		// SHA256(password) XOR SHA256(SHA256(SHA256(password)), scramble)
		hash := sha256.New()
		sha256 := func(b []byte) []byte {
			hash.Reset()
			hash.Write(b)
			return hash.Sum(nil)
		}
		x := sha256(password)
		y := sha256(append(sha256(sha256(x)), scramble[:20]...))
		for i, b := range y {
			x[i] ^= b
		}
		return x, nil
	case "mysql_native_password":
		// https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
		// SHA1(password) XOR SHA1("20-bytes random data from server", SHA1(SHA1(password)))
		if len(password) == 0 {
			return nil, nil
		}
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
		return x, nil
	case "mysql_clear_password":
		// https://dev.mysql.com/doc/internals/en/clear-text-authentication.html
		return append(password, 0), nil
	}
	return nil, fmt.Errorf("binlog: unsupported authPlugin %q", plugin)
}

func decodePEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("binlog: no PEM data found in server response")
	}
	pkix, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pkix.(*rsa.PublicKey), nil
}

func encryptPasswordPubKey(password, seed []byte, pub *rsa.PublicKey) ([]byte, error) {
	seed = seed[:20]
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		j := i % len(seed)
		plain[i] ^= seed[j]
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plain, nil)
}

// packets ----

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthMoreData
type authMoreData struct {
	pluginData []byte // extra auth-data beyond the initial challenge
}

func (e *authMoreData) decode(r *reader) error {
	status := r.int1()
	if r.err != nil {
		return r.err
	}
	if status != 0x01 {
		return fmt.Errorf("binlog: authMoreData.status is %0xd", status)
	}
	e.pluginData = r.bytesEOF()
	return r.err
}

// If both server and client support CLIENT_PLUGIN_AUTH capability,
// server can send this packet to ask client to use another
// authentication method.
//
// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchRequest
type authSwitchRequest struct {
	pluginName string // name of the authentication method to switch to
	pluginData []byte // initial auth-data for that authentication method
}

func (e *authSwitchRequest) decode(r *reader) error {
	status := r.int1()
	if r.err != nil {
		return r.err
	}
	if status != 0xFE {
		return fmt.Errorf("binlog: authSwitchRequest.status is %0xd", status)
	}
	e.pluginName = r.stringNull()
	e.pluginData = r.bytesEOF()
	return r.err
}

// authSwitchResponse contains response data generated by the authentication method requested
// in authSwitchRequest. Returns authMoreData or okPacket or errPacket.
//
// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
type authSwitchResponse struct {
	authResponse []byte
}

func (e authSwitchResponse) encode(w *writer) error {
	w.Write(e.authResponse)
	return w.err
}

type requestPublicKey struct{}

func (e requestPublicKey) encode(w *writer) error {
	return w.int1(2)
}

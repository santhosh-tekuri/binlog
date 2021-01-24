package binlog

import (
	"fmt"
)

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
	CLIENT_SECURE_CONNECTION              = 0x00008000
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
	CLIENT_CONNECT_ATTRS                  = 0x00100000
	CLIENT_PROTOCOL_41                    = 0x00000200
)

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html

type handshakeV10 struct {
	protocolVersion     uint8
	serverVersion       string
	connectionID        uint32
	authPluginDataPart1 []byte
	capabilityFlags     uint32
	characterSet        uint8
	statusFlags         uint16
	authPluginDataPart2 []byte
	authPluginName      string
}

func (e *handshakeV10) parse(r *reader) (err error) {
	if e.protocolVersion, err = r.int1(); err != nil {
		return err
	}
	if e.serverVersion, err = r.stringNull(); err != nil {
		return err
	}
	if e.connectionID, err = r.int4(); err != nil {
		return err
	}
	if e.authPluginDataPart1, err = r.bytes(8); err != nil {
		return err
	}
	if err = r.skip(1); err != nil { // filler
		return err
	}
	if lowerFlags, err := r.int2(); err != nil {
		return err
	} else {
		e.capabilityFlags = uint32(lowerFlags)
	}
	if more, err := r.more(); err != nil {
		return err
	} else if !more {
		return nil
	}
	if e.characterSet, err = r.int1(); err != nil {
		return err
	}
	if e.statusFlags, err = r.int2(); err != nil {
		return err
	}
	if upperFlags, err := r.int2(); err != nil {
		return err
	} else {
		e.capabilityFlags |= uint32(upperFlags) << 16
	}
	var authPluginDataLength uint8
	if e.capabilityFlags&CLIENT_PLUGIN_AUTH != 0 {
		if authPluginDataLength, err = r.int1(); err != nil {
			return err
		}
	} else {
		if err = r.skip(1); err != nil {
			return err
		}
	}
	if err = r.skip(10); err != nil { // reserved
		return err
	}
	if e.capabilityFlags&CLIENT_SECURE_CONNECTION != 0 {
		if authPluginDataLength > 0 && (13 < authPluginDataLength-8) {
			authPluginDataLength -= 8
		} else {
			authPluginDataLength = 13
		}
		fmt.Println("came here 2", authPluginDataLength)
		if e.authPluginDataPart2, err = r.bytes(int(authPluginDataLength)); err != nil {
			return err
		}
	}
	if e.capabilityFlags&CLIENT_PLUGIN_AUTH != 0 {
		if e.authPluginName, err = r.stringNull(); err != nil {
			return err
		}
	}
	return nil
}

// handshakeV9 ---

type handshakeV9 struct {
	protocolVersion  uint8
	serverVersion    string
	connectionID     uint32
	auth_plugin_data []byte
}

func (e *handshakeV9) parse(r *reader) (err error) {
	if e.protocolVersion, err = r.int1(); err != nil {
		return err
	}
	if e.serverVersion, err = r.stringNull(); err != nil {
		return err
	}
	if e.connectionID, err = r.int4(); err != nil {
		return err
	}
	if e.auth_plugin_data, err = r.bytesNull(); err != nil {
		return err
	}
	return nil
}

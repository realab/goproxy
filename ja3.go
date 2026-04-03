package goproxy

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// computeJA3 parses a raw TLS ClientHello record and returns the JA3
// fingerprint string and its MD5 hash. The raw slice must include the
// 5-byte TLS record header.
//
// JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
// See https://github.com/salesforce/ja3
func computeJA3(raw []byte) (ja3 string, hash string, err error) {
	// Skip TLS record header (5 bytes): type(1) + version(2) + length(2)
	if len(raw) < 5 {
		return "", "", fmt.Errorf("record too short")
	}
	payload := raw[5:]

	// Handshake header: type(1) + length(3)
	if len(payload) < 4 {
		return "", "", fmt.Errorf("handshake header too short")
	}
	if payload[0] != 1 { // ClientHello
		return "", "", fmt.Errorf("not a ClientHello (type %d)", payload[0])
	}
	payload = payload[4:]

	// ClientHello body:
	//   client_version(2) + random(32) + session_id_len(1) + session_id(var)
	//   + cipher_suites_len(2) + cipher_suites(var)
	//   + compression_methods_len(1) + compression_methods(var)
	//   + extensions_len(2) + extensions(var)
	if len(payload) < 2 {
		return "", "", fmt.Errorf("ClientHello too short for version")
	}
	tlsVersion := binary.BigEndian.Uint16(payload[:2])
	payload = payload[2:]

	// Skip random (32 bytes)
	if len(payload) < 32 {
		return "", "", fmt.Errorf("ClientHello too short for random")
	}
	payload = payload[32:]

	// Skip session ID
	if len(payload) < 1 {
		return "", "", fmt.Errorf("ClientHello too short for session ID length")
	}
	sidLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sidLen {
		return "", "", fmt.Errorf("ClientHello too short for session ID")
	}
	payload = payload[sidLen:]

	// Cipher suites
	if len(payload) < 2 {
		return "", "", fmt.Errorf("ClientHello too short for cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if len(payload) < csLen || csLen%2 != 0 {
		return "", "", fmt.Errorf("ClientHello too short for cipher suites")
	}
	var ciphers []string
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(payload[i : i+2])
		if !isGREASE(cs) {
			ciphers = append(ciphers, strconv.FormatUint(uint64(cs), 10))
		}
	}
	payload = payload[csLen:]

	// Compression methods
	if len(payload) < 1 {
		return "", "", fmt.Errorf("ClientHello too short for compression methods length")
	}
	cmLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < cmLen {
		return "", "", fmt.Errorf("ClientHello too short for compression methods")
	}
	payload = payload[cmLen:]

	// Extensions
	var extensions []string
	var curves []string
	var pointFormats []string

	if len(payload) >= 2 {
		extLen := int(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
		if len(payload) < extLen {
			return "", "", fmt.Errorf("ClientHello too short for extensions")
		}
		extData := payload[:extLen]

		for len(extData) >= 4 {
			extType := binary.BigEndian.Uint16(extData[:2])
			extBodyLen := int(binary.BigEndian.Uint16(extData[2:4]))
			extData = extData[4:]
			if len(extData) < extBodyLen {
				break
			}
			extBody := extData[:extBodyLen]
			extData = extData[extBodyLen:]

			if isGREASE(extType) {
				continue
			}
			extensions = append(extensions, strconv.FormatUint(uint64(extType), 10))

			switch extType {
			case 0x000a: // supported_groups (elliptic_curves)
				if len(extBody) >= 2 {
					groupListLen := int(binary.BigEndian.Uint16(extBody[:2]))
					groups := extBody[2:]
					for i := 0; i+1 < groupListLen && i+1 < len(groups); i += 2 {
						g := binary.BigEndian.Uint16(groups[i : i+2])
						if !isGREASE(g) {
							curves = append(curves, strconv.FormatUint(uint64(g), 10))
						}
					}
				}
			case 0x000b: // ec_point_formats
				if len(extBody) >= 1 {
					pfLen := int(extBody[0])
					pf := extBody[1:]
					for i := 0; i < pfLen && i < len(pf); i++ {
						pointFormats = append(pointFormats, strconv.FormatUint(uint64(pf[i]), 10))
					}
				}
			}
		}
	}

	ja3 = fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVersion,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(pointFormats, "-"),
	)
	hash = fmt.Sprintf("%x", md5.Sum([]byte(ja3)))
	return ja3, hash, nil
}

// isGREASE reports whether v is a GREASE (Generate Random Extensions And
// Sustain Extensibility) value. GREASE values match the pattern 0x?a?a
// where both nibbles are equal.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

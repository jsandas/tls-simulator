package ftls

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type ClientHelloMsg struct {
	original                         []byte
	Vers                             uint16
	Random                           []byte
	SessionId                        []byte
	CipherSuites                     []uint16
	CompressionMethods               []uint8
	ServerName                       string
	OcspStapling                     bool
	SupportedCurves                  []CurveID
	SupportedPoints                  []uint8
	TicketSupported                  bool
	SessionTicket                    []uint8
	SupportedSignatureAlgorithms     []SignatureScheme
	SupportedSignatureAlgorithmsCert []SignatureScheme
	SecureRenegotiationSupported     bool
	SecureRenegotiation              []byte
	ExtendedMasterSecret             bool
	AlpnProtocols                    []string
	Scts                             bool
	SupportedVersions                []uint16
	Cookie                           []byte
	KeyShares                        []KeyShare
	EarlyData                        bool
	PskModes                         []uint8
	PskIdentities                    []PskIdentity
	PskBinders                       [][]byte
	QuicTransportParameters          []byte
	EncryptedClientHello             []byte
	// extensions are only populated on the server-side of a handshake
	Extensions []uint16
}

func (m *ClientHelloMsg) MarshalMsg(echInner bool) ([]byte, error) {
	var exts cryptobyte.Builder
	if m.ServerName != "" {
		// RFC 6066, Section 3
		exts.AddUint16(ExtensionServerName)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(0) // name_type is host_name
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.ServerName))
				})
			})
		})
	}
	if len(m.SupportedPoints) > 0 && !echInner {
		// RFC 4492, Section 5.1.2
		exts.AddUint16(ExtensionSupportedPoints)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.SupportedPoints)
			})
		})
	}
	if m.TicketSupported && !echInner {
		// RFC 5077, Section 3.2
		exts.AddUint16(ExtensionSessionTicket)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.SessionTicket)
		})
	}
	if m.SecureRenegotiationSupported && !echInner {
		// RFC 5746, Section 3.2
		exts.AddUint16(ExtensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.SecureRenegotiation)
			})
		})
	}
	if m.ExtendedMasterSecret && !echInner {
		// RFC 7627
		exts.AddUint16(ExtensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if m.Scts {
		// RFC 6962, Section 3.3.1
		exts.AddUint16(ExtensionSCT)
		exts.AddUint16(0) // empty extension_data
	}
	if m.EarlyData {
		// RFC 8446, Section 4.2.10
		exts.AddUint16(ExtensionEarlyData)
		exts.AddUint16(0) // empty extension_data
	}
	if m.QuicTransportParameters != nil { // marshal zero-length parameters when present
		// RFC 9001, Section 8.2
		exts.AddUint16(ExtensionQUICTransportParameters)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.QuicTransportParameters)
		})
	}
	if len(m.EncryptedClientHello) > 0 {
		exts.AddUint16(ExtensionEncryptedClientHello)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.EncryptedClientHello)
		})
	}
	// Note that any extension that can be compressed during ECH must be
	// contiguous. If any additional extensions are to be compressed they must
	// be added to the following block, so that they can be properly
	// decompressed on the other side.
	var echOuterExts []uint16
	if m.OcspStapling {
		// RFC 4366, Section 3.6
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionStatusRequest)
		} else {
			exts.AddUint16(ExtensionStatusRequest)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(1)  // status_type is ocsp
				exts.AddUint16(0) // empty responder_id_list
				exts.AddUint16(0) // empty request_extensions
			})
		}
	}
	if len(m.SupportedCurves) > 0 {
		// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSupportedCurves)
		} else {
			exts.AddUint16(ExtensionSupportedCurves)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, curve := range m.SupportedCurves {
						exts.AddUint16(uint16(curve))
					}
				})
			})
		}
	}
	if len(m.SupportedSignatureAlgorithms) > 0 {
		// RFC 5246, Section 7.4.1.4.1
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSignatureAlgorithms)
		} else {
			exts.AddUint16(ExtensionSignatureAlgorithms)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, sigAlgo := range m.SupportedSignatureAlgorithms {
						exts.AddUint16(uint16(sigAlgo))
					}
				})
			})
		}
	}
	if len(m.SupportedSignatureAlgorithmsCert) > 0 {
		// RFC 8446, Section 4.2.3
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSignatureAlgorithmsCert)
		} else {
			exts.AddUint16(ExtensionSignatureAlgorithmsCert)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, sigAlgo := range m.SupportedSignatureAlgorithmsCert {
						exts.AddUint16(uint16(sigAlgo))
					}
				})
			})
		}
	}
	if len(m.AlpnProtocols) > 0 {
		// RFC 7301, Section 3.1
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionALPN)
		} else {
			exts.AddUint16(ExtensionALPN)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, proto := range m.AlpnProtocols {
						exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes([]byte(proto))
						})
					}
				})
			})
		}
	}
	if len(m.SupportedVersions) > 0 {
		// RFC 8446, Section 4.2.1
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSupportedVersions)
		} else {
			exts.AddUint16(ExtensionSupportedVersions)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, vers := range m.SupportedVersions {
						exts.AddUint16(vers)
					}
				})
			})
		}
	}
	if len(m.Cookie) > 0 {
		// RFC 8446, Section 4.2.2
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionCookie)
		} else {
			exts.AddUint16(ExtensionCookie)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.Cookie)
				})
			})
		}
	}
	if len(m.KeyShares) > 0 {
		// RFC 8446, Section 4.2.8
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionKeyShare)
		} else {
			exts.AddUint16(ExtensionKeyShare)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, ks := range m.KeyShares {
						exts.AddUint16(uint16(ks.Group))
						exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes(ks.Data)
						})
					}
				})
			})
		}
	}
	if len(m.PskModes) > 0 {
		// RFC 8446, Section 4.2.9
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionPSKModes)
		} else {
			exts.AddUint16(ExtensionPSKModes)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.PskModes)
				})
			})
		}
	}
	if len(echOuterExts) > 0 && echInner {
		exts.AddUint16(ExtensionECHOuterExtensions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, e := range echOuterExts {
					exts.AddUint16(e)
				}
			})
		})
	}
	if len(m.PskIdentities) > 0 { // pre_shared_key must be the last extension
		// RFC 8446, Section 4.2.11
		exts.AddUint16(ExtensionPreSharedKey)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, psk := range m.PskIdentities {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(psk.Label)
					})
					exts.AddUint32(psk.ObfuscatedTicketAge)
				}
			})
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, binder := range m.PskBinders {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(binder)
					})
				}
			})
		})
	}
	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(TypeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.Vers)
		addBytesWithLength(b, m.Random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if !echInner {
				b.AddBytes(m.SessionId)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.CipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.CompressionMethods)
		})

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *ClientHelloMsg) Unmarshal(data []byte) bool {
	*m = ClientHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Vers) || !s.ReadBytes(&m.Random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.CipherSuites = []uint16{}
	m.SecureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.SecureRenegotiationSupported = true
		}
		m.CipherSuites = append(m.CipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.CompressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true
		m.Extensions = append(m.Extensions, extension)

		switch extension {
		case ExtensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if m.ServerName != "" {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.ServerName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.ServerName, ".") {
					return false
				}
			}
		case ExtensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.OcspStapling = statusType == StatusTypeOCSP
		case ExtensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.SupportedCurves = append(m.SupportedCurves, CurveID(curve))
			}
		case ExtensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.SupportedPoints) ||
				len(m.SupportedPoints) == 0 {
				return false
			}
		case ExtensionSessionTicket:
			// RFC 5077, Section 3.2
			m.TicketSupported = true
			extData.ReadBytes(&m.SessionTicket, len(extData))
		case ExtensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.SupportedSignatureAlgorithms = append(
					m.SupportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
		case ExtensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.SupportedSignatureAlgorithmsCert = append(
					m.SupportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
			}
		case ExtensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &m.SecureRenegotiation) {
				return false
			}
			m.SecureRenegotiationSupported = true
		case ExtensionExtendedMasterSecret:
			// RFC 7627
			m.ExtendedMasterSecret = true
		case ExtensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.AlpnProtocols = append(m.AlpnProtocols, string(proto))
			}
		case ExtensionSCT:
			// RFC 6962, Section 3.3.1
			m.Scts = true
		case ExtensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return false
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return false
				}
				m.SupportedVersions = append(m.SupportedVersions, vers)
			}
		case ExtensionCookie:
			// RFC 8446, Section 4.2.2
			if !readUint16LengthPrefixed(&extData, &m.Cookie) ||
				len(m.Cookie) == 0 {
				return false
			}
		case ExtensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return false
			}
			for !clientShares.Empty() {
				var ks KeyShare
				if !clientShares.ReadUint16((*uint16)(&ks.Group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.Data) ||
					len(ks.Data) == 0 {
					return false
				}
				m.KeyShares = append(m.KeyShares, ks)
			}
		case ExtensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.EarlyData = true
		case ExtensionPSKModes:
			// RFC 8446, Section 4.2.9
			if !readUint8LengthPrefixed(&extData, &m.PskModes) {
				return false
			}
		case ExtensionQUICTransportParameters:
			m.QuicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.QuicTransportParameters) {
				return false
			}
		case ExtensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if !extensions.Empty() {
				return false // pre_shared_key must be the last extension
			}
			var identities cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
				return false
			}
			for !identities.Empty() {
				var psk PskIdentity
				if !readUint16LengthPrefixed(&identities, &psk.Label) ||
					!identities.ReadUint32(&psk.ObfuscatedTicketAge) ||
					len(psk.Label) == 0 {
					return false
				}
				m.PskIdentities = append(m.PskIdentities, psk)
			}
			var binders cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
				return false
			}
			for !binders.Empty() {
				var binder []byte
				if !readUint8LengthPrefixed(&binders, &binder) ||
					len(binder) == 0 {
					return false
				}
				m.PskBinders = append(m.PskBinders, binder)
			}
		case ExtensionEncryptedClientHello:
			if !extData.ReadBytes(&m.EncryptedClientHello, len(extData)) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type ServerHelloMsg struct {
	Original                     []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	OcspStapling                 bool
	TicketSupported              bool
	SecureRenegotiationSupported bool
	SecureRenegotiation          []byte
	ExtendedMasterSecret         bool
	AlpnProtocol                 string
	Scts                         [][]byte
	SupportedVersion             uint16
	ServerShare                  KeyShare
	SelectedIdentityPresent      bool
	SelectedIdentity             uint16
	SupportedPoints              []uint8
	EncryptedClientHello         []byte
	ServerNameAck                bool

	// HelloRetryRequest extensions
	Cookie        []byte
	SelectedGroup CurveID
}

func (m *ServerHelloMsg) Marshal() ([]byte, error) {
	var exts cryptobyte.Builder
	if m.OcspStapling {
		exts.AddUint16(ExtensionStatusRequest)
		exts.AddUint16(0) // empty extension_data
	}
	if m.TicketSupported {
		exts.AddUint16(ExtensionSessionTicket)
		exts.AddUint16(0) // empty extension_data
	}
	if m.SecureRenegotiationSupported {
		exts.AddUint16(ExtensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.SecureRenegotiation)
			})
		})
	}
	if m.ExtendedMasterSecret {
		exts.AddUint16(ExtensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if m.AlpnProtocol != "" {
		exts.AddUint16(ExtensionALPN)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.AlpnProtocol))
				})
			})
		})
	}
	if len(m.Scts) > 0 {
		exts.AddUint16(ExtensionSCT)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, sct := range m.Scts {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(sct)
					})
				}
			})
		})
	}
	if m.SupportedVersion != 0 {
		exts.AddUint16(ExtensionSupportedVersions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(m.SupportedVersion)
		})
	}
	if m.ServerShare.Group != 0 {
		exts.AddUint16(ExtensionKeyShare)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(uint16(m.ServerShare.Group))
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.ServerShare.Data)
			})
		})
	}
	if m.SelectedIdentityPresent {
		exts.AddUint16(ExtensionPreSharedKey)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(m.SelectedIdentity)
		})
	}

	if len(m.Cookie) > 0 {
		exts.AddUint16(ExtensionCookie)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.Cookie)
			})
		})
	}
	if m.SelectedGroup != 0 {
		exts.AddUint16(ExtensionKeyShare)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(uint16(m.SelectedGroup))
		})
	}
	if len(m.SupportedPoints) > 0 {
		exts.AddUint16(ExtensionSupportedPoints)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.SupportedPoints)
			})
		})
	}
	if len(m.EncryptedClientHello) > 0 {
		exts.AddUint16(ExtensionEncryptedClientHello)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.EncryptedClientHello)
		})
	}
	if m.ServerNameAck {
		exts.AddUint16(ExtensionServerName)
		exts.AddUint16(0)
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(TypeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.Vers)
		addBytesWithLength(b, m.Random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.SessionId)
		})
		b.AddUint16(m.CipherSuite)
		b.AddUint8(m.CompressionMethod)

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *ServerHelloMsg) Unmarshal(data []byte) bool {
	*m = ServerHelloMsg{Original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Vers) || !s.ReadBytes(&m.Random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionId) ||
		!s.ReadUint16(&m.CipherSuite) ||
		!s.ReadUint8(&m.CompressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case ExtensionStatusRequest:
			m.OcspStapling = true
		case ExtensionSessionTicket:
			m.TicketSupported = true
		case ExtensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.SecureRenegotiation) {
				return false
			}
			m.SecureRenegotiationSupported = true
		case ExtensionExtendedMasterSecret:
			m.ExtendedMasterSecret = true
		case ExtensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.AlpnProtocol = string(proto)
		case ExtensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return false
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return false
				}
				m.Scts = append(m.Scts, sct)
			}
		case ExtensionSupportedVersions:
			if !extData.ReadUint16(&m.SupportedVersion) {
				return false
			}
		case ExtensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.Cookie) ||
				len(m.Cookie) == 0 {
				return false
			}
		case ExtensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.SelectedGroup)) {
					return false
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.ServerShare.Group)) ||
					!readUint16LengthPrefixed(&extData, &m.ServerShare.Data) {
					return false
				}
			}
		case ExtensionPreSharedKey:
			m.SelectedIdentityPresent = true
			if !extData.ReadUint16(&m.SelectedIdentity) {
				return false
			}
		case ExtensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.SupportedPoints) ||
				len(m.SupportedPoints) == 0 {
				return false
			}
		case ExtensionEncryptedClientHello: // encrypted_client_hello
			m.EncryptedClientHello = make([]byte, len(extData))
			if !extData.CopyBytes(m.EncryptedClientHello) {
				return false
			}
		case ExtensionServerName:
			if len(extData) != 0 {
				return false
			}
			m.ServerNameAck = true
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *ServerHelloMsg) OriginalBytes() []byte {
	return m.Original
}

type ServerKeyExchangeMsg struct {
	Key     []byte
	KeySize int
	KeyType string
	CurveID CurveID
}

func (m *ServerKeyExchangeMsg) Marshal() ([]byte, error) {
	length := len(m.Key)
	x := make([]byte, length+4)
	x[0] = TypeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.Key)

	return x, nil
}

func (m *ServerKeyExchangeMsg) Unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m.Key = data[4:]
	return true
}

// GetKey returns the key exchange data
func (m *ServerKeyExchangeMsg) GetKey() error {
	key := m.Key
	if len(key) < 4 {
		return fmt.Errorf("ServerKeyExchange too short")
	}

	// Check if this is a named curve (ECDHE)
	if key[0] == 3 { // named curve
		curveID := CurveID(key[1])<<8 | CurveID(key[2])
		publicLen := int(key[3])

		if publicLen+4 > len(key) {
			return fmt.Errorf("invalid public key length in ServerKeyExchange")
		}

		// Get the curve name and key size
		switch curveID {
		case X25519:
			m.KeyType, m.KeySize, m.CurveID = "X25519", 32, curveID
			return nil
		case CurveP256:
			m.KeyType, m.KeySize, m.CurveID = "P-256", 32, curveID
			return nil
		case CurveP384:
			m.KeyType, m.KeySize, m.CurveID = "P-384", 48, curveID
			return nil
		case CurveP521:
			m.KeyType, m.KeySize, m.CurveID = "P-521", 66, curveID
			return nil
		default:
			return fmt.Errorf("unknown curve (0x%04x)", curveID)
		}
	}

	// Check if this is DH key exchange (not ECDHE)
	// DH ServerKeyExchange format: dh_p<1..2^16-1> + dh_g<1..2^16-1> + dh_Ys<1..2^16-1> + signature
	if len(key) >= 6 {
		// Parse dh_p length (first 2 bytes)
		dhPLen := int(key[0])<<8 | int(key[1])
		if dhPLen > 0 && dhPLen+2 <= len(key) {
			// Extract dh_p (prime modulus)
			dhP := key[2 : 2+dhPLen]

			// Identify common DH groups by their prime size and specific values
			switch len(dhP) {
			case 128: // 1024 bits
				m.KeyType, m.KeySize, m.CurveID = "DH-1024", 128, DH1024
				return nil
			case 256: // 2048 bits
				m.KeyType, m.KeySize, m.CurveID = "DH-2048", 256, DH2048
				return nil
			case 384: // 3072 bits
				m.KeyType, m.KeySize, m.CurveID = "DH-3072", 384, DH3072
				return nil
			case 512: // 4096 bits
				m.KeyType, m.KeySize, m.CurveID = "DH-4096", 512, DH4096
				return nil
			case 768: // 6144 bits
				m.KeyType, m.KeySize, m.CurveID = "DH-6144", 768, DH6144
				return nil
			case 1024: // 8192 bits
				m.KeyType, m.KeySize, m.CurveID = "DH-8192", 1024, DH8192
				return nil
			default:
				return fmt.Errorf("DH-%d", len(dhP)*8)
			}
		}
	}

	// For other key exchange types
	return fmt.Errorf("unknown key exchange type in ServerKeyExchange: %s", m.KeyType)
}

type FinishedMsg struct {
	verifyData []byte
}

func (m *FinishedMsg) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(TypeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	return b.Bytes()
}

func (m *FinishedMsg) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}

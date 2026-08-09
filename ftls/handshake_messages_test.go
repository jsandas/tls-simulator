package ftls

import (
	"bytes"
	"testing"
)

func TestFinishedMsg(t *testing.T) {
	tests := []struct {
		name       string
		verifyData []byte
		wantBytes  []byte
		wantError  bool
	}{
		{
			name:       "Empty verify data",
			verifyData: []byte{},
			wantBytes:  []byte{TypeFinished, 0, 0, 0},
			wantError:  false,
		},
		{
			name:       "12-byte verify data (TLS 1.2)",
			verifyData: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
			wantBytes:  []byte{TypeFinished, 0, 0, 12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
			wantError:  false,
		},
		{
			name: "32-byte verify data (TLS 1.3)",
			verifyData: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
			},
			wantBytes: append([]byte{TypeFinished, 0, 0, 32},
				[]byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				}...),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Marshal
			msg := &FinishedMsg{verifyData: tt.verifyData}

			got, err := msg.Marshal()
			if (err != nil) != tt.wantError {
				t.Errorf("Marshal() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if string(got) != string(tt.wantBytes) {
					t.Errorf("Marshal() = %v, want %v", got, tt.wantBytes)
				}
			}

			// Test Unmarshal
			if !tt.wantError {
				unmarshalMsg := &FinishedMsg{}
				if !unmarshalMsg.Unmarshal(tt.wantBytes) {
					t.Error("Unmarshal() returned false")
					return
				}

				if string(unmarshalMsg.verifyData) != string(tt.verifyData) {
					t.Errorf("Unmarshal() verifyData = %v, want %v", unmarshalMsg.verifyData, tt.verifyData)
				}
			}
		})
	}
}

func TestServerHelloMsg(t *testing.T) {
	tests := []struct {
		name             string
		msg              *ServerHelloMsg
		wantBytes        []byte
		wantUnmarshalErr bool
	}{
		{
			name: "Valid TLS 1.2 ServerHello",
			msg: &ServerHelloMsg{
				Vers: VersionTLS12,
				Random: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				},
				SessionId:         []byte{0x30, 0x31, 0x32, 0x33}, // 4-byte session ID
				CipherSuite:       uint16(0x1301),                 // TLS_AES_128_GCM_SHA256
				CompressionMethod: 0x00,                           // no compression
			},
			wantBytes: append([]byte{
				TypeServerHello,
				0x00, 0x00, 0x2A, // 42 bytes of data
				0x03, 0x03, // TLS 1.2
			},
				append([]byte{ // random
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				},
					append([]byte{
						0x04,                   // session ID length
						0x30, 0x31, 0x32, 0x33, // session ID
						0x13, 0x01, // cipher suite
						0x00, // compression method
					}, nil...)...)...),
			wantUnmarshalErr: false,
		},
		{
			name: "Valid TLS 1.3 ServerHello",
			msg: &ServerHelloMsg{
				Vers: VersionTLS13,
				Random: []byte{
					0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
					0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
					0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
					0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
				},
				SessionId:         []byte{},       // empty session ID for TLS 1.3
				CipherSuite:       uint16(0x1302), // TLS_AES_256_GCM_SHA384
				CompressionMethod: 0x00,
			},
			wantBytes: append([]byte{
				TypeServerHello,
				0x00, 0x00, 0x26, // 38 bytes of data
				0x03, 0x04, // TLS 1.3
			},
				append([]byte{ // random
					0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
					0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
					0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
					0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
				},
					append([]byte{
						0x00,       // session ID length (empty)
						0x13, 0x02, // cipher suite
						0x00, // compression method
					}, nil...)...)...),
			wantUnmarshalErr: false,
		},
		{
			name: "Invalid short message",
			msg:  &ServerHelloMsg{},
			wantBytes: []byte{
				TypeServerHello,
				0x00, 0x00, 0x02, // incorrect length
				0x03, // truncated version
			},
			wantUnmarshalErr: true,
		},
		{
			name: "Invalid session ID length",
			msg: &ServerHelloMsg{
				Vers:              VersionTLS12,
				Random:            make([]byte, 32),
				SessionId:         make([]byte, 33), // session ID too long (max is 32)
				CipherSuite:       uint16(0x1301),
				CompressionMethod: 0x00,
			},
			wantUnmarshalErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Marshal
			if !tt.wantUnmarshalErr {
				got, err := tt.msg.Marshal()
				if err != nil {
					t.Errorf("Marshal() error = %v", err)
					return
				}

				if string(got) != string(tt.wantBytes) {
					t.Errorf("Marshal() = %v, want %v", got, tt.wantBytes)
				}
			}

			// Test Unmarshal
			msg := new(ServerHelloMsg)

			success := msg.Unmarshal(tt.wantBytes)
			if success == tt.wantUnmarshalErr {
				t.Errorf("Unmarshal() = %v, want %v", success, !tt.wantUnmarshalErr)
				return
			}

			// For valid messages, verify all fields were correctly unmarshaled
			if !tt.wantUnmarshalErr {
				if msg.Vers != tt.msg.Vers {
					t.Errorf("Unmarshal() version = %v, want %v", msg.Vers, tt.msg.Vers)
				}

				if string(msg.Random) != string(tt.msg.Random) {
					t.Errorf("Unmarshal() random = %v, want %v", msg.Random, tt.msg.Random)
				}

				if string(msg.SessionId) != string(tt.msg.SessionId) {
					t.Errorf("Unmarshal() sessionId = %v, want %v", msg.SessionId, tt.msg.SessionId)
				}

				if msg.CipherSuite != tt.msg.CipherSuite {
					t.Errorf("Unmarshal() cipherSuite = %v, want %v", msg.CipherSuite, tt.msg.CipherSuite)
				}

				if msg.CompressionMethod != tt.msg.CompressionMethod {
					t.Errorf("Unmarshal() compressionMethod = %v, want %v", msg.CompressionMethod, tt.msg.CompressionMethod)
				}
			}
		})
	}
}

func TestServerKeyExchangeMsgGetKey(t *testing.T) {
	tests := []struct {
		name        string
		key         []byte
		wantType    string
		wantSize    int
		wantCurveID CurveID
		wantErr     bool
	}{
		{
			name: "ECDHE X25519",
			key: []byte{
				0x03,       // named curve
				0x00, 0x1d, // X25519 curve ID
				0x20,                   // public key length (32 bytes)
				1, 2, 3, 4, 5, 6, 7, 8, // dummy public key data
				9, 10, 11, 12, 13, 14, 15, 16,
				17, 18, 19, 20, 21, 22, 23, 24,
				25, 26, 27, 28, 29, 30, 31, 32,
			},
			wantType:    "X25519",
			wantSize:    32,
			wantCurveID: X25519,
			wantErr:     false,
		},
		{
			name: "ECDHE P-256",
			key: []byte{
				0x03,       // named curve
				0x00, 0x17, // P-256 curve ID
				0x20,                   // public key length (32 bytes)
				1, 2, 3, 4, 5, 6, 7, 8, // dummy public key data
				9, 10, 11, 12, 13, 14, 15, 16,
				17, 18, 19, 20, 21, 22, 23, 24,
				25, 26, 27, 28, 29, 30, 31, 32,
			},
			wantType:    "P-256",
			wantSize:    32,
			wantCurveID: CurveP256,
			wantErr:     false,
		},
		{
			name: "ECDHE P-384",
			key: []byte{
				0x03,       // named curve
				0x00, 0x18, // P-384 curve ID
				0x30,                   // public key length (48 bytes)
				1, 2, 3, 4, 5, 6, 7, 8, // dummy public key data
				9, 10, 11, 12, 13, 14, 15, 16,
				17, 18, 19, 20, 21, 22, 23, 24,
				25, 26, 27, 28, 29, 30, 31, 32,
				33, 34, 35, 36, 37, 38, 39, 40,
				41, 42, 43, 44, 45, 46, 47, 48,
			},
			wantType:    "P-384",
			wantSize:    48,
			wantCurveID: CurveP384,
			wantErr:     false,
		},
		{
			name: "DH 2048-bit",
			key: append(append(append([]byte{
				0x01, 0x00, // dh_p length (256 bytes = 2048 bits) in correct format
			}, make([]byte, 256)...), // dh_p value
				0x00, 0x02, // dh_g length (2 bytes)
				0x00, 0x02, // dh_g value
			), append([]byte{
				0x01, 0x00, // dh_Ys length (256 bytes)
			}, make([]byte, 256)...)...), // dh_Ys value
			wantType:    "DH-2048",
			wantSize:    256,
			wantCurveID: DH2048,
			wantErr:     false,
		},
		{
			name: "DH 3072-bit",
			key: append(append(append([]byte{
				0x01, 0x80, // dh_p length (384 bytes = 3072 bits) in correct format
			}, make([]byte, 384)...), // dh_p value
				0x00, 0x02, // dh_g length (2 bytes)
				0x00, 0x02, // dh_g value
			), append([]byte{
				0x01, 0x80, // dh_Ys length (384 bytes)
			}, make([]byte, 384)...)...), // dh_Ys value
			wantType:    "DH-3072",
			wantSize:    384,
			wantCurveID: DH3072,
			wantErr:     false,
		},
		{
			name:    "Too short message",
			key:     []byte{0x03, 0x00}, // incomplete message
			wantErr: true,
		},
		{
			name: "Unknown curve",
			key: []byte{
				0x03,       // named curve
				0xFF, 0xFF, // unknown curve ID
				0x20,       // public key length
				1, 2, 3, 4, // some data
			},
			wantErr: true,
		},
		{
			name: "Invalid public key length",
			key: []byte{
				0x03,       // named curve
				0x00, 0x1d, // X25519
				0xFF, // invalid length
				1, 2, // insufficient data
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ServerKeyExchangeMsg{Key: tt.key}
			err := m.GetKey()

			// Check error condition
			if tt.wantErr {
				if err == nil {
					t.Error("GetKey() expected error but got nil")
				}

				return
			}

			if err != nil {
				t.Errorf("GetKey() unexpected error: %v", err)
				return
			}

			// Check results
			if m.KeyType != tt.wantType {
				t.Errorf("KeyType = %v, want %v", m.KeyType, tt.wantType)
			}

			if m.KeySize != tt.wantSize {
				t.Errorf("KeySize = %v, want %v", m.KeySize, tt.wantSize)
			}

			if m.CurveID != tt.wantCurveID {
				t.Errorf("CurveID = %v, want %v", m.CurveID, tt.wantCurveID)
			}
		})
	}
}

func hasExt(exts []uint16, want uint16) bool {
	for _, ext := range exts {
		if ext == want {
			return true
		}
	}

	return false
}

func TestClientHelloMarshalUnmarshalFull(t *testing.T) {
	msg := &ClientHelloMsg{
		Vers:               VersionTLS12,
		Random:             bytes.Repeat([]byte{0xAB}, 32),
		SessionId:          []byte{0x01, 0x02, 0x03, 0x04},
		CipherSuites:       []uint16{0x1301, 0x1302, scsvRenegotiation},
		CompressionMethods: []uint8{0x00},
		ServerName:         "example.com",
		OcspStapling:       true,
		SupportedCurves:    []CurveID{X25519, CurveP256},
		SupportedPoints:    []uint8{0x00},
		TicketSupported:    true,
		SessionTicket:      []uint8{0xAA, 0xBB},
		SupportedSignatureAlgorithms: []SignatureScheme{
			SignatureScheme(0x0403),
			SignatureScheme(0x0804),
		},
		SupportedSignatureAlgorithmsCert: []SignatureScheme{
			SignatureScheme(0x0805),
		},
		SecureRenegotiationSupported: true,
		SecureRenegotiation:          []byte{0xFF},
		ExtendedMasterSecret:         true,
		AlpnProtocols:                []string{"h2", "http/1.1"},
		Scts:                         true,
		SupportedVersions:            []uint16{VersionTLS13, VersionTLS12},
		Cookie:                       []byte{0x10, 0x11},
		KeyShares: []KeyShare{{
			Group: X25519,
			Data:  []byte{1, 2, 3, 4},
		}},
		EarlyData:               true,
		PskModes:                []uint8{0x01},
		PskIdentities:           []PskIdentity{{Label: []byte("psk-id"), ObfuscatedTicketAge: 7}},
		PskBinders:              [][]byte{{0x01, 0x02, 0x03}},
		QuicTransportParameters: []byte{},
		EncryptedClientHello:    []byte{0xEE, 0xCC},
	}

	encoded, err := msg.MarshalMsg(false)
	if err != nil {
		t.Fatalf("MarshalMsg() error = %v", err)
	}

	var got ClientHelloMsg
	if !got.Unmarshal(encoded) {
		t.Fatal("Unmarshal() returned false")
	}

	if got.Vers != msg.Vers {
		t.Fatalf("version = %v, want %v", got.Vers, msg.Vers)
	}

	if !bytes.Equal(got.Random, msg.Random) {
		t.Fatalf("random mismatch")
	}

	if !got.OcspStapling || !got.TicketSupported || !got.SecureRenegotiationSupported || !got.ExtendedMasterSecret || !got.Scts || !got.EarlyData {
		t.Fatalf("expected boolean extensions to round-trip")
	}

	if got.ServerName != msg.ServerName {
		t.Fatalf("server name = %q, want %q", got.ServerName, msg.ServerName)
	}

	if len(got.PskIdentities) != 1 || len(got.PskBinders) != 1 {
		t.Fatalf("expected one PSK identity and binder")
	}

	if !hasExt(got.Extensions, ExtensionPreSharedKey) {
		t.Fatalf("expected pre_shared_key extension to be present")
	}
}

func TestClientHelloMarshalMsgECHInner(t *testing.T) {
	msg := &ClientHelloMsg{
		Vers:               VersionTLS13,
		Random:             bytes.Repeat([]byte{0xCD}, 32),
		SessionId:          []byte{0x99, 0x88, 0x77},
		CipherSuites:       []uint16{0x1301},
		CompressionMethods: []uint8{0x00},
		OcspStapling:       true,
		SupportedCurves:    []CurveID{X25519},
		SupportedSignatureAlgorithms: []SignatureScheme{
			SignatureScheme(0x0403),
		},
		AlpnProtocols:     []string{"h2"},
		SupportedVersions: []uint16{VersionTLS13},
		Cookie:            []byte{0xAA},
		KeyShares:         []KeyShare{{Group: X25519, Data: []byte{0x01, 0x02}}},
		PskModes:          []uint8{0x01},
	}

	encoded, err := msg.MarshalMsg(true)
	if err != nil {
		t.Fatalf("MarshalMsg(true) error = %v", err)
	}

	var got ClientHelloMsg
	if !got.Unmarshal(encoded) {
		t.Fatal("Unmarshal() returned false")
	}

	if len(got.SessionId) != 0 {
		t.Fatalf("session id should be omitted for ECH inner")
	}

	if hasExt(got.Extensions, ExtensionStatusRequest) {
		t.Fatalf("status_request should not be directly encoded for ECH inner")
	}

	if !hasExt(got.Extensions, ExtensionECHOuterExtensions) {
		t.Fatalf("expected ech_outer_extensions extension")
	}
}

func TestClientHelloUnmarshalRejectsInvalid(t *testing.T) {
	t.Run("server name trailing dot", func(t *testing.T) {
		msg := &ClientHelloMsg{
			Vers:               VersionTLS12,
			Random:             bytes.Repeat([]byte{0x11}, 32),
			CipherSuites:       []uint16{0x1301},
			CompressionMethods: []uint8{0x00},
			ServerName:         "example.com.",
		}

		encoded, err := msg.MarshalMsg(false)
		if err != nil {
			t.Fatalf("MarshalMsg() error = %v", err)
		}

		var got ClientHelloMsg
		if got.Unmarshal(encoded) {
			t.Fatal("Unmarshal() expected false for trailing-dot SNI")
		}
	})

	t.Run("pre shared key not last", func(t *testing.T) {
		base := &ClientHelloMsg{
			Vers:               VersionTLS13,
			Random:             bytes.Repeat([]byte{0x22}, 32),
			CipherSuites:       []uint16{0x1301},
			CompressionMethods: []uint8{0x00},
			PskIdentities:      []PskIdentity{{Label: []byte("a"), ObfuscatedTicketAge: 1}},
			PskBinders:         [][]byte{{0x01}},
		}

		encoded, err := base.MarshalMsg(false)
		if err != nil {
			t.Fatalf("MarshalMsg() error = %v", err)
		}

		// Append an extra zero-length unknown extension after pre_shared_key
		// while updating both handshake and extension length fields.
		msgData := append([]byte(nil), encoded[4:]...)
		extLenOffset := len(msgData) - 2
		for i := 0; i+3 < len(msgData); i++ {
			if i+1 < len(msgData) {
				extLen := int(msgData[i])<<8 | int(msgData[i+1])
				if i+2+extLen == len(msgData) {
					extLenOffset = i
					break
				}
			}
		}

		extLen := int(msgData[extLenOffset])<<8 | int(msgData[extLenOffset+1])
		msgData[extLenOffset] = byte((extLen + 4) >> 8)
		msgData[extLenOffset+1] = byte(extLen + 4)
		msgData = append(msgData, 0xFA, 0xCE, 0x00, 0x00)

		handshakeLen := len(msgData)
		encoded[1] = byte(handshakeLen >> 16)
		encoded[2] = byte(handshakeLen >> 8)
		encoded[3] = byte(handshakeLen)
		encoded = append(encoded[:4], msgData...)

		var got ClientHelloMsg
		if got.Unmarshal(encoded) {
			t.Fatal("Unmarshal() expected false when pre_shared_key is not last")
		}
	})
}

func TestServerHelloMarshalUnmarshalWithExtensions(t *testing.T) {
	msg := &ServerHelloMsg{
		Vers:                         VersionTLS13,
		Random:                       bytes.Repeat([]byte{0x33}, 32),
		SessionId:                    []byte{0x01, 0x02},
		CipherSuite:                  0x1301,
		CompressionMethod:            0,
		OcspStapling:                 true,
		TicketSupported:              true,
		SecureRenegotiationSupported: true,
		SecureRenegotiation:          []byte{0xAA},
		ExtendedMasterSecret:         true,
		AlpnProtocol:                 "h2",
		Scts:                         [][]byte{{0x01, 0x02}},
		SupportedVersion:             VersionTLS13,
		ServerShare:                  KeyShare{Group: X25519, Data: []byte{0x10, 0x20}},
		SelectedIdentityPresent:      true,
		SelectedIdentity:             2,
		SupportedPoints:              []uint8{0x00},
		EncryptedClientHello:         []byte{0xEE},
		ServerNameAck:                true,
		Cookie:                       []byte{0xCA, 0xFE},
	}

	encoded, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got ServerHelloMsg
	if !got.Unmarshal(encoded) {
		t.Fatal("Unmarshal() returned false")
	}

	if !got.OcspStapling || !got.TicketSupported || !got.SecureRenegotiationSupported || !got.ExtendedMasterSecret || !got.SelectedIdentityPresent || !got.ServerNameAck {
		t.Fatalf("expected boolean extension flags to be set")
	}

	if got.SelectedIdentity != msg.SelectedIdentity || got.SupportedVersion != msg.SupportedVersion {
		t.Fatalf("selected identity/version mismatch")
	}

	if got.ServerShare.Group != msg.ServerShare.Group || !bytes.Equal(got.ServerShare.Data, msg.ServerShare.Data) {
		t.Fatalf("server share mismatch")
	}

	if !bytes.Equal(got.OriginalBytes(), encoded) {
		t.Fatalf("OriginalBytes mismatch")
	}
}

func TestServerHelloUnmarshalHelloRetryRequestKeyShare(t *testing.T) {
	msg := &ServerHelloMsg{
		Vers:              VersionTLS13,
		Random:            bytes.Repeat([]byte{0x55}, 32),
		CipherSuite:       0x1301,
		CompressionMethod: 0,
		SelectedGroup:     CurveP256,
	}

	encoded, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got ServerHelloMsg
	if !got.Unmarshal(encoded) {
		t.Fatal("Unmarshal() returned false")
	}

	if got.SelectedGroup != CurveP256 {
		t.Fatalf("selected group = %v, want %v", got.SelectedGroup, CurveP256)
	}
}

func TestServerKeyExchangeMarshalAndUnmarshal(t *testing.T) {
	t.Run("marshal normal", func(t *testing.T) {
		msg := &ServerKeyExchangeMsg{Key: []byte{0x01, 0x02, 0x03}}
		encoded, err := msg.Marshal()
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}

		want := []byte{TypeServerKeyExchange, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
		if !bytes.Equal(encoded, want) {
			t.Fatalf("Marshal() = %v, want %v", encoded, want)
		}
	})

	t.Run("marshal too large", func(t *testing.T) {
		msg := &ServerKeyExchangeMsg{Key: make([]byte, 0x1000000)}
		if _, err := msg.Marshal(); err == nil {
			t.Fatal("Marshal() expected error for oversized key")
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		msg := &ServerKeyExchangeMsg{}
		if msg.Unmarshal([]byte{TypeServerKeyExchange, 0x00, 0x00}) {
			t.Fatal("Unmarshal() expected false for short message")
		}

		if !msg.Unmarshal([]byte{TypeServerKeyExchange, 0x00, 0x00, 0x01, 0xAA}) {
			t.Fatal("Unmarshal() expected true")
		}

		if !bytes.Equal(msg.Key, []byte{0xAA}) {
			t.Fatalf("unexpected key bytes: %v", msg.Key)
		}
	})
}

package ftls

import (
	"testing"
)

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

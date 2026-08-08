//go:build integration

package integrationtests

import (
	"crypto/tls"
	"testing"

	simulator "github.com/jsandas/tls-simulator"
	"github.com/jsandas/tls-simulator/ftls"
)

// TestNginx1300_TLS13_Chacha20 tests TLS 1.3 with CHACHA20_POLY1305_SHA256 on Nginx 1.30.0 (port 443).
func TestNginx1300_TLS13_Chacha20(t *testing.T) {
	ciphers := []uint16{
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	result, err := simulator.PerformTLSHandshake(
		tls.VersionTLS13,
		ciphers,
		curves,
		Nginx1300_TLS12_TLS13_Addr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS13); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	expectedCipher := tls.TLS_CHACHA20_POLY1305_SHA256
	if result.Cipher != expectedCipher {
		t.Errorf("Expected cipher suite 0x%04x, got 0x%04x", expectedCipher, result.Cipher)
	}

	if err := ValidateCurve(result, curves); err != nil {
		t.Errorf("Curve validation failed: %v", err)
	}

	t.Logf("Nginx 1.30.0 TLS 1.3 CHACHA20 handshake successful: Protocol=%s Cipher=%s Curve=%s",
		GetProtocolName(result.Protocol),
		GetCipherName(result.Cipher),
		GetCurveName(result.CurveID),
	)
}

// TestNginx1300_TLS13_DefaultCiphers tests TLS 1.3 with default ciphers on Nginx 1.30.0 (port 443).
func TestNginx1300_TLS13_DefaultCiphers(t *testing.T) {
	var ciphers []uint16
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
		ftls.CurveP521,
	}

	result, err := simulator.PerformTLSHandshake(
		tls.VersionTLS13,
		ciphers,
		curves,
		Nginx1300_TLS12_TLS13_Addr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS13); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	if err := ValidateTLS13Cipher(result); err != nil {
		t.Errorf("TLS 1.3 cipher validation failed: %v", err)
	}

	t.Logf("Nginx 1.30.0 TLS 1.3 default ciphers handshake successful: Protocol=%s Cipher=%s Curve=%s",
		GetProtocolName(result.Protocol),
		GetCipherName(result.Cipher),
		GetCurveName(result.CurveID),
	)
}

// TestNginx1300_TLS13_MultipleCurves tests negotiation of different elliptic curves on Nginx 1.30.0 (port 443).
func TestNginx1300_TLS13_MultipleCurves(t *testing.T) {
	testCases := []struct {
		name   string
		curves []ftls.CurveID
	}{
		{
			name:   "X25519 only",
			curves: []ftls.CurveID{ftls.X25519},
		},
		{
			name:   "P-256 only",
			curves: []ftls.CurveID{ftls.CurveP256},
		},
		{
			name:   "P-384 only",
			curves: []ftls.CurveID{ftls.CurveP384},
		},
		{
			name:   "P-521 only",
			curves: []ftls.CurveID{ftls.CurveP521},
		},
	}

	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := simulator.PerformTLSHandshake(
				tls.VersionTLS12,
				ciphers,
				tc.curves,
				Nginx1300_TLS12_TLS13_Addr,
			)

			if err != nil {
				t.Fatalf("TLS handshake failed for curve %s: %v", tc.name, err)
			}

			if err := ValidateTLSResult(result, tls.VersionTLS12); err != nil {
				t.Fatalf("Invalid TLS result: %v", err)
			}

			if err := ValidateCurve(result, tc.curves); err != nil {
				t.Errorf("Curve validation failed for %s: %v", tc.name, err)
			}

			t.Logf("Negotiated curve for %s: %s", tc.name, GetCurveName(result.CurveID))
		})
	}
}

// TestNginx1300_TLS12_ECDHE tests TLS 1.2 ECDHE cipher negotiation on Nginx 1.30.0 (port 443).
func TestNginx1300_TLS12_ECDHE(t *testing.T) {
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	curves := []ftls.CurveID{ftls.X25519, ftls.CurveP256}

	result, err := simulator.PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		Nginx1300_TLS12_TLS13_Addr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS12); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	if err := ValidateCipher(result, ciphers); err != nil {
		t.Errorf("Cipher validation failed: %v", err)
	}

	t.Logf("Nginx 1.30.0 TLS 1.2 ECDHE successful: Cipher=%s Curve=%s",
		GetCipherName(result.Cipher),
		GetCurveName(result.CurveID),
	)
}

// TestNginx1300_TLS12Only tests Nginx 1.30.0 configured for TLS 1.2 only (port 1443).
func TestNginx1300_TLS12Only(t *testing.T) {
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	curves := []ftls.CurveID{ftls.X25519, ftls.CurveP256}

	// Test TLS 1.2 succeeds
	result, err := simulator.PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		Nginx1300_TLS12_Addr,
	)

	if err != nil {
		t.Fatalf("TLS 1.2 handshake failed on TLS 1.2-only container: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS12); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	t.Logf("Nginx 1.30.0 TLS 1.2-only container verified: Protocol=%s Cipher=%s",
		GetProtocolName(result.Protocol),
		GetCipherName(result.Cipher),
	)
}

// TestNginx1300_TLS10To13 tests Nginx 1.30.0 configured with tls10+ config (port 2443).
// OpenSSL 3.5.7 in Nginx 1.30.0 accepts TLS 1.3 and TLS 1.2, but disables legacy TLS 1.0 / TLS 1.1.
func TestNginx1300_TLS10To13(t *testing.T) {
	curves := []ftls.CurveID{ftls.X25519, ftls.CurveP256}

	t.Run("TLS 1.3", func(t *testing.T) {
		result, err := simulator.PerformTLSHandshake(
			tls.VersionTLS13,
			nil,
			curves,
			Nginx1300_TLS10_TLS13_Addr,
		)
		if err != nil {
			t.Fatalf("TLS 1.3 handshake failed: %v", err)
		}
		t.Logf("Nginx 1.30.0 TLS 1.3 handshake successful: Protocol=%s Cipher=%s",
			GetProtocolName(result.Protocol),
			GetCipherName(result.Cipher),
		)
	})

	t.Run("TLS 1.2", func(t *testing.T) {
		ciphers := []uint16{ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		result, err := simulator.PerformTLSHandshake(
			tls.VersionTLS12,
			ciphers,
			curves,
			Nginx1300_TLS10_TLS13_Addr,
		)
		if err != nil {
			t.Fatalf("TLS 1.2 handshake failed: %v", err)
		}
		t.Logf("Nginx 1.30.0 TLS 1.2 handshake successful: Protocol=%s Cipher=%s",
			GetProtocolName(result.Protocol),
			GetCipherName(result.Cipher),
		)
	})

	t.Run("TLS 1.1 disabled by OpenSSL 3.x", func(t *testing.T) {
		ciphers := []uint16{ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}
		_, err := simulator.PerformTLSHandshake(
			tls.VersionTLS11,
			ciphers,
			curves,
			Nginx1300_TLS10_TLS13_Addr,
		)
		if err == nil {
			t.Errorf("Expected TLS 1.1 handshake to be rejected by OpenSSL 3.5.7, but it succeeded")
		} else {
			t.Logf("Correctly rejected TLS 1.1 connection: %v", err)
		}
	})

	t.Run("TLS 1.0 disabled by OpenSSL 3.x", func(t *testing.T) {
		ciphers := []uint16{ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}
		_, err := simulator.PerformTLSHandshake(
			tls.VersionTLS10,
			ciphers,
			curves,
			Nginx1300_TLS10_TLS13_Addr,
		)
		if err == nil {
			t.Errorf("Expected TLS 1.0 handshake to be rejected by OpenSSL 3.5.7, but it succeeded")
		} else {
			t.Logf("Correctly rejected TLS 1.0 connection: %v", err)
		}
	})
}

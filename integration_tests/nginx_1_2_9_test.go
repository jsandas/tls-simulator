//go:build integration

package integrationtests

import (
	"testing"

	simulator "github.com/jsandas/tls-simulator"
	"github.com/jsandas/tls-simulator/ftls"
)

// TestNginx129_TLS12_ECDHE_And_DHE tests Nginx 1.2.9 (OpenSSL 1.0.1f) with TLS 1.2 ECDHE & DHE ciphers (port 3443).
func TestNginx129_TLS12_ECDHE_And_DHE(t *testing.T) {
	t.Run("ECDHE", func(t *testing.T) {
		ciphers := []uint16{
			ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
		curves := []ftls.CurveID{ftls.X25519, ftls.CurveP256}

		result, err := simulator.PerformTLSHandshake(
			ftls.VersionTLS12,
			ciphers,
			curves,
			Nginx129_TLS12_Addr,
		)

		if err != nil {
			t.Fatalf("TLS 1.2 ECDHE handshake failed on Nginx 1.2.9: %v", err)
		}

		if err := ValidateTLSResult(result, ftls.VersionTLS12); err != nil {
			t.Fatalf("Invalid TLS result: %v", err)
		}

		t.Logf("Nginx 1.2.9 TLS 1.2 ECDHE successful: Cipher=%s Curve=%s",
			GetCipherName(result.Cipher),
			GetCurveName(result.CurveID),
		)
	})

	t.Run("DHE", func(t *testing.T) {
		ciphers := []uint16{
			ftls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
			ftls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			ftls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
			ftls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		}
		curves := []ftls.CurveID{ftls.CurveP256}

		result, err := simulator.PerformTLSHandshake(
			ftls.VersionTLS12,
			ciphers,
			curves,
			Nginx129_TLS12_Addr,
		)

		if err != nil {
			t.Fatalf("TLS 1.2 DHE handshake failed on Nginx 1.2.9: %v", err)
		}

		if err := ValidateTLSResult(result, ftls.VersionTLS12); err != nil {
			t.Fatalf("Invalid TLS result: %v", err)
		}

		t.Logf("Nginx 1.2.9 TLS 1.2 DHE successful: Cipher=%s",
			GetCipherName(result.Cipher),
		)
	})
}

// TestNginx129_TLS10_To_TLS12 tests Nginx 1.2.9 (OpenSSL 1.0.1f) with TLS 1.0–1.2 (port 4443).
func TestNginx129_TLS10_To_TLS12(t *testing.T) {
	protocols := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.2", ftls.VersionTLS12},
		{"TLS 1.1", ftls.VersionTLS11},
		{"TLS 1.0", ftls.VersionTLS10},
	}

	curves := []ftls.CurveID{ftls.CurveP256}

	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			var ciphers []uint16
			if p.version == ftls.VersionTLS10 || p.version == ftls.VersionTLS11 {
				ciphers = []uint16{
					ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					ftls.TLS_RSA_WITH_AES_128_CBC_SHA,
				}
			} else {
				ciphers = []uint16{
					ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				}
			}

			result, err := simulator.PerformTLSHandshake(
				p.version,
				ciphers,
				curves,
				Nginx129_TLS10_TLS12_Addr,
			)

			if err != nil {
				t.Fatalf("%s handshake failed on Nginx 1.2.9: %v", p.name, err)
			}

			if result.ServerHello == nil {
				t.Fatalf("%s ServerHello is nil", p.name)
			}

			t.Logf("Nginx 1.2.9 [%s] handshake successful: Protocol=%s Cipher=%s",
				p.name,
				GetProtocolName(result.Protocol),
				GetCipherName(result.Cipher),
			)
		})
	}
}

// TestNginx129_SSLv2_To_TLS12 tests Nginx 1.2.9 (OpenSSL 1.0.1f) configured for SSLv2–TLS 1.2 (port 5443).
// Tests SSL 3.0, TLS 1.0, TLS 1.1, and TLS 1.2.
func TestNginx129_SSLv2_To_TLS12(t *testing.T) {
	protocols := []struct {
		name    string
		version uint16
		ciphers []uint16
	}{
		{
			name:    "TLS 1.2",
			version: ftls.VersionTLS12,
			ciphers: []uint16{
				ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		{
			name:    "TLS 1.1",
			version: ftls.VersionTLS11,
			ciphers: []uint16{
				ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				ftls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			name:    "TLS 1.0",
			version: ftls.VersionTLS10,
			ciphers: []uint16{
				ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				ftls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			name:    "SSL 3.0",
			version: ftls.VersionSSL30,
			ciphers: []uint16{
				ftls.TLS_RSA_WITH_AES_128_CBC_SHA,
				ftls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				ftls.TLS_RSA_WITH_RC4_128_SHA,
			},
		},
	}

	curves := []ftls.CurveID{ftls.CurveP256}

	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			result, err := simulator.PerformTLSHandshake(
				p.version,
				p.ciphers,
				curves,
				Nginx129_SSLv2_TLS12_Addr,
			)

			if err != nil {
				t.Fatalf("%s handshake failed on Nginx 1.2.9 sslv2-tls12: %v", p.name, err)
			}

			if err := ValidateTLSResult(result, p.version); err != nil {
				t.Fatalf("Invalid TLS result for %s: %v", p.name, err)
			}

			t.Logf("Nginx 1.2.9 SSLv2-TLS1.2 container [%s] handshake successful: Protocol=%s Cipher=%s",
				p.name,
				GetProtocolName(result.Protocol),
				GetCipherName(result.Cipher),
			)
		})
	}
}

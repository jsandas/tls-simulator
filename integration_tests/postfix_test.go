//go:build integration

package integrationtests

import (
	"crypto/tls"
	"testing"

	simulator "github.com/jsandas/tls-simulator"
	"github.com/jsandas/tls-simulator/ftls"
)

// TestPostfix_Port25_STARTTLS tests STARTTLS connection to Postfix on port 25.
func TestPostfix_Port25_STARTTLS(t *testing.T) {
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	result, err := simulator.PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		Postfix_Port25_Addr,
	)

	if err != nil {
		t.Fatalf("Postfix port 25 STARTTLS handshake failed: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS12); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	if err := ValidateCipher(result, ciphers); err != nil {
		t.Errorf("Cipher validation failed: %v", err)
	}

	t.Logf("Postfix STARTTLS (port 25) handshake successful: Protocol=%s Cipher=%s Curve=%s",
		GetProtocolName(result.Protocol),
		GetCipherName(result.Cipher),
		GetCurveName(result.CurveID),
	)
}

// TestPostfix_Port587_STARTTLS tests STARTTLS connection to Postfix on port 587.
func TestPostfix_Port587_STARTTLS(t *testing.T) {
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	result, err := simulator.PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		Postfix_Port587_Addr,
	)

	if err != nil {
		t.Fatalf("Postfix port 587 STARTTLS handshake failed: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS12); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	if err := ValidateCipher(result, ciphers); err != nil {
		t.Errorf("Cipher validation failed: %v", err)
	}

	t.Logf("Postfix STARTTLS (port 587) handshake successful: Protocol=%s Cipher=%s Curve=%s",
		GetProtocolName(result.Protocol),
		GetCipherName(result.Cipher),
		GetCurveName(result.CurveID),
	)
}

//go:build integration

package integrationtests

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/jsandas/tls-simulator/ftls"
	"github.com/jsandas/tls-simulator/simulator"
)

// TestMariaDB_TLS tests TLS handshake connection to MariaDB (port 3306).
func TestMariaDB_TLS(t *testing.T) {
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	var result *simulator.TLSHandshakeResult
	var err error

	// Retry up to 5 attempts to allow MariaDB engine initialization after container startup
	for attempt := 1; attempt <= 5; attempt++ {
		result, err = simulator.PerformTLSHandshake(
			tls.VersionTLS12,
			ciphers,
			curves,
			MariaDB_Addr,
		)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		t.Fatalf("MariaDB TLS handshake failed after retries: %v", err)
	}

	if err := ValidateTLSResult(result, tls.VersionTLS12); err != nil {
		t.Fatalf("Invalid TLS result: %v", err)
	}

	if err := ValidateCipher(result, ciphers); err != nil {
		t.Errorf("Cipher validation failed: %v", err)
	}

	t.Logf("MariaDB TLS handshake successful: Protocol=%s Cipher=%s Curve=%s",
		GetProtocolName(result.Protocol),
		GetCipherName(result.Cipher),
		GetCurveName(result.CurveID),
	)
}

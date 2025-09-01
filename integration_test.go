//go:build integration
// +build integration

package main

import (
	"crypto/tls"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jsandas/tls-simulator/ftls"
)

const (
	nginxGoodAddr   = "localhost:443"
	nginxBadAddr    = "localhost:8443"
	postfixPort25   = "localhost:25"
	postfixPort587  = "localhost:587"
	mariadbGoodAddr = "localhost:3306"
)

// TestSetup ensures the docker containers are running.
func TestSetup(t *testing.T) {
	// Start docker compose services
	cmd := exec.Command("docker", "compose", "up", "-d")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to start docker compose services: %v", err)
	}

	// Wait for services to be ready
	time.Sleep(5 * time.Second)

	t.Log("Docker services started successfully")
}

// TestTLS13WithChacha20Poly1305 tests TLS 1.3 with specific cipher suite.
func TestTLS13WithChacha20Poly1305(t *testing.T) {
	// Define specific cipher suite for TLS 1.3
	ciphers := []uint16{
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS13,
		ciphers,
		curves,
		nginxGoodAddr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS13) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS13, result.Protocol)
	}

	// Check cipher suite
	expectedCipher := tls.TLS_CHACHA20_POLY1305_SHA256
	if result.Cipher != expectedCipher {
		t.Errorf("Expected cipher suite 0x%04x, got 0x%04x", expectedCipher, result.Cipher)
	}

	// Check curve ID (should be one of the offered curves)
	if result.CurveID == 0 {
		t.Error("Expected curve ID to be set")
	}

	// Verify curve is one of the offered curves
	validCurve := false
	for _, curve := range curves {
		if result.CurveID == curve {
			validCurve = true
			break
		}
	}
	if !validCurve {
		t.Errorf("Curve ID 0x%04x is not one of the offered curves", result.CurveID)
	}

	t.Logf("TLS 1.3 handshake successful with CHACHA20_POLY1305_SHA256")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestTLS13WithDefaultCiphers tests TLS 1.3 with default cipher suites.
func TestTLS13WithDefaultCiphers(t *testing.T) {
	// Use empty cipher list to trigger default ciphers
	var ciphers []uint16

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
		ftls.CurveP521,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS13,
		ciphers,
		curves,
		nginxGoodAddr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS13) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS13, result.Protocol)
	}

	// Check that a cipher suite was negotiated
	if result.Cipher == 0 {
		t.Error("Expected cipher suite to be negotiated")
	}

	// Verify the negotiated cipher is a valid TLS 1.3 cipher
	validTLS13Ciphers := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
	}

	if !validTLS13Ciphers[result.Cipher] {
		t.Errorf("Negotiated cipher 0x%04x is not a valid TLS 1.3 cipher", result.Cipher)
	}

	// Check curve ID
	if result.CurveID == 0 {
		t.Error("Expected curve ID to be set")
	}

	t.Logf("TLS 1.3 handshake successful with default ciphers")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestTLS12WithECDHE tests TLS 1.2 with ECDHE cipher suites.
func TestTLS12WithECDHE(t *testing.T) {
	// Define ECDHE cipher suites for TLS 1.2
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		nginxGoodAddr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS12) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS12, result.Protocol)
	}

	// Check that a cipher suite was negotiated
	if result.Cipher == 0 {
		t.Error("Expected cipher suite to be negotiated")
	}

	// Verify the negotiated cipher is one of the offered ECDHE ciphers
	validCipher := false
	for _, cipher := range ciphers {
		if result.Cipher == cipher {
			validCipher = true
			break
		}
	}
	if !validCipher {
		t.Errorf("Negotiated cipher 0x%04x is not one of the offered ciphers", result.Cipher)
	}

	// Check curve ID
	if result.CurveID == 0 {
		t.Error("Expected curve ID to be set")
	}

	t.Logf("TLS 1.2 handshake successful with ECDHE")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestTLS12WithDHE tests TLS 1.2 with DHE cipher suites.
func TestTLS12WithDHE(t *testing.T) {
	// Define DHE cipher suites for TLS 1.2
	ciphers := []uint16{
		ftls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		ftls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	// Define elliptic curves (not used for DHE, but required parameter)
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		nginxBadAddr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS12) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS12, result.Protocol)
	}

	// Check that a cipher suite was negotiated
	if result.Cipher == 0 {
		t.Error("Expected cipher suite to be negotiated")
	}

	// For DHE, we might not get a curve ID since it's not ECDHE
	// But we should still get a successful handshake
	t.Logf("TLS 1.2 handshake successful with DHE")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestNginxBadContainer tests connection to the nginx_bad container.
func TestNginxBadContainer(t *testing.T) {
	// Define cipher suites
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		nginxBadAddr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check that a cipher suite was negotiated
	if result.Cipher == 0 {
		t.Error("Expected cipher suite to be negotiated")
	}

	t.Logf("TLS handshake successful with nginx_bad container")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestMultipleCurves tests that different curves can be negotiated.
func TestMultipleCurves(t *testing.T) {
	testCases := []struct {
		name   string
		curves []ftls.CurveID
	}{
		{
			name: "X25519 only",
			curves: []ftls.CurveID{
				ftls.X25519,
			},
		},
		{
			name: "P-256 only",
			curves: []ftls.CurveID{
				ftls.CurveP256,
			},
		},
		{
			name: "P-384 only",
			curves: []ftls.CurveID{
				ftls.CurveP384,
			},
		},
		{
			name: "P-521 only",
			curves: []ftls.CurveID{
				ftls.CurveP521,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Define cipher suites
			ciphers := []uint16{
				ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			}

			// Perform TLS handshake
			result, err := PerformTLSHandshake(
				tls.VersionTLS12,
				ciphers,
				tc.curves,
				nginxGoodAddr,
			)

			if err != nil {
				t.Fatalf("TLS handshake failed: %v", err)
			}

			// Verify results
			if result.ServerHello == nil {
				t.Fatal("ServerHello is nil")
			}

			// Check that the negotiated curve is one of the offered curves
			validCurve := false
			for _, curve := range tc.curves {
				if result.CurveID == curve {
					validCurve = true
					break
				}
			}
			if !validCurve {
				t.Errorf("Negotiated curve 0x%04x is not one of the offered curves", result.CurveID)
			}

			t.Logf("Successfully negotiated curve 0x%04x", result.CurveID)
		})
	}
}

// TestPostfixPort25STARTTLS tests STARTTLS connection to Postfix on port 25.
func TestPostfixPort25STARTTLS(t *testing.T) {
	// Define cipher suites for TLS 1.2 (Postfix typically uses TLS 1.2)
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		postfixPort25,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS12) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS12, result.Protocol)
	}

	// Verify cipher suite is one of the offered ones
	validCipher := false
	for _, cipher := range ciphers {
		if result.Cipher == cipher {
			validCipher = true
			break
		}
	}
	if !validCipher {
		t.Errorf("Negotiated cipher 0x%04x is not one of the offered ciphers", result.Cipher)
	}

	t.Logf("Postfix STARTTLS (port 25) handshake successful")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestPostfixPort587STARTTLS tests STARTTLS connection to Postfix on port 587.
func TestPostfixPort587STARTTLS(t *testing.T) {
	// Define cipher suites for TLS 1.2
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		postfixPort587,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS12) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS12, result.Protocol)
	}

	// Verify cipher suite is one of the offered ones
	validCipher := false
	for _, cipher := range ciphers {
		if result.Cipher == cipher {
			validCipher = true
			break
		}
	}
	if !validCipher {
		t.Errorf("Negotiated cipher 0x%04x is not one of the offered ciphers", result.Cipher)
	}

	t.Logf("Postfix STARTTLS (port 587) handshake successful")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestMariaDBTLS tests TLS connection to MariaDB.
func TestMariaDBTLS(t *testing.T) {
	// Define cipher suites for TLS 1.2 (MariaDB commonly uses TLS 1.2)
	ciphers := []uint16{
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		// Include some fallback ciphers that MariaDB might use
		ftls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	// Define elliptic curves
	curves := []ftls.CurveID{
		ftls.X25519,
		ftls.CurveP256,
		ftls.CurveP384,
	}

	// Perform TLS handshake
	result, err := PerformTLSHandshake(
		tls.VersionTLS12,
		ciphers,
		curves,
		mariadbGoodAddr,
	)

	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify results
	if result.ServerHello == nil {
		t.Fatal("ServerHello is nil")
	}

	// Check protocol version
	if result.Protocol != int(tls.VersionTLS12) {
		t.Errorf("Expected protocol version %d, got %d", tls.VersionTLS12, result.Protocol)
	}

	// Verify cipher suite is one of the offered ones
	validCipher := false
	for _, cipher := range ciphers {
		if result.Cipher == cipher {
			validCipher = true
			break
		}
	}
	if !validCipher {
		t.Errorf("Negotiated cipher 0x%04x is not one of the offered ciphers", result.Cipher)
	}

	// Log the successful connection details
	t.Logf("MariaDB TLS handshake successful")
	t.Logf("Protocol: %d", result.Protocol)
	t.Logf("Cipher: 0x%04x", result.Cipher)
	t.Logf("Curve: 0x%04x", result.CurveID)
}

// TestCleanup stops the docker containers.
func TestCleanup(t *testing.T) {
	// Stop docker compose services
	cmd := exec.Command("docker", "compose", "down")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Logf("Failed to stop docker compose services: %v", err)
	} else {
		t.Log("Docker services stopped successfully")
	}
}

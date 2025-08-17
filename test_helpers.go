package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/jsandas/tls-simulator/ftls"
)

// TestConfig holds configuration for integration tests.
type TestConfig struct {
	ServerAddr string
	Protocol   uint16
	Ciphers    []uint16
	Curves     []ftls.CurveID
	Timeout    time.Duration
}

// DefaultTestConfig returns a default test configuration.
func DefaultTestConfig() TestConfig {
	return TestConfig{
		ServerAddr: "localhost:443",
		Protocol:   tls.VersionTLS12,
		Ciphers:    []uint16{},
		Curves:     []ftls.CurveID{ftls.X25519, ftls.CurveP256},
		Timeout:    10 * time.Second,
	}
}

// WaitForServer waits for the server to be ready.
func WaitForServer(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			if cerr := conn.Close(); cerr != nil {
				return fmt.Errorf("failed to close connection: %v", cerr)
			}
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("server at %s not ready after %v", addr, timeout)
}

// ValidateTLSResult validates the basic structure of a TLS handshake result.
func ValidateTLSResult(result *TLSHandshakeResult, expectedProtocol uint16) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}

	if result.ServerHello == nil {
		return fmt.Errorf("ServerHello is nil")
	}

	if result.Protocol != int(expectedProtocol) {
		return fmt.Errorf("expected protocol %d, got %d", expectedProtocol, result.Protocol)
	}

	if result.Cipher == 0 {
		return fmt.Errorf("no cipher suite negotiated")
	}

	return nil
}

// ValidateCurve validates that the negotiated curve is one of the offered curves.
func ValidateCurve(result *TLSHandshakeResult, offeredCurves []ftls.CurveID) error {
	if result.CurveID == 0 {
		return fmt.Errorf("no curve negotiated")
	}

	for _, curve := range offeredCurves {
		if result.CurveID == curve {
			return nil
		}
	}

	return fmt.Errorf("negotiated curve 0x%04x is not one of the offered curves", result.CurveID)
}

// ValidateCipher validates that the negotiated cipher is one of the offered ciphers.
func ValidateCipher(result *TLSHandshakeResult, offeredCiphers []uint16) error {
	for _, cipher := range offeredCiphers {
		if result.Cipher == cipher {
			return nil
		}
	}

	return fmt.Errorf("negotiated cipher 0x%04x is not one of the offered ciphers", result.Cipher)
}

// ValidateTLS13Cipher validates that the negotiated cipher is a valid TLS 1.3 cipher.
func ValidateTLS13Cipher(result *TLSHandshakeResult) error {
	validTLS13Ciphers := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
	}

	if !validTLS13Ciphers[result.Cipher] {
		return fmt.Errorf("negotiated cipher 0x%04x is not a valid TLS 1.3 cipher", result.Cipher)
	}

	return nil
}

// GetCipherName returns a human-readable name for a cipher suite.
func GetCipherName(cipher uint16) string {
	if name, exists := cipherToName[cipher]; exists {
		return name
	}
	return fmt.Sprintf("0x%04x", cipher)
}

// GetCurveName returns a human-readable name for a curve ID.
func GetCurveName(curve ftls.CurveID) string {
	if name, exists := curveIDToName[curve]; exists {
		return name
	}
	return fmt.Sprintf("0x%04x", curve)
}

// GetProtocolName returns a human-readable name for a protocol version.
func GetProtocolName(protocol int) string {
	if name, exists := protocolToName[protocol]; exists {
		return name
	}
	return fmt.Sprintf("%d", protocol)
}

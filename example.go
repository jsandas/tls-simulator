package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/jsandas/tls-simulator/ftls"
)

func main() {
	// Example 1: TLS 1.2 with ECDHE ciphers
	ciphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	curves := []ftls.CurveID{ftls.X25519, ftls.CurveP256, ftls.CurveP384, ftls.CurveP521}

	result, err := PerformTLSHandshake(tls.VersionTLS12, ciphers, curves, "localhost:443")
	if err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	fmt.Printf("=== TLS Handshake Result ===\n")
	fmt.Printf("ServerHello: %+v\n", result.ServerHello)
	if result.KeyType != "" {
		fmt.Printf("Key Type: %s\n", result.KeyType)
		fmt.Printf("Key Size: %d bytes\n", result.KeySize)
		if result.CurveID != 0 {
			fmt.Printf("Curve ID: 0x%04x\n", result.CurveID)
		}
	}
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
	}

	// Example 2: TLS 1.3 with modern ciphers
	ciphersTLS13 := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
	}

	result2, err := PerformTLSHandshake(tls.VersionTLS13, ciphersTLS13, curves, "localhost:443")
	if err != nil {
		log.Printf("TLS 1.3 handshake failed: %v", err)
		return
	}

	fmt.Printf("\n=== TLS 1.3 Handshake Result ===\n")
	fmt.Printf("ServerHello: %+v\n", result2.ServerHello)
	if result2.KeyType != "" {
		fmt.Printf("Key Type: %s\n", result2.KeyType)
		fmt.Printf("Key Size: %d bytes\n", result2.KeySize)
		if result2.CurveID != 0 {
			fmt.Printf("Curve ID: 0x%04x\n", result2.CurveID)
		}
	}
	if result2.Error != nil {
		fmt.Printf("Error: %v\n", result2.Error)
	}
}

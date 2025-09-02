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
		ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		ftls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}

	curves := []ftls.CurveID{ftls.X25519, ftls.CurveP256, ftls.CurveP384, ftls.CurveP521}

	result, err := PerformTLSHandshake(tls.VersionTLS12, ciphers, curves, "localhost:443")
	if err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	fmt.Printf("=== TLS Handshake Result ===\n")
	fmt.Printf("ServerHello: %+v\n", result.ServerHello)
	if result.Protocol != 0 {
		fmt.Printf("Protocol Version: %d : %s\n", result.Protocol, ftls.ProtocolToName[result.Protocol])
	}
	if result.Cipher != 0 {
		fmt.Printf("Cipher Suite: 0x%04x : %s\n", result.Cipher, ftls.CipherToName[result.Cipher])
	}
	if result.CurveID != 0 {
		fmt.Printf("Curve ID: 0x%04x : %s\n", result.CurveID, ftls.CurveIDToName[result.CurveID])
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
	if result2.Protocol != 0 {
		fmt.Printf("Protocol Version: %d : %s\n", result2.Protocol, ftls.ProtocolToName[result2.Protocol])
	}
	if result2.Cipher != 0 {
		fmt.Printf("Cipher Suite: 0x%04x : %s\n", result2.Cipher, ftls.CipherToName[result2.Cipher])
	}
	if result2.CurveID != 0 {
		fmt.Printf("Curve ID: 0x%04x : %s\n", result2.CurveID, ftls.CurveIDToName[result2.CurveID])
	}
	if result2.Error != nil {
		fmt.Printf("Error: %v\n", result2.Error)
	}
}

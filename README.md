# TLS Simulator

A Go module for performing TLS handshakes and analyzing cryptographic parameters used in TLS connections.

## Features

- **TLS Handshake Simulation**: Perform TLS handshakes with custom parameters
- **Protocol Version Detection**: Identify negotiated TLS protocol version
- **Cipher Suite Analysis**: Determine the selected cipher suite from the handshake
- **Key Exchange Analysis**: Identify elliptic curves used for ECDHE and DH key exchange parameters
- **Comprehensive Support**: TLS 1.0, 1.1, 1.2, and 1.3 support with various cipher suites

## Installation

```bash
go get github.com/jsandas/tls-simulator
```

## Usage

### Basic Usage

```go
package main

import (
    "crypto/tls"
    "fmt"
    "log"

    "github.com/jsandas/tls-simulator/ftls"
)

func main() {
    // Define cipher suites to offer
    ciphers := []uint16{
        ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ftls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ftls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    }

    // Define elliptic curves to support
    curves := []ftls.CurveID{
        ftls.X25519,
        ftls.CurveP256,
        ftls.CurveP384,
        ftls.CurveP521,
    }

    // Perform TLS handshake
    result, err := PerformTLSHandshake(
        ftls.VersionTLS12,  // Protocol version
        ciphers,           // Cipher suites
        curves,            // Elliptic curves
        "localhost:443",   // Server address
    )
    if err != nil {
        log.Fatalf("TLS handshake failed: %v", err)
    }

    // Analyze results
    fmt.Printf("ServerHello: %+v\n", result.ServerHello)
    if result.Protocol != 0 {
        fmt.Printf("Protocol Version: %d\n", result.Protocol)
    }
    if result.Cipher != 0 {
        fmt.Printf("Cipher Suite: 0x%04x\n", result.Cipher)
    }
    if result.CurveID != 0 {
        fmt.Printf("Curve ID: 0x%04x\n", result.CurveID)
    }
    if result.Error != nil {
        fmt.Printf("Error: %v\n", result.Error)
    }
    
    // For detailed key exchange analysis, access ServerHello.ServerShare
    if result.ServerHello != nil && result.ServerHello.ServerShare.Group != 0 {
        fmt.Printf("Key Exchange Group: 0x%04x\n", result.ServerHello.ServerShare.Group)
    }
}
```

### Analysis Capabilities

The module can identify and analyze:

#### Protocol Information
- **TLS Version**: The negotiated protocol version (TLS 1.0, 1.1, 1.2, or 1.3)
- **Cipher Suite**: The selected cipher suite from the offered list

#### Key Exchange Analysis
- **ECDHE Curves**: Identifies the elliptic curve used for ECDHE key exchange
  - **X25519**: Curve25519 for high-performance implementations
  - **P-256**: NIST P-256 curve (secp256r1)
  - **P-384**: NIST P-384 curve (secp384r1)  
  - **P-521**: NIST P-521 curve (secp521r1)

- **DH (Finite Field Diffie-Hellman)**: Identifies DH key exchange parameters
  - **DH-1024**: 1024-bit keys (legacy, not in RFC 7919)
  - **DH-2048**: 2048-bit keys (ffdhe2048, RFC 7919)
  - **DH-3072**: 3072-bit keys (ffdhe3072, RFC 7919)
  - **DH-4096**: 4096-bit keys (ffdhe4096, RFC 7919)
  - **DH-6144**: 6144-bit keys (ffdhe6144, RFC 7919)
  - **DH-8192**: 8192-bit keys (ffdhe8192, RFC 7919)

## API Reference

### `PerformTLSHandshake`

```go
func PerformTLSHandshake(
    protocolVer uint16,           // TLS protocol version
    ciphers []uint16,             // Cipher suites to offer
    curves []ftls.CurveID,        // Elliptic curves to support
    serverAddr string,            // Server address (host:port)
) (*TLSHandshakeResult, error)
```

### `TLSHandshakeResult`

```go
type TLSHandshakeResult struct {
    ServerHello *ftls.ServerHelloMsg  // Parsed ServerHello message
    Protocol    int                   // Negotiated protocol version
    Cipher      uint16                // Negotiated cipher suite
    CurveID     ftls.CurveID         // Curve ID for ECDHE key exchange
    Error       error                 // Any parsing errors
}
```

## Examples

Run the example:

```bash
go run example.go
```

## Building

```bash
go build
```

## Dependencies

- `golang.org/x/crypto`: For cryptographic operations
- `crypto/tls`: For TLS constants and types

## License

This project is licensed under the MIT License.


# TLS Simulator

A Go module for performing TLS handshakes and analyzing cryptographic parameters used in TLS connections.

## Features

- **TLS Handshake Simulation**: Perform TLS handshakes with custom parameters
- **Key Exchange Analysis**: Identify and analyze key exchange methods (ECDHE, DH)
- **Cipher Suite Support**: Support for various cipher suites and elliptic curves
- **Protocol Version Support**: TLS 1.0, 1.1, 1.2, and 1.3 support

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
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
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
        tls.VersionTLS12,  // Protocol version
        ciphers,           // Cipher suites
        curves,            // Elliptic curves
        "localhost:443",   // Server address
    )
    if err != nil {
        log.Fatalf("TLS handshake failed: %v", err)
    }

    // Analyze results
    fmt.Printf("ServerHello: %+v\n", result.ServerHello)
    if result.KeyType != "" {
        fmt.Printf("Key Type: %s\n", result.KeyType)
        fmt.Printf("Key Size: %d bytes\n", result.KeySize)
        if result.CurveID != 0 {
            fmt.Printf("Curve ID: 0x%04x\n", result.CurveID)
        }
    }
}
```

### Supported Key Exchange Types

The module can identify and analyze:

#### ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
- **X25519**: 32-byte keys
- **P-256**: 32-byte keys  
- **P-384**: 48-byte keys
- **P-521**: 66-byte keys

#### DH (Finite Field Diffie-Hellman)
- **DH-1024**: 1024-bit keys
- **DH-2048**: 2048-bit keys
- **ffdhe2048 (RFC 7919)**: Standardized 2048-bit group
- **ffdhe3072 (RFC 7919)**: Standardized 3072-bit group
- **ffdhe4096 (RFC 7919)**: Standardized 4096-bit group
- **ffdhe6144 (RFC 7919)**: Standardized 6144-bit group
- **ffdhe8192 (RFC 7919)**: Standardized 8192-bit group

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
    KeyType     string                // Key exchange type (e.g., "X25519", "ffdhe2048")
    KeySize     int                   // Key size in bytes
    CurveID     ftls.CurveID         // Curve ID for ECDHE
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


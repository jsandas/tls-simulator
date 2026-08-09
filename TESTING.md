# Testing Guide

This document describes how to run the unit and integration tests for the TLS Simulator module.

## Prerequisites

- Go 1.25 or later
- Docker and Docker Compose (required only for integration tests)
- Target containers defined in `integration_tests/docker-compose.yml`

## Test Structure

### Unit Tests

Unit tests reside within their respective packages:

- **Simulator Unit Tests** (`simulator/simulator_test.go`): Tests handshake orchestration (`PerformTLSHandshake`), ClientHello formatting, record construction, response parsing, message extraction, and network timeout handling.
- **FTLS Message Tests** (`ftls/handshake_messages_test.go`): Tests marshaling and unmarshaling of TLS handshake messages (`ServerHello`, `Finished`, `ServerKeyExchange`).

### Integration Tests

The integration tests reside in the `integration_tests/` directory:

- **Setup & Teardown** (`setup_test.go`): Manages starting and stopping docker compose containers and waiting for service health
- **Nginx 1.30.0 Tests** (`nginx_1_30_0_test.go`): Tests TLS 1.3/1.2 negotiation, ciphers, curves, and version constraints across Nginx 1.30.0 containers
- **Nginx 1.2.9 Tests** (`nginx_1_2_9_test.go`): Tests legacy TLS 1.0–1.2 and SSLv2 configurations on Nginx 1.2.9 with OpenSSL 1.0.1f
- **Postfix STARTTLS Tests** (`postfix_test.go`): Tests SMTP STARTTLS negotiation on ports 25 and 587
- **MariaDB TLS Tests** (`mariadb_test.go`): Tests MySQL/MariaDB TLS connection on port 3306
- **Test Helpers** (`test_helpers.go` in root package `simulator`): Utility functions for test validation and string formatting

## Simulator Package Unit Tests (`simulator/simulator_test.go`)

### `TestPerformTLSHandshake`

Main entrypoint test for `PerformTLSHandshake`. Uses in-memory TCP mock servers to test network interaction and response processing.

- **`invalid server address format`**: Verifies error returned when target address string is malformed (missing port).
- **`connection refused`**: Validates error handling when connecting to a closed or unreachable TCP port.
- **`valid TLS 1.2 handshake`**: Tests TLS 1.2 handshake flow against an in-memory TCP mock server, verifying `Protocol` & `Cipher`.
- **`valid TLS 1.3 handshake`**: Tests TLS 1.3 handshake flow, verifying supported version extensions and `KeyShare` curve parsing (`X25519`).
- **`handshake with server key exchange`**: Verifies parsing when server responds with combined `ServerHello` + `ServerKeyExchange` records.
- **`server sends invalid response`**: Validates error handling when server returns non-TLS formatted data.
- **`server sends no data timeout`**: Verifies error handling when server accepts connection but times out without sending data.

### `TestBuildClientHello`

Tests construction of `ftls.ClientHelloMsg` with default and custom parameters.

- **`TLS 1.2 defaults`**: Ensures default TLS 1.2 ciphers and curves are populated when empty slices are passed.
- **`TLS 1.3 defaults`**: Ensures `SupportedVersions` array and TLS 1.3 default ciphers are populated for TLS 1.3.
- **`custom ciphers and curves`**: Confirms custom cipher suite slices and curve ID lists override defaults.

### `TestCreateTLSRecord`

Tests wrapping raw handshake payload bytes into a standard 5-byte TLS record header.

- **`valid message`**: Validates header byte assembly (`0x16 0x03 0x03` + 2-byte length) for valid handshake bytes.
- **`message too large`**: Verifies error returned when payload length exceeds 65,535 bytes.

### `TestParseServerResponse`

Tests parsing `ServerHello` and `ServerKeyExchange` byte buffers into a `TLSHandshakeResult`.

- **`nil ServerHello`**: Confirms error returned if `serverHelloBytes` is `nil`.
- **`unmarshal ServerHello failure`**: Confirms error returned if `serverHelloBytes` contains malformed data.
- **`valid ServerHello without key exchange`**: Verifies field mapping (`Protocol`, `Cipher`) for a standard `ServerHello` message.
- **`unmarshal ServerKeyExchange failure`**: Verifies error returned when `serverKeyExchangeBytes` length < 4 bytes.
- **`ServerKeyExchange GetKey error`**: Ensures `result.Error` is set when key/curve extraction from `ServerKeyExchange` fails.

### `TestGetHandshakeMessages`

Tests extracting `ServerHello` and `ServerKeyExchange` handshake payloads from TLS record streams.

- **`no handshake messages found`**: Verifies error returned when record contains non-handshake types (e.g. Alert records).
- **`valid ServerHello message extracted`**: Verifies extraction of a single `ServerHello` handshake message from a TLS record.
- **`truncated record data`**: Verifies error handling when header length exceeds available buffer length.

### `TestIsTimeoutError`

Tests helper function checking `net.Error.Timeout()`.

- **`net error with timeout true`**: Confirms `isTimeoutError` returns `true` for a mock `net.Error` with `Timeout() == true`.
- **`net error with timeout false`**: Confirms `isTimeoutError` returns `false` for a mock `net.Error` with `Timeout() == false`.
- **`standard non-net error`**: Confirms `isTimeoutError` returns `false` for standard Go `error` objects.

## Running Tests

### Quick Start

```bash
# Run all tests (quality checks + integration tests)
make test

# Run only integration tests
make test-integration

# Run unit tests
make test-unit
```

### Individual Service Test Targets

```bash
# Test Nginx 1.30.0 containers
make test-nginx-1-30-0

# Test Nginx 1.2.9 containers
make test-nginx-1-2-9

# Test Postfix STARTTLS
make test-postfix

# Test MariaDB TLS
make test-mariadb
```

### Manual Docker Control

```bash
# Start integration containers
make docker-up

# Stop integration containers
make docker-down
```

### Direct Go Test Commands

```bash
# Run simulator unit tests with coverage
go test -v -cover ./simulator/...

# Run all unit tests
go test -v ./...

# Run all integration tests
go test -v -tags integration ./integration_tests/...

# Run specific test file or scenario
go test -v -tags integration -run "^TestNginx1300_TLS13" ./integration_tests/...
```

## Test Configuration

Tests use containers defined in `integration_tests/docker-compose.yml`:

- **nginx_1.30.0_tls12-tls13**: `127.0.0.1:443` - TLS 1.2 + TLS 1.3
- **nginx_1.30.0_tls12**: `127.0.0.1:1443` - TLS 1.2 only
- **nginx_1.30.0_tls10-tls13**: `127.0.0.1:2443` - TLS 1.0 through TLS 1.3
- **nginx_1.2.9_tls12**: `127.0.0.1:3443` - TLS 1.2 with OpenSSL 1.0.1f
- **nginx_1.2.9_tls10-tls12**: `127.0.0.1:4443` - TLS 1.0 through TLS 1.2
- **nginx_1.2.9_sslv2-tls12**: `127.0.0.1:5443` - SSLv2 through TLS 1.2
- **postfix-2.11.0_sslv2-tls12**: `127.0.0.1:25` & `127.0.0.1:587` - STARTTLS ports
- **mariadb-12.3**: `127.0.0.1:3306` - MariaDB TLS port

## Test Validation

Each test validates:

- **Protocol Version**: Correct TLS version negotiation (`TLS 1.0`, `1.1`, `1.2`, `1.3`)
- **Cipher Suite**: Proper cipher suite selection matching client capabilities
- **Curve ID**: Valid elliptic curve negotiation (for ECDHE)
- **ServerHello**: Valid server response parsing

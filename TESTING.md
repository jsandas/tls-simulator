# Testing Guide

This document describes how to run the integration tests for the TLS Simulator module.

## Prerequisites

- Go 1.25 or later
- Docker and Docker Compose
- Target containers defined in `integration_tests/docker-compose.yml`

## Test Structure

The integration tests reside in the `integration_tests/` directory:

- **Setup & Teardown** (`setup_test.go`): Manages starting and stopping docker compose containers and waiting for service health
- **Nginx 1.30.0 Tests** (`nginx_1_30_0_test.go`): Tests TLS 1.3/1.2 negotiation, ciphers, curves, and version constraints across Nginx 1.30.0 containers
- **Nginx 1.2.9 Tests** (`nginx_1_2_9_test.go`): Tests legacy TLS 1.0–1.2 and SSLv2 configurations on Nginx 1.2.9 with OpenSSL 1.0.1f
- **Postfix STARTTLS Tests** (`postfix_test.go`): Tests SMTP STARTTLS negotiation on ports 25 and 587
- **MariaDB TLS Tests** (`mariadb_test.go`): Tests MySQL/MariaDB TLS connection on port 3306
- **Test Helpers** (`test_helpers.go` in root package `simulator`): Utility functions for test validation and string formatting

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

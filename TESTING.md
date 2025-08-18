# Testing Guide

This document describes how to run the integration tests for the TLS Simulator module.

## Prerequisites

- Go 1.24 or later
- Docker and Docker Compose
- The nginx containers defined in `docker-compose.yml`

## Test Structure

The test suite consists of:

- **Integration Tests** (`integration_test.go`): Tests that require running nginx containers
- **Test Helpers** (`test_helpers.go`): Utility functions for test validation and configuration

**Note**: Currently, all tests are integration tests that require Docker containers. Pure unit tests can be added in the future for testing individual functions without external dependencies.

## Running Tests

### Quick Start

```bash
# Run all tests (integration tests)
make test

# Run only integration tests
make test-integration

# Check unit test status
make test-unit
```

### Individual Test Targets

```bash
# Test TLS 1.3 with CHACHA20_POLY1305_SHA256
make test-tls13-chacha20

# Test TLS 1.3 with default cipher suites
make test-tls13-default
```

### Manual Docker Control

```bash
# Start nginx containers
make docker-up

# Stop nginx containers
make docker-down
```

### Direct Go Test Commands

```bash
# Run all tests
go test -v .

# Run only integration tests
go test -v -run "^Test(Setup|TLS|Nginx|Multiple|Cleanup)" .

# Run specific test
go test -v -run "^TestTLS13WithChacha20Poly1305$" .
```

## Test Cases

### TLS 1.3 Tests

1. **TestTLS13WithChacha20Poly1305**: Tests TLS 1.3 with the specific cipher suite `TLS_CHACHA20_POLY1305_SHA256`
2. **TestTLS13WithDefaultCiphers**: Tests TLS 1.3 with default cipher suites (empty cipher list)

### TLS 1.2 Tests

3. **TestTLS12WithECDHE**: Tests TLS 1.2 with ECDHE cipher suites
4. **TestTLS12WithDHE**: Tests TLS 1.2 with DHE cipher suites

### Container Tests

5. **TestNginxBadContainer**: Tests connection to the nginx_bad container
6. **TestMultipleCurves**: Tests negotiation of different elliptic curves

### Setup and Cleanup

7. **TestSetup**: Starts docker compose services
8. **TestCleanup**: Stops docker compose services

## Test Configuration

Tests use the following nginx containers:

- **nginx_good**: `localhost:443` - Good TLS configuration
- **nginx_bad**: `localhost:8443` - Bad TLS configuration

## Test Validation

Each test validates:

- **Protocol Version**: Correct TLS version negotiation
- **Cipher Suite**: Proper cipher suite selection
- **Curve ID**: Valid elliptic curve negotiation (for ECDHE)
- **ServerHello**: Valid server response structure

## Troubleshooting

### Common Issues

1. **Port already in use**: Make sure ports 443 and 8443 are available
   ```bash
   sudo lsof -i :443
   sudo lsof -i :8443
   ```

2. **Docker containers not starting**: Check docker compose logs
   ```bash
   docker compose logs
   ```

3. **Tests timing out**: Increase wait time in tests or check container health
   ```bash
   docker compose ps
   ```

### Debug Mode

Run tests with verbose output:

```bash
go test -v -run "^TestTLS13WithChacha20Poly1305$" .
```

### Manual Testing

Test the containers manually:

```bash
# Start containers
make docker-up

# Test with openssl
openssl s_client -connect localhost:443 -tls1_3 -cipher TLS_CHACHA20_POLY1305_SHA256

# Stop containers
make docker-down
```

## Adding New Tests

To add a new integration test:

1. Add the test function to `integration_test.go`
2. Use the helper functions from `test_helpers.go` for validation
3. Add a new make target if needed
4. Update this documentation

Example test structure:

```go
func TestNewFeature(t *testing.T) {
    config := DefaultTestConfig()
    config.Protocol = tls.VersionTLS12
    config.Ciphers = []uint16{ftls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
    
    result, err := PerformTLSHandshake(
        config.Protocol,
        config.Ciphers,
        config.Curves,
        config.ServerAddr,
    )
    
    if err != nil {
        t.Fatalf("TLS handshake failed: %v", err)
    }
    
    if err := ValidateTLSResult(result, config.Protocol); err != nil {
        t.Fatalf("Invalid TLS result: %v", err)
    }
    
    t.Logf("Test passed: %s", GetCipherName(result.Cipher))
}
```

#!/bin/bash

# TLS Simulator Integration Test Runner
# This script demonstrates how to run the integration tests

set -e

echo "=== TLS Simulator Integration Tests ==="
echo

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "Error: docker-compose is not installed or not in PATH"
    exit 1
fi

# Check if docker is running
if ! docker info &> /dev/null; then
    echo "Error: Docker is not running"
    exit 1
fi

echo "Starting nginx containers..."
make docker-up

echo "Waiting for services to be ready..."
sleep 5

echo "Running TLS 1.3 with CHACHA20_POLY1305_SHA256 test..."
if go test -v -run "^TestTLS13WithChacha20Poly1305$" .; then
    echo "✅ TLS 1.3 CHACHA20 test passed"
else
    echo "❌ TLS 1.3 CHACHA20 test failed"
fi

echo
echo "Running TLS 1.3 with default ciphers test..."
if go test -v -run "^TestTLS13WithDefaultCiphers$" .; then
    echo "✅ TLS 1.3 default ciphers test passed"
else
    echo "❌ TLS 1.3 default ciphers test failed"
fi

echo
echo "Running TLS 1.2 with ECDHE test..."
if go test -v -run "^TestTLS12WithECDHE$" .; then
    echo "✅ TLS 1.2 ECDHE test passed"
else
    echo "❌ TLS 1.2 ECDHE test failed"
fi

echo
echo "Running multiple curves test..."
if go test -v -run "^TestMultipleCurves$" .; then
    echo "✅ Multiple curves test passed"
else
    echo "❌ Multiple curves test failed"
fi

echo
echo "Stopping nginx containers..."
make docker-down

echo
echo "=== Test Summary ==="
echo "Integration tests completed. Check the output above for results."

#!/bin/bash

# TLS Simulator Integration Test Runner
# This script runs the refactored integration test suite

set -e

echo "=== TLS Simulator Integration Tests ==="
echo

# Check if docker compose is available
if ! command -v docker compose &> /dev/null; then
    echo "Error: docker compose is not installed or not in PATH"
    exit 1
fi

# Check if docker is running
if ! docker info &> /dev/null; then
    echo "Error: Docker is not running"
    exit 1
fi

echo "Starting docker containers..."
make docker-up

echo "Waiting for services to be ready..."
sleep 5

echo "Running Nginx 1.30.0 tests..."
if go test -v -tags integration -run "^TestNginx1300" ./integration_tests/...; then
    echo "✅ Nginx 1.30.0 tests passed"
else
    echo "❌ Nginx 1.30.0 tests failed"
fi

echo
echo "Running Nginx 1.2.9 tests..."
if go test -v -tags integration -run "^TestNginx129" ./integration_tests/...; then
    echo "✅ Nginx 1.2.9 tests passed"
else
    echo "❌ Nginx 1.2.9 tests failed"
fi

echo
echo "Running Postfix STARTTLS tests..."
if go test -v -tags integration -run "^TestPostfix" ./integration_tests/...; then
    echo "✅ Postfix STARTTLS tests passed"
else
    echo "❌ Postfix STARTTLS tests failed"
fi

echo
echo "Running MariaDB TLS tests..."
if go test -v -tags integration -run "^TestMariaDB" ./integration_tests/...; then
    echo "✅ MariaDB TLS tests passed"
else
    echo "❌ MariaDB TLS tests failed"
fi

echo
echo "Stopping docker containers..."
make docker-down

echo
echo "=== Test Summary ==="
echo "All integration tests completed successfully!"

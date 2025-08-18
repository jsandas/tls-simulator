.PHONY: test test-integration test-unit build clean docker-up docker-down

# Default target
all: build

# Build the TLS simulator
build:
	go build -o tls-simulator .

# Run all tests and quality checks
test: quality test-integration

# Run unit tests only
test-unit:
	@echo "No unit tests available yet - all tests are integration tests"
	@echo "Use 'make test-integration' to run the integration tests"

# Run integration tests (requires docker compose)
test-integration: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -run "^Test(Setup|TLS|Nginx|Multiple|Cleanup)" .
	@$(MAKE) docker-down

# Run specific integration test
test-tls13-chacha20: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -run "^TestTLS13WithChacha20Poly1305" .
	@$(MAKE) docker-down

test-tls13-default: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -run "^TestTLS13WithDefaultCiphers" .
	@$(MAKE) docker-down

# Start docker services
docker-up:
	docker compose up -d

# Stop docker services
docker-down:
	docker compose down

# Clean build artifacts
clean:
	rm -f tls-simulator
	go clean

# Run linting with golangci-lint
lint:
	golangci-lint run --timeout=5m

# Run linting with golangci-lint (install if not present)
lint-install:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run --timeout=5m

# Check code formatting
fmt-check:
	@if [ "$(shell gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted. Please run 'gofmt -s -w .'"; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@echo "Code formatting is correct"

# Format code
fmt:
	gofmt -s -w .

# Check go mod tidy
mod-check:
	@echo "Checking go.mod and go.sum..."
	@git diff --quiet go.mod go.sum || (echo "go.mod or go.sum has uncommitted changes. Please commit them first." && exit 1)
	go mod tidy
	@git diff --quiet go.mod go.sum || (echo "go.mod or go.sum is not tidy. Please run 'go mod tidy' and commit changes." && git diff go.mod go.sum && exit 1)
	@echo "Go modules are tidy"

# Run all code quality checks
quality: fmt-check mod-check lint
	@echo "All code quality checks passed!"

# Run example
example: build
	./tls-simulator

# Show help
help:
	@echo "Available targets:"
	@echo "  build              - Build the TLS simulator"
	@echo "  test               - Run all tests (integration tests)"
	@echo "  test-unit          - Show unit test status"
	@echo "  test-integration   - Run integration tests (requires docker)"
	@echo "  test-tls13-chacha20 - Run TLS 1.3 with CHACHA20 test"
	@echo "  test-tls13-default  - Run TLS 1.3 with default ciphers test"
	@echo "  docker-up          - Start docker services"
	@echo "  docker-down        - Stop docker services"
	@echo "  clean              - Clean build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  quality            - Run all code quality checks"
	@echo "  lint               - Run golangci-lint (requires golangci-lint)"
	@echo "  lint-install       - Install golangci-lint and run linting"
	@echo "  fmt-check          - Check code formatting"
	@echo "  fmt                - Format code with gofmt"
	@echo "  mod-check          - Check if go.mod is tidy"
	@echo ""
	@echo "Other:"
	@echo "  example            - Run the example"
	@echo "  help               - Show this help"

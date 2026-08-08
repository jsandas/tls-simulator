.PHONY: test test-integration test-unit build clean docker-up docker-down example quality fmt fmt-check go-mod-tidy lint lint-install help

COMPOSE_FILE = integration_tests/docker-compose.yml

# Default target
all: build

# Build the TLS simulator library and examples
build:
	go build ./...
	go build -o tls-simulator ./examples

# Run all tests and quality checks
test: quality test-integration

# Run unit tests only
test-unit:
	@go test -v ./ftls/...

# Run integration tests (requires docker compose)
test-integration: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -tags integration ./integration_tests/...
	@$(MAKE) docker-down

# Service-specific integration test targets
test-nginx-1-30-0: docker-up
	@sleep 5
	go test -v -tags integration -run "^TestNginx1300" ./integration_tests/...
	@$(MAKE) docker-down

test-nginx-1-2-9: docker-up
	@sleep 5
	go test -v -tags integration -run "^TestNginx129" ./integration_tests/...
	@$(MAKE) docker-down

test-postfix: docker-up
	@sleep 5
	go test -v -tags integration -run "^TestPostfix" ./integration_tests/...
	@$(MAKE) docker-down

test-mariadb: docker-up
	@sleep 5
	go test -v -tags integration -run "^TestMariaDB" ./integration_tests/...
	@$(MAKE) docker-down

# Start docker services
docker-up:
	docker compose -f $(COMPOSE_FILE) up -d

# Stop docker services
docker-down:
	docker compose -f $(COMPOSE_FILE) down

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
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
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

go-mod-tidy:
	@go mod tidy
	@if [ -n "$(shell git status --porcelain | egrep '(go.mod|go.sum)')" ]; then \
		echo "go.mod or go.sum is not tidy. Please run 'go mod tidy'"; \
		exit 1; \
	fi
	@echo "go.mod and go.sum are tidy"

# Format code
fmt:
	gofmt -s -w .

# Run all code quality checks
quality: fmt-check go-mod-tidy lint
	@echo "All code quality checks passed!"

# Run example
example: build
	./tls-simulator

# Show help
help:
	@echo "Available targets:"
	@echo "  build               - Build the TLS simulator library & example"
	@echo "  test                - Run all tests (quality checks + integration tests)"
	@echo "  test-unit           - Run unit tests"
	@echo "  test-integration    - Run all integration tests (requires docker)"
	@echo "  test-nginx-1-30-0   - Run Nginx 1.30.0 integration tests"
	@echo "  test-nginx-1-2-9    - Run Nginx 1.2.9 integration tests"
	@echo "  test-postfix        - Run Postfix STARTTLS integration tests"
	@echo "  test-mariadb        - Run MariaDB TLS integration tests"
	@echo "  docker-up           - Start integration docker containers"
	@echo "  docker-down         - Stop integration docker containers"
	@echo "  clean               - Clean build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  quality             - Run all code quality checks"
	@echo "  lint                - Run golangci-lint"
	@echo "  lint-install        - Install golangci-lint and run linting"
	@echo "  fmt-check           - Check code formatting"
	@echo "  fmt                 - Format code with gofmt"
	@echo "  go-mod-tidy         - Check if go.mod is tidy"
	@echo ""
	@echo "Other:"
	@echo "  example             - Run the example"
	@echo "  help                - Show this help"

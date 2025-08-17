.PHONY: test test-integration test-unit build clean docker-up docker-down

# Default target
all: build

# Build the TLS simulator
build:
	go build -o tls-simulator .

# Run all tests
test: test-integration

# Run unit tests only
test-unit:
	@echo "No unit tests available yet - all tests are integration tests"
	@echo "Use 'make test-integration' to run the integration tests"

# Run integration tests (requires docker-compose)
test-integration: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -run "^Test(Setup|TLS|Nginx|Multiple|Cleanup)" .
	@$(MAKE) docker-down

# Run specific integration test
test-tls13-chacha20: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -run "^TestTLS13WithChacha20Poly1305$" .
	@$(MAKE) docker-down

test-tls13-default: docker-up
	@echo "Waiting for services to be ready..."
	@sleep 5
	go test -v -run "^TestTLS13WithDefaultCiphers$" .
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
	@echo "  example            - Run the example"
	@echo "  help               - Show this help"

# GitHub Actions Workflows

This directory contains GitHub Actions workflows for the TLS Simulator project.

## Workflows

### 1. `test.yml` - Integration Tests (Primary)

**Triggers:**
- Pull requests to `main` or `master` branch
- Pushes to `main` or `master` branch

**Purpose:**
- Runs integration tests against nginx containers
- Ensures TLS handshake functionality works correctly
- Validates TLS 1.3 and TLS 1.2 protocol support

**Steps:**
1. Set up Go 1.24 environment
2. Set up Docker and Docker Compose using `docker/setup-docker-action`
3. Build the TLS simulator application
4. Run integration tests using `make test-integration`
5. Run specific TLS 1.3 tests
6. Clean up Docker containers

### 2. `ci.yml` - Comprehensive CI (Advanced)

**Triggers:**
- Pull requests to `main` or `master` branch
- Pushes to `main` or `master` branch

**Purpose:**
- Comprehensive CI pipeline including linting, security scanning, and testing
- Ensures code quality and security

**Jobs:**
1. **Lint and Format Check**
   - Runs golangci-lint with comprehensive rules
   - Checks code formatting with gofmt
   - Validates go.mod and go.sum are tidy

2. **Security Scan**
   - Runs gosec security scanner
   - Uploads SARIF results for GitHub security tab

3. **Integration Tests**
   - Same as `test.yml` but runs after linting passes

### 3. `scheduled-tests.yml` - Scheduled Tests

**Triggers:**
- Daily at 2 AM UTC (cron schedule)
- Manual trigger via workflow_dispatch

**Purpose:**
- Ensures nginx containers remain functional
- Catches infrastructure issues proactively
- Provides health monitoring for test environment

## Configuration

### Docker Compose
The workflows use the `docker-compose.yml` file in the root directory to start nginx containers:
- `nginx_good` on port 443
- `nginx_bad` on port 8443

### Environment Variables
- `DOCKER_CLIENT_TIMEOUT: 120` - Increased timeout for CI environment
- `COMPOSE_HTTP_TIMEOUT: 120` - Increased timeout for Docker Compose

### Go Version
All workflows use Go 1.24 to match the project requirements.

## Usage

### For Pull Requests
The workflows automatically run when you create a pull request to the main branch. The status will be displayed in the PR interface.

### Manual Trigger
You can manually trigger the scheduled tests workflow:
1. Go to the Actions tab in GitHub
2. Select "Scheduled Integration Tests"
3. Click "Run workflow"

### Local Testing
To test the workflows locally before pushing:

```bash
# Test the integration tests locally
make test-integration

# Test specific TLS 1.3 tests
make test-tls13-chacha20
make test-tls13-default
```

## Troubleshooting

### Common Issues

1. **Docker Setup Issues**
   - The workflow uses `docker/setup-docker-action` for reliable Docker setup
   - This action automatically handles Docker and Docker Compose installation

2. **Tests Time Out**
   - The workflow includes increased timeouts for CI environment
   - If tests still timeout, check nginx container health

3. **Port Conflicts**
   - Ensure ports 443 and 8443 are available on the runner
   - The workflow cleans up containers after each run

4. **Go Module Issues**
   - The workflow runs `go mod download` and `go mod tidy`
   - Check go.mod and go.sum files are up to date

### Debugging

To debug workflow issues:

1. Check the Actions tab in GitHub for detailed logs
2. Look for specific step failures
3. Verify Docker containers are starting correctly
4. Check that the nginx images are accessible

### Adding New Tests

When adding new integration tests:

1. Add the test to `integration_test.go`
2. Update the workflow if needed (usually not required)
3. Test locally with `make test-integration`
4. Create a PR to trigger the workflow

## Security

The workflows include security scanning with gosec to identify potential security issues in the codebase. Results are uploaded to GitHub's security tab for review.

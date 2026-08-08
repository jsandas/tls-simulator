//go:build integration

package integrationtests

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Container service addresses
const (
	Nginx1300_TLS12_TLS13_Addr = "127.0.0.1:443"
	Nginx1300_TLS12_Addr       = "127.0.0.1:1443"
	Nginx1300_TLS10_TLS13_Addr = "127.0.0.1:2443"
	Nginx129_TLS12_Addr        = "127.0.0.1:3443"
	Nginx129_TLS10_TLS12_Addr  = "127.0.0.1:4443"
	Nginx129_SSLv2_TLS12_Addr  = "127.0.0.1:5443"
	Postfix_Port25_Addr        = "127.0.0.1:25"
	Postfix_Port587_Addr       = "127.0.0.1:587"
	MariaDB_Addr               = "127.0.0.1:3306"
)

var allAddrs = []string{
	Nginx1300_TLS12_TLS13_Addr,
	Nginx1300_TLS12_Addr,
	Nginx1300_TLS10_TLS13_Addr,
	Nginx129_TLS12_Addr,
	Nginx129_TLS10_TLS12_Addr,
	Nginx129_SSLv2_TLS12_Addr,
	Postfix_Port25_Addr,
	Postfix_Port587_Addr,
	MariaDB_Addr,
}

// TestMain manages the life-cycle of docker compose services for integration tests.
func TestMain(m *testing.M) {
	fmt.Println("=== Integration Tests Setup: Starting Docker Compose ===")
	cmd := exec.Command("docker", "compose", "up", "-d")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to start docker compose services: %v\n", err)
		os.Exit(1)
	}

	// Wait for each service port to be open
	fmt.Println("Waiting for all service ports to become ready...")
	for _, addr := range allAddrs {
		if err := WaitForServer(addr, 20*time.Second); err != nil {
			fmt.Printf("Service at %s failed to become ready: %v\n", addr, err)
			os.Exit(1)
		}
	}
	// Give services (like MariaDB engine initialization) a brief warm-up buffer
	time.Sleep(3 * time.Second)
	fmt.Println("All services are ready!")

	code := m.Run()

	fmt.Println("=== Integration Tests Teardown: Stopping Docker Compose ===")
	downCmd := exec.Command("docker", "compose", "down")
	downCmd.Stdout = os.Stdout
	downCmd.Stderr = os.Stderr
	_ = downCmd.Run()

	os.Exit(code)
}

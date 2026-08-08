//go:build integration

package integrationtests

import (
	"net"
	"testing"
	"time"
)

func TestWaitForServerUsesFreshAttemptTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create initial listener: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close initial listener: %v", err)
	}

	listenerReady := make(chan struct{})
	var startedListener net.Listener

	go func() {
		time.Sleep(2500 * time.Millisecond)
		var err error
		startedListener, err = net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("failed to create listener: %v", err)
			return
		}
		close(listenerReady)
	}()

	defer func() {
		if startedListener != nil {
			_ = startedListener.Close()
		}
	}()

	err = WaitForServer(addr, 10*time.Second)
	if err != nil {
		t.Fatalf("WaitForServer returned an error for a server that became ready after the initial retry window: %v", err)
	}

	select {
	case <-listenerReady:
	default:
		t.Fatal("listener was not created")
	}
}

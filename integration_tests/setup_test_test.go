//go:build integration

package integrationtests

import (
	"errors"
	"testing"
)

func TestRunWithCleanupInvokesCleanupOnError(t *testing.T) {
	var cleanupCalled bool
	origRunner := dockerComposeRunner
	defer func() { dockerComposeRunner = origRunner }()

	dockerComposeRunner = func(args ...string) error {
		if len(args) == 1 && args[0] == "down" {
			cleanupCalled = true
		}
		return nil
	}

	err := runWithCleanup(func() error {
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected runWithCleanup to return an error")
	}
	if !cleanupCalled {
		t.Fatal("expected cleanup to run when the action failed")
	}
}

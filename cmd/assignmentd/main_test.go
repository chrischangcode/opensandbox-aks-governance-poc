package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"k8s.io/client-go/kubernetes"
)

type controllerRunnerFunc func(context.Context) error

func (f controllerRunnerFunc) Run(ctx context.Context) error { return f(ctx) }

func TestParseOptionsLeaderElection(t *testing.T) {
	defaults, err := parseOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !defaults.leaderElect {
		t.Fatal("leader election default = false, want true")
	}

	disabled, err := parseOptions([]string{"--leader-elect=false"})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.leaderElect {
		t.Fatal("leader election = true, want false")
	}
}

func TestRunAssignmentControllerWithoutLeaderElection(t *testing.T) {
	called := false
	runner := controllerRunnerFunc(func(context.Context) error {
		called = true
		return nil
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := runAssignmentController(context.Background(), runner, nilKubernetesClient{}, "test", false, logger); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("controller was not run")
	}
}

// nilKubernetesClient is never used when leader election is disabled.
type nilKubernetesClient struct{ kubernetes.Interface }

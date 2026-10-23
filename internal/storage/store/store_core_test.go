package store

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestFileStorePingChecksDurableStateWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, "readiness-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Fatalf("Ping on healthy file store: %v", err)
	}
	if err := os.Remove(st.path); err != nil {
		t.Fatal(err)
	}
	if err := st.Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded after durable state disappeared")
	}
}

func TestStorePingHonorsCancelledContext(t *testing.T) {
	st, err := Open(t.TempDir(), "readiness-cancel")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := st.Ping(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping error=%v, want context.Canceled", err)
	}
}

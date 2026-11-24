package alertd

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmptySubjectDefaultsToDashAndIsAccepted(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "alerts.db"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	eng := NewEngine(DaemonOptions{}, DefaultConfig(), store, []Channel{})
	defer eng.Close()

	res, err := eng.Observe(context.Background(), map[string]any{
		"rule":    "security.burst",
		"subject": "",
		"summary": "Burst detected",
	})
	if err != nil {
		t.Fatalf("empty subject should default to '-' and succeed, got %v", err)
	}
	if res["subject"] != "-" {
		t.Fatalf("expected subject '-', got %v", res["subject"])
	}
}

func TestCleanTextTruncatesByRunesNotBytes(t *testing.T) {
	got := cleanText("ПриветМир", 6)
	if got != "Привет" {
		t.Fatalf("expected 6 Cyrillic runes 'Привет', got %q", got)
	}
}

func TestRetryMailTimerStopsOnEngineClose(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "alerts.db"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	marker := filepath.Join(dir, "postqueue-ran")
	fakeDocker := filepath.Join(dir, "docker")
	script := "#!/bin/sh\nif [ \"$3\" = \"postqueue\" ] && [ \"$4\" = \"-j\" ]; then echo ran >> " + marker + "; fi\nexit 0\n"
	if err := os.WriteFile(fakeDocker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	eng := NewEngine(DaemonOptions{DockerBin: fakeDocker, MailRelayContainer: "mail_relay"}, DefaultConfig(), store, []Channel{})
	eng.retryDelay = 80 * time.Millisecond

	if _, err := eng.RetryMail(context.Background()); err != nil {
		t.Fatalf("RetryMail failed: %v", err)
	}
	eng.Close()
	time.Sleep(180 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		calls.Add(1)
	}
	if calls.Load() != 0 {
		t.Fatal("retry timer fired after Engine.Close()")
	}
}

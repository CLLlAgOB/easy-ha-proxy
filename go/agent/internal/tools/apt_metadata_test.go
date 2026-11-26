package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func aptFixture(t *testing.T, script string) (state, root string) {
	t.Helper()
	dir := t.TempDir()
	root = filepath.Join(dir, "apt")
	os.MkdirAll(filepath.Join(root, "sources.list.d"), 0o755)
	os.WriteFile(filepath.Join(root, "sources.list"), []byte("deb http://archive.ubuntu.com/ubuntu noble main\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sources.list.d", "docker.list"), []byte("deb https://download.docker.com/linux/ubuntu noble stable\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sources.list.d", "notes.txt"), []byte("ignored\n"), 0o644)
	fake := filepath.Join(dir, "apt-get")
	os.WriteFile(fake, []byte("#!/bin/sh\n"+script), 0o755)
	old := aptGetPath
	aptGetPath = fake
	t.Cleanup(func() { aptGetPath = old })
	return filepath.Join(dir, "state", "status.json"), root
}

func TestAnAptRefreshThatWorksIsFreshForADay(t *testing.T) {
	state, root := aptFixture(t, "exit 0\n")
	result, err := RefreshAptMetadata(state, root, 10*time.Second)
	if err != nil || result["success"] != true || result["fresh"] != true || result["error"] != nil {
		t.Fatalf("%v %v", result, err)
	}
	fi, _ := os.Stat(state)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if got := AssessAptMetadata(state, root, time.Now()); got["fresh"] != true {
		t.Fatalf("assess %v", got)
	}
	if got := AssessAptMetadata(state, root, time.Now().Add(25*time.Hour)); got["fresh"] != false {
		t.Fatal("a day-old refresh still fresh")
	}
	os.WriteFile(filepath.Join(root, "sources.list.d", "new.sources"), []byte("Types: deb\n"), 0o644)
	if got := AssessAptMetadata(state, root, time.Now()); got["fresh"] != false {
		t.Fatal("fresh after the sources changed")
	}
}

func TestAFailedAptRefreshKeepsTheLastSuccessAndHidesCredentials(t *testing.T) {
	state, root := aptFixture(t, "exit 0\n")
	first, _ := RefreshAptMetadata(state, root, 10*time.Second)
	aptGetPath = filepath.Join(filepath.Dir(aptGetPath), "apt-get-bad")
	os.WriteFile(aptGetPath, []byte("#!/bin/sh\necho 'E: Failed to fetch https://user:secret@repo.example/dists/x  401' >&2\nexit 100\n"), 0o755)
	result, err := RefreshAptMetadata(state, root, 10*time.Second)
	if err != nil || result["success"] != false || result["fresh"] != false {
		t.Fatalf("%v %v", result, err)
	}
	msg := result["error"].(string)
	if !strings.Contains(msg, "exit 100") || strings.Contains(msg, "secret") || !strings.Contains(msg, "[repository]") {
		t.Fatalf("error %q", msg)
	}
	raw, _ := os.ReadFile(state)
	var record map[string]any
	json.Unmarshal(raw, &record)
	if record["last_success"] != first["last_success"] {
		t.Fatalf("last success %v, was %v", record["last_success"], first["last_success"])
	}
}

func TestAnAptRefreshThatHangsIsStopped(t *testing.T) {
	state, root := aptFixture(t, "sleep 30\n")
	start := time.Now()
	result, err := RefreshAptMetadata(state, root, time.Second)
	if err != nil || result["error"] != "APT metadata refresh timed out" || time.Since(start) > 10*time.Second {
		t.Fatalf("%v %v after %v", result, err, time.Since(start))
	}
}

func TestADamagedAptRecordIsNotTrusted(t *testing.T) {
	state, root := aptFixture(t, "exit 0\n")
	os.MkdirAll(filepath.Dir(state), 0o700)
	os.WriteFile(state, []byte("{not json"), 0o600)
	if got := AssessAptMetadata(state, root, time.Now()); got["fresh"] != false || got["error"] != "APT metadata has not been verified" {
		t.Fatalf("assess %v", got)
	}
}

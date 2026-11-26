package fullbackup

import (
	"strings"
	"testing"
)

func TestTheWebSafeFlagsAreOnEveryCommand(t *testing.T) {
	booleans := map[string][]string{"passphrase-stdin": nil, "replace-managed": nil, "yes": nil}
	p, err := parseArgs([]string{"/tmp/backup.enc", "--passphrase-stdin", "--replace-managed", "--yes", "--mode=overlay"}, booleans,
		map[string][]string{"mode": {"auto", "fresh", "overlay"}})
	if err != nil || !p.set("passphrase-stdin") || !p.set("replace-managed") || !p.set("yes") || p.value("mode", "") != "overlay" ||
		len(p.positional) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parseArgs([]string{"--mode", "sideways"}, nil, map[string][]string{"mode": {"auto"}}); err == nil {
		t.Fatal("an invalid choice was accepted")
	}
}

func TestBadCommandLinesExitTwo(t *testing.T) {
	for _, args := range [][]string{{}, {"explode"}, {"backup", "extra"}, {"restore"}, {"restore", "a", "b"},
		{"restore", "a", "--scope", "everything"}, {"inspect"}, {"backup", "--unknown"}} {
		var stdout, stderr strings.Builder
		if code := RunCLI(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "error: ") {
			t.Errorf("%q: %d %q", args, code, stderr.String())
		}
	}
}

func TestAFailureIsReportedAsAnError(t *testing.T) {
	t.Setenv("EASY_HA_PROXY_ALLOW_NON_ROOT", "1")
	var stdout, stderr strings.Builder
	if code := RunCLI([]string{"inspect", "/nonexistent/backup.enc", "--passphrase-stdin"}, &stdout, &stderr); code != 2 ||
		!strings.HasPrefix(stderr.String(), "ERROR: Backup file not found") {
		t.Fatalf("%d %q", code, stderr.String())
	}
	t.Setenv("EASY_HA_PROXY_BACKUP_MAX_CORE_MEMBERS", "zero")
	stderr.Reset()
	if code := RunCLI([]string{"inspect", "/nonexistent/backup.enc"}, &stdout, &stderr); code != 2 ||
		!strings.Contains(stderr.String(), "must be a positive integer") {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

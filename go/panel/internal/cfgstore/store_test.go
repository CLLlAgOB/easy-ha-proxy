package cfgstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreReadWriteBackupAndAllowlist(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "config")
	bakDir := filepath.Join(tmp, "backups")
	liveCfg := filepath.Join(tmp, "haproxy.cfg")
	_ = os.WriteFile(liveCfg, []byte("global\n  maxconn 2000\n"), 0o644)

	st := New(cfgDir, bakDir, liveCfg)

	if _, _, err := st.ResolvePath("../etc/passwd"); err == nil {
		t.Fatalf("expected error for disallowed path traversal kind")
	}

	h1, err := st.Write("vars", []byte("enable_geoip: true\n"))
	if err != nil || len(h1) != 64 {
		t.Fatalf("Write vars failed: err=%v hash=%q", err, h1)
	}
	h2, err := st.Write("vars", []byte("enable_geoip: false\n"))
	if err != nil || h1 == h2 {
		t.Fatalf("second Write vars failed: err=%v", err)
	}

	raw, fname, hRead, err := st.Read("vars")
	if err != nil || fname != "vars.yml" || hRead != h2 || !strings.Contains(string(raw), "false") {
		t.Fatalf("Read vars mismatch: err=%v fname=%q raw=%q", err, fname, string(raw))
	}

	entries, _ := os.ReadDir(bakDir)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "vars.yml.bak.") {
		t.Fatalf("expected backup file in %s, got %+v", bakDir, entries)
	}

	live, err := st.ReadLiveHAProxyCfg()
	if err != nil || !strings.Contains(string(live), "maxconn 2000") {
		t.Fatalf("ReadLiveHAProxyCfg failed: %v", err)
	}
}

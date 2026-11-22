package controld

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validHAProxyCfg = `global
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    lua-load /etc/haproxy/lua/auth-request.lua
    server-state-file /var/lib/haproxy/server-state
    .if !feature(OPENSSL_AWSLC)
    tune.ssl.default-dh-param 2048
    .endif

defaults
    mode http

frontend fe_http
    bind *:80
`

func TestEnforceConfigPolicy(t *testing.T) {
	if err := EnforceConfigPolicy([]byte(validHAProxyCfg)); err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}

	cases := []struct {
		name string
		cfg  string
	}{
		{"missing privilege drop", "global\n    daemon\n"},
		{"forbidden external-check", validHAProxyCfg + "\nbackend b\n    option external-check\n"},
		{"forbidden program", validHAProxyCfg + "\nprogram p\n    command /bin/sh\n"},
		{"unapproved lua-load", strings.Replace(validHAProxyCfg, "/etc/haproxy/lua/auth-request.lua", "/tmp/evil.lua", 1)},
		{"traversal stats socket", strings.Replace(validHAProxyCfg, "/run/haproxy/admin.sock", "/run/haproxy/../root.sock", 1)},
		{"unapproved conditional", strings.Replace(validHAProxyCfg, ".if !feature(OPENSSL_AWSLC)", ".if defined(EVIL)", 1)},
		{"server-state outside chroot", strings.Replace(validHAProxyCfg, "/var/lib/haproxy/server-state", "/etc/shadow", 1)},
	}
	for _, tc := range cases {
		if err := EnforceConfigPolicy([]byte(tc.cfg)); err == nil {
			t.Fatalf("case %q: expected policy error, got nil", tc.name)
		}
	}
}

func TestLineHasIPAndReverseTailGrep(t *testing.T) {
	if LineHasIP("client 203.0.113.10:55123 GET /", "203.0.113.1") {
		t.Fatal("prefix match 203.0.113.10 must not match 203.0.113.1")
	}
	if !LineHasIP("client 203.0.113.1:55123 GET /", "203.0.113.1") {
		t.Fatal("exact IPv4 match failed")
	}
	if !LineHasIP("src=2001:db8::1:443", "2001:db8::1") {
		t.Fatal("exact IPv6 match failed")
	}

	logFile := filepath.Join(t.TempDir(), "haproxy.log")
	content := strings.Join([]string{
		"Jan 1 00:00:01 gw haproxy: 203.0.113.1:1001 GET /first",
		"Jan 1 00:00:02 gw haproxy: 203.0.113.10:1002 GET /wrong",
		"Jan 1 00:00:03 gw haproxy: 203.0.113.1:1003 GET /second",
		"Jan 1 00:00:04 gw haproxy: 203.0.113.1:1004 GET /third",
	}, "\n") + "\n"
	if err := os.WriteFile(logFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	lines, err := GrepLastLogsForIP(logFile, "203.0.113.1", 2, 32, 64*1024)
	if err != nil {
		t.Fatalf("GrepLastLogsForIP: %v", err)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "/second") || !strings.Contains(lines[1], "/third") {
		t.Fatalf("expected [/second, /third], got %+v", lines)
	}
}

func TestUnixSocketControlProtocolAndRebootLock(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "controld.sock")
	cfgPath := filepath.Join(dir, "haproxy.cfg")
	logPath := filepath.Join(dir, "haproxy.log")
	histDir := filepath.Join(dir, "history")
	procUDP := filepath.Join(dir, "proc_udp")
	geoDir := filepath.Join(dir, "geoip")
	rebootMarker := filepath.Join(dir, "reboot.json")

	// Fake haproxy & systemctl scripts.
	fakeHaproxy := filepath.Join(dir, "fake-haproxy.sh")
	_ = os.WriteFile(fakeHaproxy, []byte("#!/bin/sh\necho 'Configuration file is valid'\nexit 0\n"), 0o755)
	fakeSystemctl := filepath.Join(dir, "fake-systemctl.sh")
	_ = os.WriteFile(fakeSystemctl, []byte("#!/bin/sh\necho 'reloaded'\nexit 0\n"), 0o755)

	// Fixture log, proc/net/udp, history version, and GeoIP release.
	_ = os.WriteFile(logPath, []byte("2026-01-01 198.51.100.7:1234 GET /ok\n"), 0o644)
	// Port 51820 = 0xCA6C
	_ = os.WriteFile(procUDP, []byte("  sl  local_address rem_address st\n   0: 00000000:CA6C 00000000:0000 07\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(histDir, "v001"), 0o755)
	_ = os.WriteFile(filepath.Join(histDir, "v001", "meta.json"), []byte(`{"id":"v001","actor":"admin"}`), 0o644)
	_ = os.WriteFile(filepath.Join(histDir, "v001", "vars.yml"), []byte("key: val\n"), 0o644)

	relDir := filepath.Join(geoDir, "releases", "2026-01")
	_ = os.MkdirAll(relDir, 0o755)
	dbBytes := []byte("fake-mmdb")
	alBytes := []byte("1.0.0.0/24\n")
	dbSum := sha256.Sum256(dbBytes)
	alSum := sha256.Sum256(alBytes)
	_ = os.WriteFile(filepath.Join(relDir, "dbip-country-lite.mmdb"), dbBytes, 0o644)
	_ = os.WriteFile(filepath.Join(relDir, "allowed.geo"), alBytes, 0o644)
	stateJSON, _ := json.Marshal(map[string]any{
		"release_format_version": 1,
		"provider":               "dbip",
		"database_sha256":        hex.EncodeToString(dbSum[:]),
		"allowed_sha256":         hex.EncodeToString(alSum[:]),
		"countries":              []string{"DE"},
		"access_filter_enabled":  true,
	})
	_ = os.WriteFile(filepath.Join(relDir, "state.json"), stateJSON, 0o644)
	_ = os.Symlink(relDir, filepath.Join(geoDir, "current"))
	_ = os.WriteFile(filepath.Join(geoDir, "selection.json"), []byte(`{"countries":["DE"],"access_filter_enabled":true}`), 0o644)

	opts := Options{
		ControlSocket:           sock,
		HAProxyBin:              fakeHaproxy,
		HAProxyCfgPath:          cfgPath,
		SystemctlBin:            fakeSystemctl,
		LogFile:                 logPath,
		LogLimit:                30,
		LogTailChunk:            4096,
		LogTailMaxBytes:         1024 * 1024,
		ConfigHistoryDir:        histDir,
		MaintenanceRebootMarker: rebootMarker,
		GeoIPDir:                geoDir,
		ProcNetUDPPath:          procUDP,
		ProcNetUDP6Path:         filepath.Join(dir, "missing"),
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewServer(NewController(opts))
	go func() { _ = srv.Serve(ctx, ln) }()

	send := func(cmd string) string {
		t.Helper()
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial %q: %v", cmd, err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(cmd + "\n"))
		sc := bufio.NewReader(conn)
		all, _ := sc.ReadString(0)
		return all
	}

	if got := send("ping"); got != "OK pong\n" {
		t.Fatalf("ping: got %q", got)
	}
	if got := send("udp-port-check 51819 51821"); got != "OK busy 51820\n" {
		t.Fatalf("udp-port-check busy: got %q", got)
	}
	if got := send("udp-port-check 52000 52010"); got != "OK free 52000-52010\n" {
		t.Fatalf("udp-port-check free: got %q", got)
	}

	cfgB64 := base64.StdEncoding.EncodeToString([]byte(validHAProxyCfg))
	if got := send("check-config " + cfgB64); !strings.HasPrefix(got, "OK 0\n") {
		t.Fatalf("check-config: got %q", got)
	}
	if got := send("write-config " + cfgB64); got != "OK wrote haproxy.cfg\n" {
		t.Fatalf("write-config: got %q", got)
	}
	if got := send("reload"); got != "OK reloaded\n" {
		t.Fatalf("reload: got %q", got)
	}

	// Logs-ip returns base64-encoded matching line.
	logsReply := send("logs-ip 198.51.100.7 5")
	if !strings.HasPrefix(logsReply, "OK ") {
		t.Fatalf("logs-ip: got %q", logsReply)
	}
	decodedLog, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(logsReply, "OK ")))
	if !strings.Contains(string(decodedLog), "198.51.100.7") {
		t.Fatalf("unexpected decoded log: %q", string(decodedLog))
	}

	// GeoIP status verifies SHA-256 integrity.
	geoReply := send("geoip-status")
	if !strings.HasPrefix(geoReply, "OK ") {
		t.Fatalf("geoip-status: got %q", geoReply)
	}
	geoRaw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(geoReply, "OK ")))
	var geo map[string]any
	_ = json.Unmarshal(geoRaw, &geo)
	dbObj := geo["database"].(map[string]any)
	if dbObj["integrity_ok"] != true {
		t.Fatalf("expected geoip integrity_ok=true, got %+v", geo)
	}

	// Reboot marker blocks mutating commands while allowing read-only ping.
	_ = os.WriteFile(rebootMarker, []byte(`{"scheduled":true}`), 0o600)
	if got := send("reload"); got != "ERROR a server reboot is scheduled\n" {
		t.Fatalf("expected reboot lock on reload, got %q", got)
	}
	if got := send("ping"); got != "OK pong\n" {
		t.Fatalf("ping must remain allowed during scheduled reboot, got %q", got)
	}
}

package healthd

import (
	"context"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchingUnitGlobDoesNotAllocateCursorForUnknownUnit(t *testing.T) {
	old := CursorDir
	CursorDir = t.TempDir()
	t.Cleanup(func() { CursorDir = old })
	scans := 0
	s := NewState(Config{SystemdUnitGlobs: []string{"authelia-*.service"}, UnitsRescanSeconds: 60}, "", func(_ time.Duration, argv ...string) (int, string, string) {
		if argv[0] != "systemctl" || argv[1] != "list-unit-files" {
			t.Fatalf("unexpected command: %v", argv)
		}
		scans++
		return 0, "", ""
	})
	for range 2 {
		result := s.LogsSystemd("authelia-unused.service", 10, 60, "follow", false, "")
		if result["ok"] != false || result["error"] != "unit is not installed" {
			t.Fatalf("unexpected response: %v", result)
		}
	}
	if scans != 1 {
		t.Fatalf("repeated an empty unit scan %d times", scans)
	}
}

func fakeRunner(t *testing.T) Runner {
	t.Helper()
	return func(_ time.Duration, argv ...string) (int, string, string) {
		cmd := strings.Join(argv, " ")
		switch {
		case strings.HasPrefix(cmd, "systemctl list-unit-files"):
			return 0, "authelia-bansd.service enabled enabled\nother.service enabled enabled\n", ""
		case strings.HasPrefix(cmd, "systemctl show easy-ha-proxy-backup.service"):
			return 0, "LoadState=loaded\nActiveState=inactive\nSubState=dead\nType=oneshot\nResult=success\nExecMainStatus=0\nInactiveExitTimestamp=Sun 2026-11-22 03:39:23 CET\n", ""
		case strings.HasPrefix(cmd, "systemctl show"):
			return 0, "LoadState=loaded\nActiveState=active\nSubState=running\nType=simple\n", ""
		case cmd == "docker version":
			return 0, "", ""
		case strings.HasPrefix(cmd, "docker container inspect"):
			return 0, "Status=running\nRunning=true\nHealth=healthy\nExitCode=0\n", ""
		case strings.HasPrefix(cmd, "journalctl -u haproxy.service --no-pager -q -o short-iso --show-cursor"):
			return 0, "2026-11-22 line one\n-- cursor: s=abc\n", ""
		case strings.HasPrefix(cmd, "journalctl") && strings.Contains(cmd, "-o json"):
			return 0, `{"MESSAGE":"hello","__REALTIME_TIMESTAMP":"1795341600000000","PRIORITY":"6","_SYSTEMD_UNIT":"authelia-bansd.service"}` + "\n", ""
		case strings.HasPrefix(cmd, "systemctl restart"):
			return 0, "", ""
		}
		return 1, "", "unexpected " + cmd
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "healthd.json")
	_ = os.WriteFile(p, []byte(`{"systemd":{"units":["haproxy.service","easy-ha-proxy-backup.service","haproxy-healthd.service"],"unit_globs":["authelia-*.service"]},
		"docker":{"containers":["haproxy-admin"]},"cache_ttl_seconds":0,"logs":{"default_tail":5}}`), 0o644)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestConfigShapeAndLimits(t *testing.T) {
	cfg := testConfig(t)
	if len(cfg.SystemdUnits) != 3 || cfg.SystemdUnitGlobs[0] != "authelia-*.service" || cfg.DockerContainers[0] != "haproxy-admin" {
		t.Fatalf("nested keys not read: %+v", cfg)
	}
	if cfg.LogsDefaultTail != 10 || cfg.CacheTTLSeconds != 15 || cfg.LogsMaxSinceSeconds != 86400 {
		t.Fatalf("defaults/limits differ from Python: %+v", cfg)
	}
}

func TestOneshotHealthAndSnapshot(t *testing.T) {
	st := NewState(testConfig(t), DefaultHealthUnit, fakeRunner(t))
	snap := st.Snapshot(true)
	units := snap["systemd"].(map[string]any)["units"].(map[string]any)
	backup := units["easy-ha-proxy-backup.service"].(map[string]any)
	if backup["healthy"] != true || backup["display_state"] != "completed" || backup["display_sub_state"] != "success" {
		t.Fatalf("oneshot health: %v", backup)
	}
	if _, ok := units["authelia-bansd.service"]; !ok {
		t.Fatalf("glob not expanded: %v", units)
	}
	if snap["docker"].(map[string]any)["available"] != true {
		t.Fatalf("docker: %v", snap["docker"])
	}
}

func TestHTTPRoutes(t *testing.T) {
	st := NewState(testConfig(t), DefaultHealthUnit, fakeRunner(t))
	srv := httptest.NewServer(&Server{State: st, ControlToken: "tok"})
	defer srv.Close()
	get := func(p string) (int, map[string]any) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if c, out := get("/api/v1/health/ping"); c != 200 || out["ok"] != true {
		t.Fatalf("ping %d %v", c, out)
	}
	if c, out := get("/api/v1/health/logs/systemd?unit=haproxy.service"); c != 200 || out["cursor"] != "s=abc" || out["text"] != "2026-11-22 line one\n" {
		t.Fatalf("logs %d %v", c, out)
	}
	if c, out := get("/api/v1/health/logs/systemd"); c != 400 || out["error"] != "unit is required" {
		t.Fatalf("logs no unit %d %v", c, out)
	}
	c, out := get("/api/v1/health/recent-systemd")
	items, _ := out["items"].([]any)
	if c != 200 || len(items) != 1 || items[0].(map[string]any)["raw_message"] != "hello" {
		t.Fatalf("recent %d %v", c, out)
	}
	if units := out["units"].([]any); len(units) != 2 {
		t.Fatalf("haproxy and healthd must be excluded by default: %v", units)
	}
	if c, out := get("/api/v1/health/recent-systemd?unit=bogus.service"); c != 400 || out["error"] != "one or more units are not monitored" {
		t.Fatalf("recent invalid %d %v", c, out)
	}
	if c, out := get("/api/v1/health/events?limit=5"); c != 200 || out["items"] == nil {
		t.Fatalf("events %d %v", c, out)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/control", strings.NewReader(`{"kind":"systemd","name":"easy-ha-proxy-backup.service","action":"start"}`))
	req.Header.Set("X-Healthd-Token", "tok")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("backup unit must not be startable: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/control", strings.NewReader(`{"kind":"systemd","name":"haproxy.service","action":"restart"}`))
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("missing token must be forbidden: %d", resp.StatusCode)
	}
}

func TestSiteStateMachineMailsOnceAndRecovers(t *testing.T) {
	dir := t.TempDir()
	siteAlertsStatePath = filepath.Join(dir, "site-alerts.json")
	var sent []string
	sa := &SiteAlerts{incidents: map[string]*incident{}, send: func(_, subject, _ string) bool {
		sent = append(sent, subject)
		return true
	}}
	site := map[string]any{"name": "app", "alert_after": "1m", "alert_mode": "down"}
	down := &siteCondition{State: "down", Total: 1}
	ok := &siteCondition{State: "ok", Total: 1, Up: 1}
	sa.evaluate(context.Background(), site, "app", down, 1000)
	sa.evaluate(context.Background(), site, "app", down, 1059)
	if len(sent) != 0 {
		t.Fatalf("alerted before alert_after: %v", sent)
	}
	sa.evaluate(context.Background(), site, "app", down, 1061)
	sa.evaluate(context.Background(), site, "app", down, 1100)
	if len(sent) != 1 || !strings.HasSuffix(sent[0], ": DOWN") {
		t.Fatalf("expected one DOWN: %v", sent)
	}
	sa.evaluate(context.Background(), site, "app", ok, 1200)
	sa.evaluate(context.Background(), site, "app", ok, 1261)
	if len(sent) != 2 || !strings.HasSuffix(sent[1], ": RECOVERED") {
		t.Fatalf("expected recovery: %v", sent)
	}
	if err := sa.persist(); err != nil {
		t.Fatal("persist failed")
	}
	if got := loadIncidents(); len(got) != 0 {
		t.Fatalf("closed incident must not be kept: %v", got)
	}
}

func TestSiteCondition(t *testing.T) {
	rows := []haproxy.StatRow{
		{"pxname": "be_app", "svname": "s1", "status": "UP"},
		{"pxname": "be_app", "svname": "s2", "status": "DOWN", "addr": "10.0.0.2:80"},
		{"pxname": "be_app", "svname": "BACKEND", "status": "UP"},
	}
	c := siteConditionFor("app", rows)
	if c == nil || c.State != "degraded" || c.Up != 1 || c.Total != 2 {
		t.Fatalf("condition: %+v", c)
	}
	if siteConditionFor("other", rows) != nil {
		t.Fatal("unknown backend must be nil")
	}
	if alertAfterSeconds("5m") != 300 || alertAfterSeconds(nil) != 300 || alertAfterSeconds(90) != 90 {
		t.Fatal("alert_after parsing")
	}
}

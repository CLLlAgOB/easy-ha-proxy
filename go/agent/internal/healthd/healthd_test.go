package healthd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, argv ...string) (int, string, string) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	if len(argv) >= 2 && argv[0] == "systemctl" && argv[1] == "show" {
		return 0, "Id=haproxy.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nDescription=HAProxy\n", ""
	}
	if len(argv) >= 2 && argv[0] == "docker" && argv[1] == "inspect" {
		return 0, "running|healthy|example/haproxy-admin:alpha\n", ""
	}
	return 0, "", ""
}

func TestAllowedActionsPolicyParity(t *testing.T) {
	if !ActionPermitted("systemd", "haproxy.service", "reload", DefaultHealthUnit) {
		t.Fatal("haproxy must allow reload")
	}
	if ActionPermitted("systemd", "haproxy.service", "stop", DefaultHealthUnit) {
		t.Fatal("haproxy must not allow stop")
	}
	if ActionPermitted("docker", "haproxy-admin", "stop", DefaultHealthUnit) {
		t.Fatal("haproxy-admin container must allow restart only")
	}
	if len(AllowedActions("systemd", "easy-ha-proxy-backup.service", DefaultHealthUnit)) != 0 {
		t.Fatal("scheduled backup service must allow no control actions")
	}
}

func TestUnixSocketStatusAndControl(t *testing.T) {
	cfg := Config{
		SystemdUnits:       []string{"haproxy.service"},
		DockerContainers:   []string{"haproxy-admin"},
		EventsMax:          50,
		CacheTTLSeconds:    0,
		UnitsRescanSeconds: 300,
	}
	runner := &fakeRunner{}
	col := NewCollector(cfg, DefaultHealthUnit, runner)
	srv := &Server{
		Collector:    col,
		ControlToken: "unit-secret",
		SelfUnit:     DefaultHealthUnit,
		Runner:       runner,
	}

	sock := filepath.Join(t.TempDir(), "healthd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, sock) }()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 3 * time.Second,
	}

	var resp *http.Response
	var err error
	for i := 0; i < 40; i++ {
		resp, err = client.Get("http://unix/api/v1/status")
		if err == nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /api/v1/status failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var statusBody struct {
		OK       bool     `json:"ok"`
		Snapshot Snapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&statusBody); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !statusBody.OK || len(statusBody.Snapshot.Systemd) != 1 || statusBody.Snapshot.Systemd[0].ActiveState != "active" {
		t.Fatalf("unexpected snapshot: %+v", statusBody)
	}

	// Unauthorized control request must be rejected with 401.
	reqBad, _ := http.NewRequest(http.MethodPost, "http://unix/api/v1/control",
		bytes.NewBufferString(`{"kind":"systemd","name":"haproxy.service","action":"reload"}`))
	reqBad.Header.Set("X-Healthd-Token", "wrong")
	rBad, err := client.Do(reqBad)
	if err != nil {
		t.Fatalf("POST bad failed: %v", err)
	}
	rBad.Body.Close()
	if rBad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rBad.StatusCode)
	}

	// Authorized reload of haproxy.service must succeed.
	reqOK, _ := http.NewRequest(http.MethodPost, "http://unix/api/v1/control",
		bytes.NewBufferString(`{"kind":"systemd","name":"haproxy.service","action":"reload"}`))
	reqOK.Header.Set("X-Healthd-Token", "unit-secret")
	rOK, err := client.Do(reqOK)
	if err != nil {
		t.Fatalf("POST ok failed: %v", err)
	}
	rOK.Body.Close()
	if rOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rOK.StatusCode)
	}
	foundReload := false
	for _, call := range runner.calls {
		if strings.Join(call, " ") == "systemctl reload haproxy.service" {
			foundReload = true
		}
	}
	if !foundReload {
		t.Fatalf("expected systemctl reload call, got %+v", runner.calls)
	}
}

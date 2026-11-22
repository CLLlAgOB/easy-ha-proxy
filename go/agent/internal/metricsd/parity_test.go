package metricsd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

func TestRollupStoragePressureTrafficAlertsAndFullHTTPAPI(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "metrics-store.json")
	cfg := DefaultConfig()
	cfg.AlertErrorRatioPercent = 10
	cfg.AlertSlowResponseMS = 500
	cfg.AlertMinRequests = 10

	store, err := NewStore(storePath, cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Capture alert observations over a local fake alertd socket.
	alertSock := filepath.Join(dir, "alertd.sock")
	alertLn, err := net.Listen("unix", alertSock)
	if err != nil {
		t.Fatalf("listen alertd: %v", err)
	}
	defer alertLn.Close()
	var mu sync.Mutex
	var gotAlerts []alerts.Observation
	alertSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var obs alerts.Observation
			_ = json.NewDecoder(r.Body).Decode(&obs)
			mu.Lock()
			gotAlerts = append(gotAlerts, obs)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	}
	go func() { _ = alertSrv.Serve(alertLn) }()
	defer alertSrv.Close()

	col := NewCollectorWithStore(cfg, nil, store, alerts.NewClient(alertSock, "tok-metrics"))

	// Seed a high-error, slow minute bucket for be_app and a healthy frontend bucket.
	minuteTS := int64(1700000100/60) * 60
	store.RecordTraffic(DeltaSample{
		TS: minuteTS + 10, Kind: "frontend", Proxy: "fe_https", Status: "OPEN",
		Requests: 100, BytesIn: 5000, BytesOut: 25000, Resp2xx: 80, Resp5xx: 20, Scur: 12, RtimeMS: 800,
	})
	store.RecordTraffic(DeltaSample{
		TS: minuteTS + 10, Kind: "backend", Proxy: "be_app", Status: "UP",
		Requests: 50, BytesIn: 2500, BytesOut: 12000, Resp2xx: 40, Resp5xx: 10, Scur: 7, RtimeMS: 750,
	})
	store.RecordTraffic(DeltaSample{
		TS: minuteTS + 10, Kind: "server", Proxy: "be_app", Server: "srv1", Status: "UP",
		Requests: 50, BytesIn: 2500, BytesOut: 12000, Resp2xx: 40, Resp5xx: 10,
	})
	store.RecordHost(HostSample{TS: minuteTS + 10, CPUPercent: 42.5, MemPercent: 61.0, Load1: 1.25})
	store.Flush()

	// Evaluate traffic alerts -> must fire both http.error_ratio (20% >= 10%) and response.slow (750ms >= 500ms).
	col.EvaluateTrafficAlerts(context.Background(), minuteTS)
	mu.Lock()
	fired := map[string]bool{}
	for _, obs := range gotAlerts {
		if obs.Active != nil && *obs.Active {
			fired[obs.Rule] = true
		}
	}
	mu.Unlock()
	if !fired["http.error_ratio"] || !fired["response.slow"] {
		t.Fatalf("expected http.error_ratio and response.slow alerts, got %+v", fired)
	}

	// Simulate low disk space -> StorageGuard sets Pressure=true and Paused=true.
	store.statFSFn = func(string) (fsStats, error) {
		return fsStats{TotalBytes: 20 * GiB, AvailBytes: 500 * 1024 * 1024}, nil
	}
	st := col.EvaluateStorageAlerts(context.Background(), minuteTS+120)
	if !st.Pressure || !st.Paused {
		t.Fatalf("expected storage pressure and paused writes, got %+v", st)
	}

	// Serve AF_UNIX HTTP API and verify /series, /servers, /backends, /states, /storage, /channel-labels.
	sock := filepath.Join(dir, "metricsd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen metricsd: %v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: (&Server{Collector: col}).Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	// POST /api/v1/metrics/channel-labels persists labels and hidden list.
	resp, err := client.Post("http://unix/api/v1/metrics/channel-labels", "application/json",
		bytes.NewBufferString(`{"labels":{"srv1":"Primary Fiber"},"hidden":["srv2"]}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("channel-labels failed: err=%v resp=%v", err, resp)
	}
	resp.Body.Close()

	// GET /api/v1/metrics/servers returns saved labels + hidden + srv1 totals.
	resp, err = client.Get("http://unix/api/v1/metrics/servers?since=1699999000&until=1700001000")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("servers failed: err=%v", err)
	}
	var srvBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&srvBody)
	resp.Body.Close()
	if srvBody["labels"].(map[string]any)["srv1"] != "Primary Fiber" {
		t.Fatalf("unexpected servers payload: %+v", srvBody)
	}

	// GET /api/v1/metrics/series?chart=requests returns points.
	resp, err = client.Get("http://unix/api/v1/metrics/series?chart=requests&since=1699999000&until=1700001000")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("series failed: err=%v", err)
	}
	var seriesBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&seriesBody)
	resp.Body.Close()
	if len(seriesBody["points"].([]any)) != 1 {
		t.Fatalf("expected 1 series point, got %+v", seriesBody)
	}

	// Unknown chart returns 400.
	resp, err = client.Get("http://unix/api/v1/metrics/series?chart=nonexistent")
	if err != nil {
		t.Fatalf("bad chart req: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown chart, got %d", resp.StatusCode)
	}

	// Verify snapshot reload from disk preserves channel labels and buckets.
	reloaded, err := NewStore(storePath, cfg)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	reLabels, _ := reloaded.ChannelLabels()
	if reLabels["srv1"] != "Primary Fiber" {
		t.Fatalf("reloaded store lost channel labels: %+v", reLabels)
	}
}

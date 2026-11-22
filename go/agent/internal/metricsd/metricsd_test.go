package metricsd

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
)

func TestResolveWindowAndParseSize(t *testing.T) {
	q := url.Values{"since": {"1000"}, "until": {"4600"}, "range": {"24h"}}
	rk, s, u := ResolveWindow(q, 9999)
	if rk != "custom" || s != 1000 || u != 4600 {
		t.Fatalf("expected custom 1000..4600, got %s %d..%d", rk, s, u)
	}
	rk2, s2, u2 := ResolveWindow(url.Values{"range": {"7d"}}, 1000000)
	if rk2 != "7d" || u2-s2 != 7*86400 {
		t.Fatalf("unexpected preset window: %s %d..%d", rk2, s2, u2)
	}
	if sz, ok := ParseSize("256M"); !ok || sz != 256*1024*1024 {
		t.Fatalf("ParseSize(256M) = %d, %v", sz, ok)
	}
}

func TestProcParsers(t *testing.T) {
	cpu, ok := ParseProcStat("cpu  100 10 50 800 40 0 0 0 0 0\ncpu0 50 5 25 400 20\n")
	if !ok || cpu.Total != 1000 || cpu.Idle != 840 {
		t.Fatalf("unexpected cpu totals: %+v ok=%v", cpu, ok)
	}
	total, used, ok := ParseProcMeminfo("MemTotal:       2000000 kB\nMemFree:        500000 kB\nMemAvailable:   1200000 kB\n")
	if !ok || total != 2000000*1024 || used != 800000*1024 {
		t.Fatalf("unexpected meminfo: total=%d used=%d ok=%v", total, used, ok)
	}
	rx, tx := ParseProcNetDev("Inter-| Receive\n  lo: 999 0 0 0 0 0 0 0 999 0\n eth0: 1234 0 0 0 0 0 0 0 5678 0\n")
	if rx != 1234 || tx != 5678 {
		t.Fatalf("unexpected net dev: rx=%d tx=%d", rx, tx)
	}
}

func TestCollectorDeltasAcrossHAProxyReloadAndHTTPAPI(t *testing.T) {
	haSock := filepath.Join(t.TempDir(), "haproxy.sock")
	ln, err := net.Listen("unix", haSock)
	if err != nil {
		t.Fatalf("listen haproxy: %v", err)
	}
	defer ln.Close()

	var step atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = bufio.NewReader(c).ReadString('\n')
				n := step.Add(1)
				var payload string
				switch n {
				case 1:
					payload = "# pxname,svname,req_tot,bin,bout,hrsp_2xx,hrsp_5xx,status\nfe_https,FRONTEND,100,1000,2000,99,1,OPEN\nbe_app,BACKEND,100,1000,2000,99,1,UP\n"
				case 2:
					payload = "# pxname,svname,req_tot,bin,bout,hrsp_2xx,hrsp_5xx,status\nfe_https,FRONTEND,140,1500,3200,138,2,OPEN\nbe_app,BACKEND,140,1500,3200,138,2,UP\n"
				default:
					// Simulated HAProxy reload counter reset
					payload = "# pxname,svname,req_tot,bin,bout,hrsp_2xx,hrsp_5xx,status\nfe_https,FRONTEND,15,200,400,15,0,OPEN\nbe_app,BACKEND,15,200,400,15,0,UP\n"
				}
				_, _ = c.Write([]byte(payload))
			}(conn)
		}
	}()

	cfg := DefaultConfig()
	cfg.HAProxySocket = haSock
	col := NewCollector(cfg, haproxy.NewClient(haSock))
	ctx := context.Background()

	if err := col.PollOnce(ctx, 1000); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if err := col.PollOnce(ctx, 1010); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if err := col.PollOnce(ctx, 1020); err != nil {
		t.Fatalf("poll 3 (reload reset): %v", err)
	}

	// Serve over AF_UNIX and query /api/v1/metrics/summary
	apiSock := filepath.Join(t.TempDir(), "metricsd.sock")
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Collector: col}
	go func() { _ = srv.Serve(srvCtx, apiSock) }()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", apiSock)
			},
		},
		Timeout: 3 * time.Second,
	}

	var resp *http.Response
	for i := 0; i < 40; i++ {
		resp, err = httpClient.Get("http://unix/api/v1/metrics/summary?since=990&until=1030")
		if err == nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET summary failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	// Delta 2 (40) + post-reload delta 3 (15) = 55 requests.
	if body["range"] != "custom" || body["requests"] != float64(55) {
		t.Fatalf("unexpected summary body: %+v", body)
	}
}

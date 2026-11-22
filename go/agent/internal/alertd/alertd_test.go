package alertd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeChannel struct {
	mu       sync.Mutex
	name     string
	avail    bool
	sent     []string
	failWith string
}

func (f *fakeChannel) Name() string        { return f.name }
func (f *fakeChannel) Available(Config) bool { return f.avail }
func (f *fakeChannel) Send(_ context.Context, _ Config, subject, _ string) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != "" {
		return false, f.failWith
	}
	f.sent = append(f.sent, subject)
	return true, ""
}

func TestEngineLifecycleEscalationRecoveryAndStormControl(t *testing.T) {
	now := int64(1700000000)
	store, err := NewStore(filepath.Join(t.TempDir(), "alerts-state.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ch := &fakeChannel{name: "email", avail: true}
	cfg := DefaultConfig()
	eng := NewEngine(DaemonOptions{GatewayName: "gw-alpha"}, cfg, store, []Channel{ch})
	eng.nowFn = func() int64 { return now }

	// 1. Level rule enters pending during trigger_delay (site.down default 300s).
	res, err := eng.Observe(context.Background(), map[string]any{
		"rule": "site.down", "subject": "app.example.com", "active": true, "severity": "warning",
	})
	if err != nil || res["state"] != StatePending {
		t.Fatalf("expected pending, got %+v err=%v", res, err)
	}

	// 2. After trigger_delay, fires and notifies.
	now += 300
	res, err = eng.Observe(context.Background(), map[string]any{
		"rule": "site.down", "subject": "app.example.com", "active": true, "severity": "warning",
	})
	if err != nil || res["state"] != StateFiring || res["transition"] != TransitionFired || res["notified"] != true {
		t.Fatalf("expected fired+notified, got %+v err=%v", res, err)
	}

	// 3. Escalation from warning -> critical notifies immediately without waiting repeat_after.
	now += 10
	res, err = eng.Observe(context.Background(), map[string]any{
		"rule": "site.down", "subject": "app.example.com", "active": true, "severity": "critical",
	})
	if err != nil || res["transition"] != TransitionEscalated || res["notified"] != true {
		t.Fatalf("expected escalated, got %+v err=%v", res, err)
	}

	// 4. Acknowledge suppresses repeats and removes from Portal().
	if _, err := eng.Quieten(map[string]any{"rule": "site.down", "subject": "app.example.com", "mode": "acknowledge", "by": "admin"}); err != nil {
		t.Fatalf("quieten: %v", err)
	}
	portal := eng.Portal()
	if portal["total"] != 0 || portal["quiet"] != 1 {
		t.Fatalf("expected acked alert hidden from portal, got %+v", portal)
	}

	// 5. Recovery notifies and clears acknowledgement.
	now += 60
	res, err = eng.Observe(context.Background(), map[string]any{
		"rule": "site.down", "subject": "app.example.com", "active": false,
	})
	if err != nil || res["state"] != StateOK || res["transition"] != TransitionRecovered || res["notified"] != true {
		t.Fatalf("expected recovered, got %+v err=%v", res, err)
	}
	st, ok := store.GetState("site.down", "app.example.com")
	if !ok || st.AcknowledgedTS != 0 {
		t.Fatalf("expected ack cleared after recovery, got %+v", st)
	}

	// 6. Storm control caps burst across distinct subjects at StormMaxNotifications within 300s.
	for i := 0; i < StormMaxNotifications+2; i++ {
		_, err := eng.Observe(context.Background(), map[string]any{
			"rule":    "backup.failed",
			"subject": fmt.Sprintf("job-%d", i),
			"summary": "backup error",
		})
		if err != nil {
			t.Fatalf("observe burst %d: %v", i, err)
		}
	}
	_, events := store.Events(EventFilter{Rule: "backup.failed", Limit: 50})
	suppressed := 0
	for _, ev := range events {
		if ev.Transition == TransitionSuppressed {
			suppressed++
		}
	}
	if suppressed == 0 {
		t.Fatalf("expected storm-suppressed events, got %+v", events)
	}
}

func TestSweepStaleExpiredAndDismiss(t *testing.T) {
	now := int64(1700000000)
	store, _ := NewStore("")
	ch := &fakeChannel{name: "email", avail: true}
	eng := NewEngine(DaemonOptions{GatewayName: "gw"}, DefaultConfig(), store, []Channel{ch})
	eng.nowFn = func() int64 { return now }

	// Fire a 0-delay level alert.
	_, err := eng.Observe(context.Background(), map[string]any{
		"rule": "monitoring.storage", "subject": "disk", "active": true,
	})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	// Active non-stale level cannot be dismissed.
	if _, err := eng.Dismiss(map[string]any{"rule": "monitoring.storage", "subject": "disk"}); err == nil {
		t.Fatal("expected active non-stale level dismiss to fail")
	}

	// Past stale_after (900s): marked stale, NOT recovered.
	now += 1000
	counts := eng.Sweep()
	if counts["stale"] != 1 {
		t.Fatalf("expected 1 stale alert, got %+v", counts)
	}
	// Once stale, operator can dismiss it.
	if _, err := eng.Dismiss(map[string]any{"rule": "monitoring.storage", "subject": "disk", "by": "op"}); err != nil {
		t.Fatalf("expected stale level dismiss to succeed: %v", err)
	}
}

func TestResolveWebhookTargetSSRFProtection(t *testing.T) {
	fakeLookup := func(ip string) LookupIPFunc {
		return func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(ip)}, nil
		}
	}

	// Public HTTPS succeeds.
	tgt, err := ResolveWebhookTarget(context.Background(), "https://hooks.example.com/alert", false, fakeLookup("93.184.216.34"))
	if err != nil || tgt.Address != "93.184.216.34" || tgt.Port != 443 {
		t.Fatalf("expected public webhook allowed, got %+v err=%v", tgt, err)
	}
	// HTTP rejected.
	if _, err := ResolveWebhookTarget(context.Background(), "http://hooks.example.com/a", false, fakeLookup("93.184.216.34")); err == nil {
		t.Fatal("http scheme must be rejected")
	}
	// Credentials in URL rejected.
	if _, err := ResolveWebhookTarget(context.Background(), "https://user:pass@hooks.example.com/a", false, fakeLookup("93.184.216.34")); err == nil {
		t.Fatal("URL credentials must be rejected")
	}
	// Loopback and IPv4-mapped IPv6 loopback rejected even with allowPrivate=true.
	for _, badIP := range []string{"127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "::1"} {
		if _, err := ResolveWebhookTarget(context.Background(), "https://hooks.example.com/a", true, fakeLookup(badIP)); err == nil {
			t.Fatalf("expected %s to be rejected even when allowPrivate=true", badIP)
		}
	}
	// Private IP rejected by default, allowed when allowPrivate=true.
	if _, err := ResolveWebhookTarget(context.Background(), "https://hooks.local/a", false, fakeLookup("10.0.0.5")); err == nil {
		t.Fatal("private IP must be rejected by default")
	}
	if _, err := ResolveWebhookTarget(context.Background(), "https://hooks.local/a", true, fakeLookup("10.0.0.5")); err != nil {
		t.Fatalf("private IP must be allowed when allowPrivate=true: %v", err)
	}
}

func TestParseMailQueueStuck(t *testing.T) {
	now := int64(1700005000)
	out := strings.Join([]string{
		`{"queue_name":"active","arrival_time":1700000000,"recipients":[{"delay_reason":"ignored"}]}`,
		`{"queue_name":"deferred","arrival_time":1700004900,"recipients":[{"delay_reason":"too fresh"}]}`,
		`{"queue_name":"deferred","arrival_time":1700000000,"recipients":[{"delay_reason":"Connection timed out"}]}`,
	}, "\n")
	stuck := ParseMailQueueStuck(out, now)
	if len(stuck) != 1 || stuck[0].Reason != "Connection timed out" {
		t.Fatalf("unexpected stuck list: %+v", stuck)
	}
}

func TestUnixSocketHTTPServerAuthAndConfigRedaction(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "alertd.sock")
	cfgPath := filepath.Join(dir, "alertd.json")
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	ch := &fakeChannel{name: "email", avail: true}
	eng := NewEngine(DaemonOptions{ConfigPath: cfgPath, GatewayName: "gw-test"}, DefaultConfig(), store, []Channel{ch})
	eng.lookupHook = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: (&Server{Engine: eng, Token: "tok-123"}).Handler()}
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

	// Unauthenticated POST must fail with 403.
	resp, err := client.Post("http://unix/api/v1/alerts/notify", "application/json", strings.NewReader(`{"rule":"backup.failed"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	// Authenticated config update redacts secret in response and preserves it on "***".
	body := `{"webhook_url":"https://hooks.example.com/secret/token","webhook_header_name":"Authorization","webhook_header_value":"Bearer s3cr3t"}`
	req, _ := http.NewRequest(http.MethodPost, "http://unix/api/v1/alerts/config", bytes.NewBufferString(body))
	req.Header.Set("X-Alertd-Token", "tok-123")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("config post: %v", err)
	}
	var cfgResp struct {
		OK     bool   `json:"ok"`
		Config Config `json:"config"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&cfgResp)
	resp.Body.Close()
	if !cfgResp.OK || cfgResp.Config.WebhookURL != "https://hooks.example.com/***" || cfgResp.Config.WebhookHeaderValue != "***" {
		t.Fatalf("unexpected redacted config: %+v", cfgResp)
	}

	// GET /api/v1/alerts/health works without token.
	resp, err = client.Get("http://unix/api/v1/alerts/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if health["ok"] != true || int(health["rules"].(float64)) != len(Rules) {
		t.Fatalf("unexpected health: %+v", health)
	}
}

package alerts

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestObserveOverUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "alertd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var gotPath string
	var gotToken string
	var gotObs Observation
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotToken = r.Header.Get(TokenHeader)
			_ = json.NewDecoder(r.Body).Decode(&gotObs)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	disabled := NewClient(sock, "")
	if disabled.Observe(context.Background(), Observation{Rule: "site.down", Subject: "be_app", Active: BoolPtr(true)}) {
		t.Fatal("disabled client must not send")
	}

	c := NewClient(sock, "secret-token")
	ok := c.Observe(context.Background(), Observation{
		Rule:    "http.error_ratio",
		Subject: "be_app",
		Active:  BoolPtr(true),
		Summary: "5xx rate high",
		Detail:  "ratio=12%",
	})
	if !ok {
		t.Fatal("expected alert observation to succeed")
	}
	if gotPath != "/api/v1/alerts/notify" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
	if gotToken != "secret-token" || gotObs.Rule != "http.error_ratio" || gotObs.Subject != "be_app" || gotObs.Active == nil || !*gotObs.Active {
		t.Fatalf("unexpected received observation: token=%q obs=%+v", gotToken, gotObs)
	}
}

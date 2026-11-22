package alerts

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestReportOverUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "alertd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var gotToken string
	var gotEvent Event
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotToken = r.Header.Get("X-Alert-Token")
			_ = json.NewDecoder(r.Body).Decode(&gotEvent)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	disabled := NewClient(sock, "")
	if disabled.Report(context.Background(), Event{Rule: "site.down", Subject: "be_app"}) {
		t.Fatal("disabled client must not send")
	}

	c := NewClient(sock, "secret-token")
	ok := c.Report(context.Background(), Event{
		Rule:    "http.error_ratio",
		Subject: "be_app",
		State:   "firing",
		Summary: "5xx rate high",
	})
	if !ok {
		t.Fatal("expected alert report to succeed")
	}
	if gotToken != "secret-token" || gotEvent.Rule != "http.error_ratio" || gotEvent.Subject != "be_app" {
		t.Fatalf("unexpected received alert: token=%q event=%+v", gotToken, gotEvent)
	}
}

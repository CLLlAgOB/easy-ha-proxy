package healthd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestControlRejectsNullPayloadAndLeadingDashName(t *testing.T) {
	cfg := testConfig(t)
	st := NewState(cfg, "haproxy-healthd.service", fakeRunner(t))
	srv := &Server{State: st, ControlToken: "tok"}

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"null json", "null", "payload must be a JSON object"},
		{"leading dash", `{"kind":"systemd","name":"--version","action":"restart"}`, "name is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/control", bytes.NewBufferString(tc.body))
			req.Header.Set("X-Healthd-Token", "tok")
			req.Header.Set("Content-Length", strconv.Itoa(len(tc.body)))
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != 400 || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("expected 400 containing %q, got %d: %s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

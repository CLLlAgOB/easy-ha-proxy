package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditRedactRecordAndQuery(t *testing.T) {
	redacted := Redact(map[string]any{
		"user":     "admin",
		"password": "secret-value",
		"nested": map[string]any{
			"api_token": "tok-999",
			"safe":      "ok",
		},
	}).(map[string]any)

	if redacted["password"] != "***" {
		t.Fatalf("expected password redacted, got %v", redacted["password"])
	}
	nested := redacted["nested"].(map[string]any)
	if nested["api_token"] != "***" || nested["safe"] != "ok" {
		t.Fatalf("unexpected nested redaction: %+v", nested)
	}

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	st := Open(dbPath)
	st.Record("alice", "10.0.0.1", "ssh.unban", "ip", "203.0.113.5", ResultSuccess, "unbanned", "", nil, map[string]any{"secret": "x"})
	st.Record("bob", "10.0.0.2", "service.control", "systemd", "haproxy.service", ResultDenied, "reload", "superadmin required", nil, nil)

	res := st.Query(QueryFilter{Action: "ssh.unban", Result: ResultSuccess, Limit: 10})
	events := res["events"].([]Event)
	if len(events) != 1 || events[0].Actor != "alice" {
		t.Fatalf("unexpected query result: %+v", res)
	}
	if strings.Contains(events[0].AfterJSON, `"x"`) {
		t.Fatalf("secret leaked into after_json: %s", events[0].AfterJSON)
	}

	// Re-open from disk and confirm persistence.
	st2 := Open(dbPath)
	if st2.Stats()["row_count"] != 2 {
		t.Fatalf("expected 2 persisted rows, got %+v", st2.Stats())
	}
	if actors := st2.Distinct("actor"); len(actors) != 2 || actors[0] != "alice" || actors[1] != "bob" {
		t.Fatalf("unexpected distinct actors: %+v", actors)
	}
}

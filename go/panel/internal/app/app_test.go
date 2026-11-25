package app

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/pyyaml"
)

func testApp(t *testing.T) *App {
	t.Helper()
	cfg := &config.Config{SecretKey: "test-secret"}
	return New(cfg, nil, "../../web/templates")
}

// TestURLForVectors builds every endpoint's URL the way Flask did
// (testdata/url_for.json.gz, generated from the Flask url_map).
func TestURLForVectors(t *testing.T) {
	fh, err := os.Open("testdata/url_for.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []json.RawMessage
	if err := json.NewDecoder(zr).Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	a := testApp(t)
	c := &Ctx{App: a}
	for _, raw := range vectors {
		v, err := pyyaml.JSONLoads(raw)
		if err != nil {
			t.Fatal(err)
		}
		m := v.(*pyyaml.Map)
		endpoint := m.Value("endpoint").(string)
		got, err := c.urlFor(endpoint, m.Value("values").(*pyyaml.Map))
		if err != nil {
			t.Errorf("%s: %v", endpoint, err)
			continue
		}
		if endpoint == "static" {
			got, _, _ = strings.Cut(got, "?v=")
		}
		if want := m.Value("url").(string); got != want {
			t.Errorf("%s: want %q got %q", endpoint, want, got)
		}
	}
}

// TestRouterMatchesEveryRule checks that each Flask rule's own URL matches
// back to its endpoint.
func TestRouterMatchesEveryRule(t *testing.T) {
	a := testApp(t)
	c := &Ctx{App: a}
	for _, r := range flaskRules {
		if r.endpoint == "static" || strings.HasSuffix(r.endpoint, ".static") {
			continue
		}
		kw := pyyaml.NewMap()
		for _, n := range a.Router.ArgNames(r.endpoint) {
			kw.Set(n, "sample")
		}
		u, err := c.urlFor(r.endpoint, kw)
		if err != nil {
			t.Fatal(err)
		}
		m := a.Router.Match(r.methods[0], u)
		if m.Rule == nil || m.Rule.endpoint != r.endpoint {
			got := "<none>"
			if m.Rule != nil {
				got = m.Rule.endpoint
			}
			t.Errorf("%s %s matched %s", r.methods[0], u, got)
		}
	}
	if m := a.Router.Match("GET", "/system/backups"); m.Redirect != "/system/backups/" {
		t.Errorf("strict slash redirect: %+v", m)
	}
	if m := a.Router.Match("DELETE", "/haproxy/sites"); len(m.Allowed) == 0 {
		t.Errorf("expected 405 for DELETE /haproxy/sites")
	}
}

// TestSimplePagesRender renders the template-only pages.
func TestSimplePagesRender(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/", "/monitoring", "/system/health", "/system/audit", "/haproxy/trash", "/security/adaptive", "/debug/"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		a.ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<!doctype html>") {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body.String()[:min(300, rec.Body.Len())])
		}
	}
}

func TestAutomaticOptions(t *testing.T) {
	a := testApp(t)
	a.Router = NewRouter([]flaskRule{
		{endpoint: "test.write", rule: "/write", methods: []string{http.MethodPost}},
		{endpoint: "test.writeSlash", rule: "/write-slash/", methods: []string{http.MethodPost}, strictSlashes: true},
	})
	unexpectedHandler := func(*Ctx) error {
		t.Fatal("automatic OPTIONS called the route handler")
		return nil
	}
	a.Handle("test.write", unexpectedHandler)
	a.Handle("test.writeSlash", unexpectedHandler)
	for _, tc := range []struct {
		path, allow string
		status      int
	}{
		{"/write", "OPTIONS, POST", http.StatusOK},
		{"/write-slash?x=1", "", http.StatusPermanentRedirect},
		{"/missing", "", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, tc.path, nil))
		if rec.Code != tc.status || rec.Header().Get("Allow") != tc.allow {
			t.Errorf("OPTIONS %s: got %d, headers %v", tc.path, rec.Code, rec.Header())
		}
		if tc.status == http.StatusOK && rec.Body.Len() != 0 {
			t.Errorf("OPTIONS %s returned a body", tc.path)
		}
	}
}

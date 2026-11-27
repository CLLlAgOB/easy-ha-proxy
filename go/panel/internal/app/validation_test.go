package app

import (
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// HAProxy evaluates log-format %[...] inside a set-header value, so an
// add_headers value must not carry a '%' that could read a sample fetch
// (e.g. %[env(HAPROXY_ADMIN_PROXY_SECRET)]) into the response.
func TestAddHeadersRejectFormatStrings(t *testing.T) {
	site, _ := pyyaml.Load([]byte("name: app\ndomain: app.example.com\nadd_headers:\n  X-Leak: '%[env(HAPROXY_ADMIN_PROXY_SECRET)]'\n"))
	if err := validateSite(site, 0); err == nil || !strings.Contains(err.Error(), "unsafe characters") {
		t.Fatalf("a log-format header value was accepted: %v", err)
	}
	safe, _ := pyyaml.Load([]byte("name: app\ndomain: app.example.com\nadd_headers:\n  X-Ok: 'plain value'\n"))
	if err := validateSite(safe, 0); err != nil {
		t.Fatalf("a plain header value was refused: %v", err)
	}
}

func TestProtectedVarsIncludeHostOwnedPaths(t *testing.T) {
	for _, key := range []string{"haproxy_mtls_dir", "haproxy_socket", "metrics_export_enabled"} {
		found := false
		for _, k := range protectedVarsKeys {
			if k == key {
				found = true
			}
		}
		if !found {
			t.Errorf("host-owned variable %s is not protected", key)
		}
	}
}

func TestSiteAndDefaultValidationCoverRenderedValues(t *testing.T) {
	for _, tc := range []struct{ kind, yaml, field string }{
		{"vars", "site_defaults:\n  health_uri: '/status extra'\n", "health_uri"},
		{"vars", "site_defaults:\n  err_window: '20s extra'\n", "err_window"},
		{"vars", "site_defaults:\n  add_headers:\n    X-Test: '100%'\n", "add_headers"},
		{"vars", "site_defaults:\n  other_err_exclude_exact:\n  - path: /health\n    methods: ['GET extra']\n", "methods"},
		{"websites", "sites:\n- name: test\n  domain: app.example.com\n  backend_sni: 'tls(example.com)'\n", "backend_sni"},
		{"websites", "sites:\n- name: test\n  domain: app.example.com\n  err_limit: many\n", "err_limit"},
		{"websites", "sites:\n- name: test\n  domain: app.example.com\n  err_exclude:\n  - path_beg: '/images extra'\n", "err_exclude"},
		{"vars", "site_defaults:\n  health_uri: /ready\n  rate_window: 20s\n  err_limit: 20\n  err_exclude:\n  - path_reg: '^/alt\\.[a-z]+$'\n    methods: [GET, HEAD]\n", ""},
	} {
		v, err := pyyaml.Load([]byte(tc.yaml))
		if err != nil {
			t.Fatal(err)
		}
		err = ValidateConfigData(tc.kind, v.(*Map))
		if tc.field == "" {
			if err != nil {
				t.Errorf("valid settings rejected: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("invalid %s: %v", tc.field, err)
		}
	}
}

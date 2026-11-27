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

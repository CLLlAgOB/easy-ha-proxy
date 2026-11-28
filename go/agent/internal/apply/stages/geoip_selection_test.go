package stages

import (
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
)

// controld's config transactions and the GeoIP updater write selection.json
// as json.dumps(indent=2) + "\n"; this stage wrote Ansible's to_nice_json
// (indent 4, no final newline). After any apply from the panel every update
// rewrote the file and rebuilt the GeoIP release although nothing changed.

func geoipSelectionFile(t *testing.T, extra map[string]any) *engine.File {
	t.Helper()
	part := Part{Name: "geoip_acl/geoip", Role: "geoip_acl", File: "geoip"}
	// Managed-config sync on: the stage takes the managed variables and does
	// not read the panel's runtime vars.yml.
	extra["haproxy_admin_sync_managed_config"] = true
	b := &Builder{Set: mustSetWith(t, repoRoot(t), part, extra)}
	steps := geoip(b)
	if _, err := steps[stepAt(t, steps, "Select the effective runtime GeoIP settings")].Build(nil); err != nil {
		t.Fatal(err)
	}
	res, err := steps[stepAt(t, steps, "Synchronize the runtime GeoIP country selection")].Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	file, ok := res.(*engine.File)
	if !ok {
		t.Fatalf("the selection step builds %T, not a file", res)
	}
	return file
}

func TestTheGeoIPStageWritesTheSelectionAsTheUpdaterDoes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		vars      map[string]any
		countries []string
		enabled   bool
	}{
		{"filter off, no countries", map[string]any{"enable_geoip": false, "geoip_country_codes": []any{}}, []string{}, false},
		{"filter on, countries normalized", map[string]any{"enable_geoip": true,
			"geoip_country_codes": []any{"ru", "DE", "de"}}, []string{"DE", "RU"}, true},
		{"filter off, countries kept", map[string]any{"enable_geoip": false,
			"geoip_country_codes": []any{"FR"}}, []string{"FR"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := geoipSelectionFile(t, tc.vars)
			if want := string(tools.SelectionJSON(tc.countries, tc.enabled)); string(file.Content) != want {
				t.Fatalf("selection.json:\n%q\nwant the updater's form:\n%q", file.Content, want)
			}
			if file.Path != "/etc/haproxy/geoip/selection.json" {
				t.Fatalf("path %s", file.Path)
			}
		})
	}
}

func TestTheGeoIPSelectionFormHasNotChanged(t *testing.T) {
	// Gateways hold files in this form; changing it rewrites every one of them
	// and rebuilds its GeoIP release once.
	want := "{\n  \"access_filter_enabled\": true,\n  \"countries\": [\n    \"DE\",\n    \"RU\"\n  ],\n  \"version\": 1\n}\n"
	if got := string(tools.SelectionJSON([]string{"DE", "RU"}, true)); got != want {
		t.Fatalf("selection.json form changed:\n%q", got)
	}
	if got := string(tools.SelectionJSON([]string{}, false)); got != "{\n  \"access_filter_enabled\": false,\n  \"countries\": [],\n  \"version\": 1\n}\n" {
		t.Fatalf("empty selection form changed:\n%q", got)
	}
}

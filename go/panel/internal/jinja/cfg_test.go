package jinja

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"easy-ha-proxy/panel/internal/pyyaml"
)

// TestHAProxyCfgVectors renders haproxy.cfg.j2 on contexts the Flask renderer
// produced (JINJA_CFG_VECTORS points at the gzipped cases) and compares.
func TestHAProxyCfgVectors(t *testing.T) {
	path := os.Getenv("JINJA_CFG_VECTORS")
	tmplPath := os.Getenv("JINJA_CFG_TEMPLATE")
	if path == "" || tmplPath == "" {
		t.Skip("JINJA_CFG_VECTORS/JINJA_CFG_TEMPLATE not set")
	}
	src, err := os.ReadFile(tmplPath)
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.NewDecoder(zr).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	env := NewEnvironment(func(string) (string, error) { return string(src), nil })
	env.Autoescape = false
	env.TrimBlocks = true
	env.LstripBlocks = true
	env.Filters["regex_replace"] = RegexReplaceFilter
	env.Filters["combine"] = CombineFilter
	failures := 0
	for i, c := range raw.Cases {
		v, err := pyyaml.JSONLoads(c)
		if err != nil {
			t.Fatal(err)
		}
		m := v.(*pyyaml.Map)
		ctxMap := m.Value("context").(*pyyaml.Map)
		vars := map[string]any{}
		ctxMap.Each(func(k, val any) { vars[k.(string)] = val })
		got, err := env.Render("haproxy.cfg.j2", vars)
		want, hasOut := m.Get("out")
		if !hasOut {
			if err == nil {
				failures++
				t.Errorf("case %d: python failed (%v) but go rendered", i, m.Value("error"))
			}
			continue
		}
		if err != nil {
			failures++
			t.Errorf("case %d: go error %v", i, err)
		} else if got != want.(string) {
			failures++
			wl := strings.Split(want.(string), "\n")
			gl := strings.Split(got, "\n")
			for j := 0; j < len(wl) || j < len(gl); j++ {
				var a, b string
				if j < len(wl) {
					a = wl[j]
				}
				if j < len(gl) {
					b = gl[j]
				}
				if a != b {
					t.Errorf("case %d line %d:\n want %q\n got  %q", i, j+1, a, b)
					break
				}
			}
		}
		if failures > 8 {
			t.Fatal("too many failures")
		}
	}
	t.Logf("%d cases", len(raw.Cases))
}

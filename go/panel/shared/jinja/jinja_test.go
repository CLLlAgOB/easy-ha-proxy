package jinja

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

type vector struct {
	Templates map[string]string `json:"templates"`
	Name      string            `json:"name"`
	Out       *string           `json:"out"`
	Error     string            `json:"error"`
}

// TestJinjaVectors renders cases whose expected output came from Flask's own
// Jinja2 environment (testdata/vectors.json.gz).
func TestJinjaVectors(t *testing.T) {
	fh, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Ctx     json.RawMessage `json:"ctx"`
		Vectors []vector        `json:"vectors"`
	}
	if err := json.NewDecoder(zr).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	ctxVal, err := pyyaml.JSONLoads(raw.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{}
	ctxVal.(*pyyaml.Map).Each(func(k, v any) { ctx[k.(string)] = v })
	for _, v := range raw.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			env := NewEnvironment(func(name string) (string, error) {
				src, ok := v.Templates[name]
				if !ok {
					return "", fmt.Errorf("template %s not found", name)
				}
				return src, nil
			})
			got, err := env.Render(v.Name, ctx)
			if v.Out == nil {
				if err == nil {
					t.Fatalf("expected error %q, got output %q", v.Error, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("render error: %v\nsource: %s", err, v.Templates[v.Name])
			}
			want := *v.Out
			if strings.Contains(want, " at 0x") {
				// repr of a bound method carries an address
				return
			}
			if got != want {
				t.Fatalf("mismatch\nsource: %s\nwant: %q\ngot:  %q", v.Templates[v.Name], want, got)
			}
		})
	}
}

// TestParsePanelTemplates parses every template the panel renders. They live
// in go/panel/web; read from their earlier place, the test skipped itself.
func TestParsePanelTemplates(t *testing.T) {
	dir := filepath.Join("..", "..", "web", "templates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("the panel templates are missing:", err)
	}
	if len(entries) == 0 {
		t.Fatal("no panel templates in", dir)
	}
	for _, e := range entries {
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parse(e.Name(), string(src)); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
	}
}

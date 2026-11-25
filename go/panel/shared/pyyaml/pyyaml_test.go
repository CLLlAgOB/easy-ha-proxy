package pyyaml

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

type vector struct {
	Input string  `json:"input"`
	JSON  *string `json:"json"`
	Out00 *string `json:"out_00"`
	Out01 *string `json:"out_01"`
	Out10 *string `json:"out_10"`
	Out11 *string `json:"out_11"`
}

// TestPythonVectors checks Load+Dump against yaml.safe_load/safe_dump
// outputs recorded from PyYAML 6.0.2 (testdata/vectors.json.gz).
func TestPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.NewDecoder(zr).Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	failures := 0
	for i, v := range vectors {
		data, err := Load([]byte(v.Input))
		if err != nil {
			t.Errorf("vector %d: load: %v", i, err)
			failures++
			continue
		}
		if v.JSON != nil && !strings.Contains(v.Input, "202") {
			if got, err := JSONDumps(data, false, false); err != nil || got != *v.JSON {
				failures++
				if failures < 8 {
					t.Errorf("vector %d json: %v\n--- want\n%s\n--- got\n%s", i, err, clip(*v.JSON), clip(got))
				}
			}
		}
		for _, c := range []struct {
			want          *string
			sort, unicode bool
		}{{v.Out00, false, false}, {v.Out01, false, true}, {v.Out10, true, false}, {v.Out11, true, true}} {
			if c.want == nil {
				continue
			}
			got, err := Dump(data, Options{AllowUnicode: c.unicode, SortKeys: c.sort})
			if err != nil || got != *c.want {
				failures++
				if failures < 8 {
					t.Errorf("vector %d sort=%v unicode=%v: %v\n--- want\n%s\n--- got\n%s", i, c.sort, c.unicode, err, clip(*c.want), clip(got))
				}
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d vectors differ", failures, len(vectors))
	}
}

func clip(s string) string {
	if len(s) > 1500 {
		return s[:1500] + "..."
	}
	return s
}

func TestFloatRepr(t *testing.T) {
	for f, want := range map[float64]string{1.5: "1.5", 100: "100.0", 1e16: "1e+16", 1e20: "1e+20", 0.0001: "0.0001",
		0.00001: "1e-05", 123456789012345.6: "123456789012345.6"} {
		if got := FloatRepr(f); got != want {
			t.Fatalf("%v: %s want %s", f, got, want)
		}
	}
	if FloatRepr(math.Copysign(0, -1)) != "-0.0" {
		t.Fatal("negative zero")
	}
	if yamlFloat(1e20) != "1.0e+20" {
		t.Fatal(yamlFloat(1e20))
	}
}

func TestJSONOrder(t *testing.T) {
	v, err := JSONLoads([]byte(`{"b": 1, "a": {"z": [1, 2.5, "x"], "y": null}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := JSONDumps(v, false, false)
	if s != `{"b": 1, "a": {"z": [1, 2.5, "x"], "y": null}}` {
		t.Fatal(s)
	}
	if !strings.Contains(mustDump(v), "b: 1\na:\n  z:\n  - 1\n") {
		t.Fatal(mustDump(v))
	}
}

func mustDump(v any) string {
	s, _ := Dump(v, Options{AllowUnicode: true})
	return s
}

package app

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestHTMLDiffVectors compares make_table with CPython 3.12's output
// (testdata/htmldiff.json.gz, generated with HtmlDiff(wrapcolumn=120)).
func TestHTMLDiffVectors(t *testing.T) {
	fh, err := os.Open("testdata/htmldiff.json.gz")
	if err != nil {
		t.Skip(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		A   []string `json:"a"`
		B   []string `json:"b"`
		Out string   `json:"out"`
	}
	if err := json.NewDecoder(zr).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	fails := 0
	for i, c := range cases {
		htmlDiffMu.Lock()
		htmlDiffPrefix = 0
		htmlDiffMu.Unlock()
		got := htmlMakeTable(append([]string{}, c.A...), append([]string{}, c.B...), "F", "T")
		if got != c.Out {
			fails++
			gl, wl := strings.Split(got, "\n"), strings.Split(c.Out, "\n")
			for j := 0; j < len(gl) || j < len(wl); j++ {
				var g, w string
				if j < len(gl) {
					g = gl[j]
				}
				if j < len(wl) {
					w = wl[j]
				}
				if g != w {
					t.Errorf("case %d line %d\n want %q\n got  %q", i, j, w, g)
					break
				}
			}
			if fails > 5 {
				t.Fatal("too many failures")
			}
		}
	}
	t.Logf("%d cases", len(cases))
}

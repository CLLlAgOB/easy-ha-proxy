package pyyaml

import (
	"math"
	"testing"
)

func TestJSONDumpsParitySpecialFloatsAndUnescapedKeys(t *testing.T) {
	m := NewMap()
	m.Set("a<b&c>d", "x<y&z>")
	m.Set("nan", math.NaN())
	m.Set("pos_inf", math.Inf(1))
	m.Set("neg_inf", math.Inf(-1))

	got, err := JSONDumps(m, false, true)
	if err != nil {
		t.Fatalf("JSONDumps failed: %v", err)
	}
	want := `{"a<b&c>d":"x<y&z>","nan":NaN,"pos_inf":Infinity,"neg_inf":-Infinity}`
	if got != want {
		t.Fatalf("JSONDumps mismatch:\n got: %s\nwant: %s", got, want)
	}
}

package pyyaml

import "testing"

func TestMergeResolution(t *testing.T) {
	raw := []byte("a: &a {one: 1, both: first}\nb: &b {two: 2, both: second}\nresult: {<<: [*a, *b], two: 3}\n")
	v, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	result := v.(*Map).Value("result").(*Map)
	if result.Value("both") != "first" || result.Value("two") != int64(3) || result.Value("one") != int64(1) {
		t.Fatalf("wrong merge precedence: %v", result)
	}
	for _, invalid := range []string{"x: &item {<<: *item}", "x: !!int '+'"} {
		if _, err := Load([]byte(invalid)); err == nil {
			t.Fatal("expected invalid input to be rejected")
		}
	}
}

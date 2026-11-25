package vars

import (
	"errors"
	"reflect"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func TestLiteralEvalReadsWhatPythonPrints(t *testing.T) {
	m := pyyaml.NewMap()
	m.Set("a", int64(1))
	m.Set("b", []any{true, nil, "x'y"})
	m.Set(int64(3), 2.5)
	cases := []struct {
		in   string
		want any
	}{
		{"True", true},
		{"False", false},
		{"[]", []any{}},
		{"['a', \"b\", 1, -2, 0x10, 1_000]", []any{"a", "b", int64(1), int64(-2), int64(16), int64(1000)}},
		{"{'a': 1, 'b': [True, None, \"x'y\"], 3: 2.5}", m},
		{"(1, 'two')", []any{int64(1), "two"}},
		{"[(1,), ()]", []any{[]any{int64(1)}, []any{}}},
		{"['a\\nb\\t\\x41\\u00e9\\\\']", []any{"a\nb\tAé\\"}},
		{"['ab' 'cd']", []any{"abcd"}},
		{"[r'\\d+']", []any{"\\d+"}},
		{"[1.5e3, .5, -0.0]", []any{1500.0, 0.5, -0.0}},
		{"{}", pyyaml.NewMap()},
	}
	for _, c := range cases {
		got, err := literalEval(c.in)
		if err != nil {
			t.Errorf("literalEval(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("literalEval(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestLiteralEvalRefusesWhatItIsNot(t *testing.T) {
	for _, in := range []string{
		"[abc]", "{1, 2}", "[b'x']", "[1 2]", "{'a' 1}", "[012]", "['unterminated]", "True False",
		"[1j]", "{[1]: 2}", "",
	} {
		if v, err := literalEval(in); !errors.Is(err, errNotLiteral) {
			t.Errorf("literalEval(%q) = %#v, %v; want errNotLiteral", in, v, err)
		}
	}
}

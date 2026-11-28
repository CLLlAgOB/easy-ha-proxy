package jinja

import (
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// to_json, to_nice_json, to_nice_yaml and ternary as Ansible writes them
// (the expected text came from Python's json and yaml with Ansible's
// arguments).
func TestAnsibleSerialisingFiltersMatchPython(t *testing.T) {
	value, err := pyyaml.JSONLoads([]byte("{\"enabled\": false, \"from\": \"a@b\", \"only_for\": [\"x\", \"\\u00fc\"], \"to\": \"\", \"n\": 3, \"f\": 1.5, \"z\": null, \"nested\": {\"b\": [1, {\"q\": \"w\\\"x\"}], \"a\": {}}}"))
	if err != nil {
		t.Fatal(err)
	}
	env := NewEnvironment(nil)
	env.Autoescape = false
	AddAnsibleFilters(env)
	for _, c := range []struct{ tmpl, want string }{
		{"{{ v | to_nice_json }}", "{\n    \"enabled\": false,\n    \"f\": 1.5,\n    \"from\": \"a@b\",\n    \"n\": 3,\n    \"nested\": {\n        \"a\": {},\n        \"b\": [\n            1,\n            {\n                \"q\": \"w\\\"x\"\n            }\n        ]\n    },\n    \"only_for\": [\n        \"x\",\n        \"\\u00fc\"\n    ],\n    \"to\": \"\",\n    \"z\": null\n}"},
		{"{{ v | to_json }}", "{\"enabled\": false, \"from\": \"a@b\", \"only_for\": [\"x\", \"\\u00fc\"], \"to\": \"\", \"n\": 3, \"f\": 1.5, \"z\": null, \"nested\": {\"b\": [1, {\"q\": \"w\\\"x\"}], \"a\": {}}}"},
		{"{{ v | to_nice_yaml(indent=2) }}", "enabled: false\nf: 1.5\nfrom: a@b\nn: 3\nnested:\n  a: {}\n  b:\n  - 1\n  - q: w\"x\nonly_for:\n- x\n- \u00fc\nto: ''\nz: null\n"},
		{"{{ v.enabled | ternary('true', 'false') }}", "false"},
		{"{{ v.n | ternary('yes', 'no') }}", "yes"},
	} {
		tpl, err := env.FromString("t", c.tmpl)
		if err != nil {
			t.Fatal(err)
		}
		got, err := env.RenderTemplate(tpl, map[string]any{"v": value})
		if err != nil {
			t.Fatalf("%s: %v", c.tmpl, err)
		}
		if got != c.want {
			t.Errorf("%s:\ngot  %q\nwant %q", c.tmpl, got, c.want)
		}
	}
}

// indent as Jinja's do_indent writes it (expected text from jinja2 itself).
func TestIndentMatchesJinja(t *testing.T) {
	env := NewEnvironment(nil)
	env.Autoescape = false
	for _, c := range []struct{ in, four, twoFirst string }{
		{"a\nb\n", "a\n    b\n", "  a\n  b\n"},
		{"a\n\nb", "a\n\n    b", "  a\n\n  b"},
		{"x", "x", "  x"},
		{"", "", "  "},
	} {
		for tmpl, want := range map[string]string{"{{ s | indent(4) }}": c.four, "{{ s | indent(2, true) }}": c.twoFirst} {
			tpl, err := env.FromString("t", tmpl)
			if err != nil {
				t.Fatal(err)
			}
			got, err := env.RenderTemplate(tpl, map[string]any{"s": c.in})
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%q %s: got %q, want %q", c.in, tmpl, got, want)
			}
		}
	}
}

// The keywords Ansible passes to json.dumps (expected text from Python).
func TestJSONFilterKeywordsMatchPython(t *testing.T) {
	value, err := pyyaml.JSONLoads([]byte("{\"s\": \"[dev] \\u0423\\u0432\\u0435\\u0434\\u043e\\u043c\\u043b\\u0435\\u043d\\u0438\\u0435 \\u00fc\\ud83d\\ude00\", \"b\": [1, \"x\"], \"a\": null}"))
	if err != nil {
		t.Fatal(err)
	}
	env := NewEnvironment(nil)
	env.Autoescape = false
	AddAnsibleFilters(env)
	for tmpl, want := range map[string]string{
		"{{ v | to_json(ensure_ascii=False) }}":            "{\"s\": \"[dev] Уведомление ü😀\", \"b\": [1, \"x\"], \"a\": null}",
		"{{ v | to_nice_json(ensure_ascii=False) }}":       "{\n    \"a\": null,\n    \"b\": [\n        1,\n        \"x\"\n    ],\n    \"s\": \"[dev] Уведомление ü😀\"\n}",
		"{{ v | to_json(sort_keys=True) }}":                "{\"a\": null, \"b\": [1, \"x\"], \"s\": \"[dev] \\u0423\\u0432\\u0435\\u0434\\u043e\\u043c\\u043b\\u0435\\u043d\\u0438\\u0435 \\u00fc\\ud83d\\ude00\"}",
		"{{ v.s | string | to_json(ensure_ascii=False) }}": "\"[dev] Уведомление ü😀\"",
	} {
		tpl, err := env.FromString("t", tmpl)
		if err != nil {
			t.Fatal(err)
		}
		got, err := env.RenderTemplate(tpl, map[string]any{"v": value})
		if err != nil {
			t.Fatalf("%s: %v", tmpl, err)
		}
		if got != want {
			t.Errorf("%s:\ngot  %q\nwant %q", tmpl, got, want)
		}
	}
}

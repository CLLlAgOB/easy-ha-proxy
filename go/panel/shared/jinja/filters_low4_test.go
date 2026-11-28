package jinja

import "testing"

func TestJoinEscapesItemsWhenSeparatorIsMarkup(t *testing.T) {
	env := NewEnvironment(nil)
	env.Autoescape = true
	tmpl, err := env.FromString("join", `{{ items|join("<br>"|safe) }}`)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	got, err := env.RenderTemplate(tmpl, map[string]any{
		"items": []any{"<b>a</b>", "c&d"},
	})
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	want := "&lt;b&gt;a&lt;/b&gt;<br>c&amp;d"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRoundNegativePrecision(t *testing.T) {
	env := NewEnvironment(nil)
	tmpl, err := env.FromString("round", `{{ 1234|round(-2) }} {{ 1250|round(-2) }}`)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	got, err := env.RenderTemplate(tmpl, nil)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if got != "1200.0 1200.0" {
		t.Fatalf("got %q, want %q", got, "1200.0 1200.0")
	}
}

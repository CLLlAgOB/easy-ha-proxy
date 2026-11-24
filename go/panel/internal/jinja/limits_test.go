package jinja

import (
	"strings"
	"testing"
)

func TestMED24FormatIndexBoundsNoPanic(t *testing.T) {
	env := NewEnvironment(nil)
	for _, tmpl := range []string{
		`{{ "{0.}".format("x") }}`,
		`{{ "{9999999999999999999999999999}".format("x") }}`,
		`{{ "{1}".format("only-one") }}`,
	} {
		parsed, err := env.FromString("test", tmpl)
		if err != nil {
			t.Fatalf("parse %q failed unexpectedly: %v", tmpl, err)
		}
		if _, err := env.RenderTemplate(parsed, nil); err == nil {
			t.Fatalf("expected controlled error for %q, got nil", tmpl)
		}
	}
	// Valid positional format still works.
	parsed, err := env.FromString("ok", `{{ "{0}-{1}".format("a", "b") }}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := env.RenderTemplate(parsed, nil)
	if err != nil || got != "a-b" {
		t.Fatalf("unexpected format result: %q err=%v", got, err)
	}
}

func TestMED24RecursionAndExecutionBudgets(t *testing.T) {
	t.Run("cyclic include hits recursion limit", func(t *testing.T) {
		env := NewEnvironment(func(name string) (string, error) {
			return `{% include "self.html" %}`, nil
		})
		if _, err := env.Render("self.html", nil); err == nil || !strings.Contains(err.Error(), "recursion depth") {
			t.Fatalf("expected recursion depth error, got %v", err)
		}
	})

	t.Run("cyclic extends hits recursion limit", func(t *testing.T) {
		env := NewEnvironment(func(name string) (string, error) {
			if name == "a.html" {
				return `{% extends "b.html" %}`, nil
			}
			return `{% extends "a.html" %}`, nil
		})
		if _, err := env.Render("a.html", nil); err == nil || !strings.Contains(err.Error(), "recursion depth") {
			t.Fatalf("expected extends recursion depth error, got %v", err)
		}
	})

	t.Run("recursive macro hits recursion limit", func(t *testing.T) {
		env := NewEnvironment(nil)
		parsed, err := env.FromString("macro", `{% macro m(n) %}{{ m(n + 1) }}{% endmacro %}{{ m(0) }}`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.RenderTemplate(parsed, nil); err == nil || !strings.Contains(err.Error(), "recursion depth") {
			t.Fatalf("expected macro recursion depth error, got %v", err)
		}
	})

	t.Run("deeply nested expression hits parser depth limit", func(t *testing.T) {
		env := NewEnvironment(nil)
		deep := "{{ " + strings.Repeat("(", 100) + "1" + strings.Repeat(")", 100) + " }}"
		if _, err := env.FromString("deep", deep); err == nil || !strings.Contains(err.Error(), "nesting depth") {
			t.Fatalf("expected parser nesting depth error, got %v", err)
		}
	})

	t.Run("string repetition and exponentiation are bounded", func(t *testing.T) {
		env := NewEnvironment(nil)
		for _, expr := range []string{
			`{{ "a" * 100000000 }}`,
			`{{ [1, 2] * 1000000 }}`,
			`{{ 2 ** 1000000000 }}`,
			`{{ 2 ** 63 }}`,
		} {
			parsed, err := env.FromString("bound", expr)
			if err != nil {
				t.Fatalf("parse %q: %v", expr, err)
			}
			if _, err := env.RenderTemplate(parsed, nil); err == nil {
				t.Fatalf("expected bounded error for %q", expr)
			}
		}
		// Valid small powers and repeats keep working.
		parsed, err := env.FromString("valid", `{{ 2 ** 10 }}-{{ "ab" * 3 }}`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := env.RenderTemplate(parsed, nil)
		if err != nil || got != "1024-ababab" {
			t.Fatalf("unexpected valid result: %q err=%v", got, err)
		}
	})

	t.Run("execution step budget stops huge nested loops", func(t *testing.T) {
		env := NewEnvironment(nil)
		env.MaxRenderSteps = 200_000
		parsed, err := env.FromString("loop", `{% for i in range(1000) %}{% for j in range(1000) %}x{% endfor %}{% endfor %}`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.RenderTemplate(parsed, nil); err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("expected execution budget error, got %v", err)
		}
	})

	// haproxy.cfg.j2 takes some 250-500 steps per site: the default must
	// render a gateway of thousands of sites, which the earlier 200,000-step
	// cap refused between 400 and 800 plain ones.
	t.Run("default budget renders a large configuration", func(t *testing.T) {
		env := NewEnvironment(nil)
		parsed, err := env.FromString("big", `{% for i in range(1000) %}{% for j in range(1000) %}x{% endfor %}{% endfor %}`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := env.RenderTemplate(parsed, nil)
		if err != nil || len(got) != 1_000_000 {
			t.Fatalf("a million-iteration render failed: len=%d err=%v", len(got), err)
		}
	})
}

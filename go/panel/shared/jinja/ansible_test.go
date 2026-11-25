package jinja

import (
	"errors"
	"testing"
)

func TestAnsibleBoolFollowsToBool(t *testing.T) {
	cases := []struct {
		in   any
		want bool
	}{
		{true, true}, {false, false}, {nil, false},
		{"yes", true}, {"On", true}, {"1", true}, {"TRUE", true},
		{"no", false}, {"0", false}, {"", false}, {"y", false},
		{int64(1), true}, {int64(2), false}, {1.0, true}, {0.5, false},
	}
	for _, c := range cases {
		got, err := AnsibleBool(nil, c.in, nil, nil)
		if err != nil || got != c.want {
			t.Errorf("bool(%#v) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	if _, err := AnsibleBool(nil, Undefined{Name: "missing"}, nil, nil); err == nil {
		t.Error("bool of an undefined name must fail, as in Ansible")
	}
}

// A name neither the template nor the vars define is asked of Resolve, so a
// value can be computed only when a template reads it.
func TestResolveSuppliesNamesOnDemand(t *testing.T) {
	env := NewEnvironment(nil)
	env.Autoescape = false
	AddAnsibleFilters(env)
	asked := []string{}
	env.Resolve = func(name string) (any, bool) {
		asked = append(asked, name)
		switch name {
		case "port":
			return int64(8443), true
		case "enabled":
			return "yes", true
		}
		return nil, false
	}
	tpl, err := env.FromString("t", "{{ port }} {{ enabled | bool }} {{ missing | default('d') }} {{ local }}{% if other is defined %}x{% endif %}")
	if err != nil {
		t.Fatal(err)
	}
	out, err := env.RenderTemplate(tpl, map[string]any{"local": "L"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "8443 True d L" {
		t.Fatalf("render = %q", out)
	}
	for _, name := range asked {
		if name == "local" {
			t.Fatal("a name the render's vars define must not reach Resolve")
		}
	}
}

// Under StrictUndefined printing an undefined name fails, as in Ansible, while
// default() and "is defined" still see it as undefined.
func TestStrictUndefinedFailsOnlyWhenPrinted(t *testing.T) {
	env := NewEnvironment(nil)
	env.Autoescape = false
	env.StrictUndefined = true
	tpl, err := env.FromString("t", "{{ x | default('d') }}{% if y is defined %}y{% endif %}")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := env.RenderTemplate(tpl, nil); err != nil || out != "d" {
		t.Fatalf("render = %q, %v", out, err)
	}
	tpl, err = env.FromString("t", "a{{ missing }}b")
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.RenderTemplate(tpl, nil)
	var undef *UndefinedError
	if !errors.As(err, &undef) || undef.Name != "missing" {
		t.Fatalf("printing an undefined name: %v", err)
	}
	lenient := NewEnvironment(nil)
	if out, err := lenient.RenderTemplate(tpl, nil); err != nil || out != "ab" {
		t.Fatalf("without StrictUndefined an undefined name still prints as nothing: %q, %v", out, err)
	}
}

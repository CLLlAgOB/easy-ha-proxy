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

func TestAnsibleHashAndPathFilters(t *testing.T) {
	sha256Of := func(v any) any { out, _ := AnsibleHash(nil, v, []any{"sha256"}, nil); return out }
	if got := sha256Of("alertd:x"); got != "7f4a1318d8a81e0a53bb55bebbf7aceae71337b9be70c152ce6f9c2f81249e6f" {
		t.Fatalf("sha256 = %v", got)
	}
	if got, _ := AnsibleHash(nil, "abc", nil, nil); got != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("sha1 is the default: %v", got)
	}
	if got, _ := AnsibleHash(nil, "abc", []any{"nope"}, nil); got != nil {
		t.Fatalf("an unknown algorithm gives None: %v", got)
	}
	for in, want := range map[string]string{
		"/var/lib/x/alerts.db": "/var/lib/x", "/etc/": "/etc", "alerts.db": "", "/": "/", "//a": "//", "a/b//c": "a/b",
	} {
		if got, _ := AnsibleDirname(nil, in, nil, nil); got != want {
			t.Errorf("dirname(%q) = %q, want %q", in, got, want)
		}
	}
	if got, _ := AnsibleBasename(nil, "/etc/systemd/x.service", nil, nil); got != "x.service" {
		t.Fatalf("basename = %v", got)
	}
}

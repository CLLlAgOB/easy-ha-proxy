package vars

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// A source tree and a config dir shaped like the real ones, small.
func fixture(t *testing.T) (source, config string) {
	t.Helper()
	root := t.TempDir()
	source, config = filepath.Join(root, "source"), filepath.Join(root, "etc")
	files := map[string]string{
		"source/ansible/easy-ha-proxy.yml": `---
- hosts: "{{ easy_ha_proxy_target | default('easy_ha_proxy') }}"
  vars_files:
    - "{{ easy_ha_proxy_config_dir | default(playbook_dir) }}/vars.yml"
  roles:
    - role: alpha
      task_stage: install
    - role: beta
    - role: alpha
      task_stage: config
- hosts: all
  vars_files:
    - "{{ easy_ha_proxy_config_dir | default(playbook_dir) }}/vars.yml"
  roles:
    - role: gamma
`,
		"source/ansible/roles/alpha/defaults/main.yml": `shared: from-alpha
alpha_only: "{{ base }}-alpha"
alpha_port: "{{ 8000 + 443 }}"
alpha_enabled: "{{ feature | default('yes') | bool }}"
alpha_list: "{{ items }}"
alpha_text: "{{ items | join(',') }}"
alpha_none: "{{ nothing }}"
alpha_dir: "{{ role_path }}"
alpha_block: |+
  {{ base }}

`,
		"source/ansible/roles/beta/defaults/main.yml": `shared: from-beta
beta_derived: "{{ shared }}/{{ alpha_only }}"
loop_a: "{{ loop_b }}"
loop_b: "{{ loop_a }}"
broken: "{{ not_defined_anywhere }}"
beta_guarded: "{{ broken | default('fallback') }}"
beta_looped: "{{ loop_a | default('fallback') }}"
`,
		"source/ansible/roles/gamma/defaults/main.yml": `gamma_sees: "{{ secret_token | default('no secret') }}"
`,
		"etc/inventory.ini": "[easy_ha_proxy]\nlocalhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3 answer=42\n",
		"etc/vars.yml":      "base: example\nitems: [one, two]\nnothing: null\nshared_override: vars\nsecret_token: from-vars\n",
		"etc/secrets.yml":   "secret_token: s3cret\n",
	}
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return source, config
}

func load(t *testing.T, opts Options) *Set {
	t.Helper()
	s, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Set, name string) any {
	t.Helper()
	v, err := s.Get(name)
	if err != nil {
		t.Fatalf("Get(%s): %v", name, err)
	}
	return v
}

// The running role's defaults sit above the other roles'; at play level the
// role listed last wins, and a role listed twice counts at its last place.
func TestRoleDefaultsFollowThePlayAndTheRunningRole(t *testing.T) {
	source, config := fixture(t)
	play := load(t, Options{SourceDir: source, ConfigDir: config})
	if v := get(t, play, "shared"); v != "from-alpha" {
		t.Fatalf("play level: shared = %v (alpha is listed again after beta)", v)
	}
	beta := load(t, Options{SourceDir: source, ConfigDir: config, Role: "beta"})
	if v := get(t, beta, "shared"); v != "from-beta" {
		t.Fatalf("role beta: shared = %v", v)
	}
	if v := get(t, beta, "beta_derived"); v != "from-beta/example-alpha" {
		t.Fatalf("a default reading another role's default: %v", v)
	}
	if beta.Source("shared") != "role beta defaults (running role)" {
		t.Fatalf("source: %s", beta.Source("shared"))
	}
}

// Ansible 2.17 renders to text, then turns text that looks like a list, a
// dict or a bool back into one; numbers and None stay text.
func TestTemplatedValuesHaveAnsiblesTypes(t *testing.T) {
	source, config := fixture(t)
	s := load(t, Options{SourceDir: source, ConfigDir: config, Role: "alpha"})
	for name, want := range map[string]any{
		"alpha_port":         "8443",
		"alpha_enabled":      true,
		"alpha_list":         []any{"one", "two"},
		"alpha_text":         "one,two",
		"alpha_none":         "None",
		"alpha_only":         "example-alpha",
		"alpha_dir":          filepath.Join(source, "ansible", "roles", "alpha"),
		"alpha_block":        "example\n\n",
		"answer":             int64(42),
		"ansible_connection": "local",
	} {
		if got := get(t, s, name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
}

func TestPrecedenceOfTheOtherSources(t *testing.T) {
	source, config := fixture(t)
	s := load(t, Options{SourceDir: source, ConfigDir: config, Role: "alpha",
		Params: map[string]any{"task_stage": "config", "base": "param"},
		Extra:  map[string]any{"secret_token": "extra"},
		Facts:  map[string]any{"architecture": "aarch64", "os_family": "Debian"}})
	if v := get(t, s, "base"); v != "param" {
		t.Fatalf("role params beat vars_files: base = %v", v)
	}
	if v := get(t, s, "secret_token"); v != "extra" {
		t.Fatalf("extra vars beat everything: %v", v)
	}
	if v := get(t, s, "ansible_architecture"); v != "aarch64" {
		t.Fatalf("facts as ansible_<name>: %v", v)
	}
	facts, _ := get(t, s, "ansible_facts").(*pyyaml.Map)
	if facts == nil || facts.Value("os_family") != "Debian" {
		t.Fatalf("ansible_facts: %#v", facts)
	}
	s.SetFact("alpha_only", "fact")
	if v := get(t, s, "alpha_only"); v != "fact" {
		t.Fatalf("set_fact beats defaults: %v", v)
	}
	s.SetFact("base", "fact")
	if v := get(t, s, "base"); v != "param" {
		t.Fatalf("role params beat set_fact: %v", v)
	}

	plain := load(t, Options{SourceDir: source, ConfigDir: config})
	if v := get(t, plain, "secret_token"); v != "s3cret" {
		t.Fatalf("the first play includes secrets.yml above vars_files: %v", v)
	}
	second := load(t, Options{SourceDir: source, ConfigDir: config, Play: 1, Role: "gamma"})
	// include_vars results stay with the host, so the healthcheck play sees
	// the secrets the first play included (found by the parity stand).
	if v := get(t, second, "gamma_sees"); v != "s3cret" {
		t.Fatalf("the healthcheck play keeps the first play's secrets.yml: %v", v)
	}
}

func TestUndefinedAndLoopsFailLikeAnsible(t *testing.T) {
	source, config := fixture(t)
	s := load(t, Options{SourceDir: source, ConfigDir: config, Role: "beta"})
	var undef *UndefinedError
	if _, err := s.Get("no_such_var"); !errors.As(err, &undef) {
		t.Fatalf("an unknown name: %v", err)
	}
	if _, err := s.Get("broken"); err == nil || !strings.Contains(err.Error(), "not_defined_anywhere") {
		t.Fatalf("a template printing an undefined name fails when read: %v", err)
	}
	if v := get(t, s, "beta_guarded"); v != "fallback" {
		t.Fatalf("default() covers a variable whose template is undefined: %v", v)
	}
	if _, err := s.Get("loop_a"); err == nil || !strings.Contains(err.Error(), "recursive loop") {
		t.Fatalf("a loop: %v", err)
	}
	if _, err := s.Get("beta_looped"); err == nil || !strings.Contains(err.Error(), "recursive loop") {
		t.Fatalf("default() must not hide a loop: %v", err)
	}
}

func TestUnsupportedLayoutsAreRefusedNotGuessed(t *testing.T) {
	source, config := fixture(t)
	if err := os.MkdirAll(filepath.Join(config, "group_vars"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{SourceDir: source, ConfigDir: config}); err == nil {
		t.Fatal("group_vars must be refused until the loader reads them")
	}
	source, config = fixture(t)
	if _, err := Load(Options{SourceDir: source, ConfigDir: config, Role: "gamma"}); err == nil {
		t.Fatal("a role the play does not list")
	}
	if err := os.Remove(filepath.Join(config, "vars.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{SourceDir: source, ConfigDir: config}); err == nil {
		t.Fatal("a missing vars_files entry fails, as in Ansible")
	}
}

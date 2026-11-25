// Package vars gives the Go installer the variables Ansible gives a task of
// ansible/easy-ha-proxy.yml: the same sources, in Ansible's order of
// precedence, templated the way ansible-core 2.17 templates them.
//
// Sources, lowest first, as VariableManager.get_vars combines them:
//
//  1. the defaults of every role the play lists, in play order (a role listed
//     twice counts twice, so its last place wins), then the running role's
//     own defaults again, so a task sees its role's defaults above the others;
//  2. host variables from the inventory line;
//  3. facts, as ansible_facts and as ansible_<name>;
//  4. the play's vars_files (vars.yml, authelia.yml, ... in the config dir);
//  5. secrets.yml, which the first play's pre_tasks include and which stays
//     for every later play, as include_vars results do;
//  6. facts a stage sets (set_fact);
//  7. role parameters (task_stage);
//  8. extra variables;
//  9. magic variables (playbook_dir, role_path, inventory_hostname, ...).
//
// A higher source replaces a whole value (hash_behaviour=replace). A value is
// templated only when it is read, so defaults may refer to each other and to
// anything above them, exactly as in Ansible.
package vars

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// Playbook is the playbook the installer replaces, relative to the source dir.
const Playbook = "ansible/easy-ha-proxy.yml"

// Options says which task's view of the variables to build.
type Options struct {
	SourceDir string // the checkout holding ansible/ (/opt/easy-ha-proxy/source)
	ConfigDir string // the managed configuration (/etc/easy-ha-proxy)
	Play      int    // index of the play in the playbook
	Role      string // the running role; empty for the play's own tasks
	Params    map[string]any
	Extra     map[string]any // --extra-vars
	Facts     map[string]any // setup facts, without the ansible_ prefix
	CheckMode bool
}

// UndefinedError is a variable no source defines.
type UndefinedError struct{ Name string }

func (e *UndefinedError) Error() string { return fmt.Sprintf("'%s' is undefined", e.Name) }

// Set is one task's view of the variables.
type Set struct {
	layers    []layer // lowest first
	facts     *pyyaml.Map
	env       *jinja.Environment
	cache     map[string]any
	resolving map[string]bool
	failure   error // the first error met while a template read a variable
}

type layer struct {
	name   string
	values *pyyaml.Map
}

// Load builds the variables a task of opts.Role in play opts.Play sees.
func Load(opts Options) (*Set, error) {
	playbookDir := filepath.Join(opts.SourceDir, "ansible")
	plays, err := readPlays(filepath.Join(opts.SourceDir, Playbook))
	if err != nil {
		return nil, err
	}
	if opts.Play < 0 || opts.Play >= len(plays) {
		return nil, fmt.Errorf("the playbook has no play %d", opts.Play)
	}
	play := plays[opts.Play]
	if opts.Role != "" && !contains(play.roles, opts.Role) {
		return nil, fmt.Errorf("play %d does not list role %q", opts.Play, opts.Role)
	}
	for _, unsupported := range []string{"group_vars", "host_vars"} {
		for _, dir := range []string{playbookDir, opts.ConfigDir} {
			if _, err := os.Stat(filepath.Join(dir, unsupported)); err == nil {
				return nil, fmt.Errorf("%s in %s is not supported by the Go installer yet", unsupported, dir)
			}
		}
	}

	s := &Set{cache: map[string]any{}, resolving: map[string]bool{}}
	s.env = newEnv(s.resolve)

	// 1. Role defaults: every listed role in order, then the running one.
	defaults := map[string]*pyyaml.Map{}
	roleDefaults := func(role string) (*pyyaml.Map, error) {
		if m, ok := defaults[role]; ok {
			return m, nil
		}
		path := filepath.Join(playbookDir, "roles", role, "defaults", "main.yml")
		m, err := readYAMLMap(path, true)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(filepath.Join(playbookDir, "roles", role, "vars")); err == nil {
			return nil, fmt.Errorf("role %s has role vars, which the Go installer does not read yet", role)
		}
		defaults[role] = m
		return m, nil
	}
	for _, role := range play.roles {
		m, err := roleDefaults(role)
		if err != nil {
			return nil, err
		}
		s.push("role "+role+" defaults", m)
	}
	if opts.Role != "" {
		m, err := roleDefaults(opts.Role)
		if err != nil {
			return nil, err
		}
		s.push("role "+opts.Role+" defaults (running role)", m)
	}

	// 2. The inventory line's host variables.
	hostVars, err := readInventory(filepath.Join(opts.ConfigDir, "inventory.ini"))
	if err != nil {
		return nil, err
	}
	s.push("inventory host vars", hostVars)

	// 3. Facts.
	s.facts = pyyaml.NewMap()
	factVars := pyyaml.NewMap()
	for _, k := range sortedKeys(opts.Facts) {
		s.facts.Set(k, opts.Facts[k])
		factVars.Set("ansible_"+k, opts.Facts[k])
	}
	factVars.Set("ansible_facts", s.facts)
	s.push("facts", factVars)

	// 8 (early, for the file names): extra vars and the config dir.
	extra := pyyaml.NewMap()
	for _, k := range sortedKeys(opts.Extra) {
		extra.Set(k, opts.Extra[k])
	}
	if _, ok := extra.Get("easy_ha_proxy_config_dir"); !ok {
		extra.Set("easy_ha_proxy_config_dir", opts.ConfigDir)
	}
	magic := magicVars(opts, playbookDir)

	// 4. vars_files, named by templates over the variables known so far.
	early := &Set{layers: append(append([]layer{}, s.layers...), layer{"extra vars", extra}, layer{"magic vars", magic}),
		facts: s.facts, cache: map[string]any{}, resolving: map[string]bool{}}
	early.env = newEnv(early.resolve)
	for _, name := range play.varsFiles {
		path, err := early.Render(name)
		if err != nil {
			return nil, fmt.Errorf("vars_files %q: %w", name, err)
		}
		m, err := readYAMLMap(path, false)
		if err != nil {
			return nil, err
		}
		s.push("vars_files "+filepath.Base(path), m)
	}

	// 5. secrets.yml, included by the first play's pre_tasks (tagged always).
	// include_vars results belong to the host for the rest of the run, so
	// the later play sees them too.
	secrets, err := readYAMLMap(filepath.Join(opts.ConfigDir, "secrets.yml"), false)
	if err != nil {
		return nil, err
	}
	s.push("include_vars secrets.yml", secrets)

	// 6. set_fact, filled by stages.
	s.push("set_fact", pyyaml.NewMap())

	// 7. Role parameters.
	params := pyyaml.NewMap()
	for _, k := range sortedKeys(opts.Params) {
		params.Set(k, opts.Params[k])
	}
	s.push("role params", params)

	s.push("extra vars", extra)
	s.push("magic vars", magic)
	return s, nil
}

// newEnv is the Jinja environment Ansible templates variables with:
// no autoescape, trim_blocks on, and Ansible's filters.
func newEnv(resolve func(string) (any, bool)) *jinja.Environment {
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.TrimBlocks = true
	env.StrictUndefined = true
	jinja.AddAnsibleFilters(env)
	env.Resolve = resolve
	return env
}

func (s *Set) push(name string, m *pyyaml.Map) { s.layers = append(s.layers, layer{name, m}) }

func magicVars(opts Options, playbookDir string) *pyyaml.Map {
	m := pyyaml.NewMap()
	m.Set("playbook_dir", playbookDir)
	m.Set("inventory_hostname", "localhost")
	m.Set("inventory_hostname_short", "localhost")
	m.Set("inventory_dir", opts.ConfigDir)
	m.Set("inventory_file", filepath.Join(opts.ConfigDir, "inventory.ini"))
	m.Set("ansible_check_mode", opts.CheckMode)
	groups := pyyaml.NewMap()
	groups.Set("all", []any{"localhost"})
	groups.Set("easy_ha_proxy", []any{"localhost"})
	groups.Set("ungrouped", []any{})
	m.Set("groups", groups)
	m.Set("group_names", []any{"easy_ha_proxy"})
	if opts.Role != "" {
		m.Set("role_name", opts.Role)
		m.Set("role_path", filepath.Join(playbookDir, "roles", opts.Role))
	}
	return m
}

// Raw is a variable's value as its source holds it, untemplated.
func (s *Set) Raw(name string) (any, bool) {
	for i := len(s.layers) - 1; i >= 0; i-- {
		if v, ok := s.layers[i].values.Get(name); ok {
			return v, true
		}
	}
	return nil, false
}

// Source names the source a variable's value comes from.
func (s *Set) Source(name string) string {
	for i := len(s.layers) - 1; i >= 0; i-- {
		if _, ok := s.layers[i].values.Get(name); ok {
			return s.layers[i].name
		}
	}
	return ""
}

// Names lists every name the playbook's sources define: role defaults,
// inventory, vars_files, secrets, set_fact, role parameters and extra
// variables; facts and magic variables are left out.
func (s *Set) Names() []string {
	seen := map[string]bool{}
	var names []string
	for _, l := range s.layers {
		if l.name == "facts" || l.name == "magic vars" {
			continue
		}
		l.values.Each(func(k, _ any) {
			if name, ok := k.(string); ok && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		})
	}
	sort.Strings(names)
	return names
}

// Has says whether any source defines the variable.
func (s *Set) Has(name string) bool {
	_, ok := s.Raw(name)
	return ok
}

// Get is a variable's templated value, as a task reading it would see it.
func (s *Set) Get(name string) (any, error) {
	if v, ok := s.cache[name]; ok {
		return v, nil
	}
	raw, ok := s.Raw(name)
	if !ok {
		return nil, &UndefinedError{Name: name}
	}
	if s.resolving[name] {
		return nil, fmt.Errorf("recursive loop detected in template string: %s", name)
	}
	s.resolving[name] = true
	v, err := s.template(raw)
	delete(s.resolving, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	s.cache[name] = v
	return v, nil
}

// SetFact is a stage's set_fact: above the playbook's sources, below role
// parameters and extra variables.
func (s *Set) SetFact(name string, value any) {
	for _, l := range s.layers {
		if l.name == "set_fact" {
			l.values.Set(name, value)
		}
	}
	s.cache = map[string]any{} // anything may depend on it
}

// Render templates a string the way a task argument is templated.
func (s *Set) Render(src string) (string, error) {
	v, err := s.template(src)
	if err != nil {
		return "", err
	}
	if str, ok := v.(string); ok {
		return str, nil
	}
	return jinja.Str(v), nil
}

// Template templates any value: strings, and the strings inside lists and
// dicts (keys too), as Templar.template does.
func (s *Set) Template(v any) (any, error) { return s.template(v) }

func (s *Set) template(v any) (any, error) {
	switch x := v.(type) {
	case string:
		if !isTemplate(x) {
			return x, nil
		}
		return s.renderString(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			t, err := s.template(item)
			if err != nil {
				return nil, err
			}
			out[i] = t
		}
		return out, nil
	case *pyyaml.Map:
		out := pyyaml.NewMap()
		var failed error
		x.Each(func(k, val any) {
			if failed != nil {
				return
			}
			tk, err := s.template(k)
			if err != nil {
				failed = err
				return
			}
			tv, err := s.template(val)
			if err != nil {
				failed = err
				return
			}
			out.Set(tk, tv)
		})
		if failed != nil {
			return nil, failed
		}
		return out, nil
	}
	return v, nil
}

func isTemplate(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, "{%") || strings.Contains(s, "{#")
}

// renderString is Templar.template for a string with convert_data on:
// render, keep the source's trailing newlines, then ansible_eval_concat --
// text that looks like a dict, a list or a bool becomes one.
func (s *Set) renderString(src string) (any, error) {
	tpl, err := s.env.FromString("<template>", src)
	if err != nil {
		return nil, err
	}
	outer := s.failure
	s.failure = nil
	out, err := s.env.RenderTemplate(tpl, nil)
	if s.failure != nil {
		// The variable that failed to template is the cause; the render's own
		// error is only its echo (an undefined name where it was printed).
		err = s.failure
	}
	s.failure = outer
	if err != nil {
		return nil, err
	}
	if want, have := trailingNewlines(src), trailingNewlines(out); want > have {
		out += strings.Repeat("\n", want-have)
	}
	if strings.HasPrefix(out, "{") || strings.HasPrefix(out, "[") || out == "True" || out == "False" {
		if v, err := literalEval(out); err == nil {
			return v, nil
		}
	}
	return out, nil
}

func trailingNewlines(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\n'; i-- {
		n++
	}
	return n
}

// resolve answers the Jinja engine for a name a template reads. A variable
// no source defines is undefined, and so is one whose own template reads an
// undefined name (AnsibleJ2Vars returns an Undefined for it), so default()
// works on both. Any other failure is kept and fails the render, as Ansible
// fails the task.
func (s *Set) resolve(name string) (any, bool) {
	if !s.Has(name) {
		return nil, false
	}
	v, err := s.Get(name)
	if err != nil {
		var undefVar *UndefinedError
		var undefTpl *jinja.UndefinedError
		if errors.As(err, &undefVar) || errors.As(err, &undefTpl) {
			return nil, false
		}
		if s.failure == nil {
			s.failure = err
		}
		return nil, false
	}
	return v, true
}

type playInfo struct {
	roles     []string
	varsFiles []string
}

func readPlays(path string) ([]playInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := pyyaml.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	list, ok := doc.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a list of plays", path)
	}
	var plays []playInfo
	for _, item := range list {
		m, ok := item.(*pyyaml.Map)
		if !ok {
			return nil, fmt.Errorf("%s: a play is not a mapping", path)
		}
		var p playInfo
		if roles, ok := m.Value("roles").([]any); ok {
			for _, r := range roles {
				switch x := r.(type) {
				case string:
					p.roles = append(p.roles, x)
				case *pyyaml.Map:
					name, _ := x.Value("role").(string)
					if name == "" {
						return nil, fmt.Errorf("%s: a role entry has no name", path)
					}
					p.roles = append(p.roles, name)
				}
			}
		}
		if files, ok := m.Value("vars_files").([]any); ok {
			for _, f := range files {
				name, ok := f.(string)
				if !ok {
					return nil, fmt.Errorf("%s: a vars_files entry is not a string", path)
				}
				p.varsFiles = append(p.varsFiles, name)
			}
		}
		plays = append(plays, p)
	}
	return plays, nil
}

// readYAMLMap reads a variables file. A missing file is an error, as for
// Ansible's vars_files, unless optional; an empty one is no variables.
func readYAMLMap(path string, optional bool) (*pyyaml.Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return pyyaml.NewMap(), nil
		}
		return nil, err
	}
	doc, err := pyyaml.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc == nil {
		return pyyaml.NewMap(), nil
	}
	m, ok := doc.(*pyyaml.Map)
	if !ok {
		return nil, fmt.Errorf("%s: variables must be a mapping", path)
	}
	return m, nil
}

// readInventory reads the host variables of the installer's inventory: one
// group, one host line of key=value pairs. Values are Python literals where
// they parse as one, as Ansible's ini inventory reads them.
func readInventory(path string) (*pyyaml.Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := pyyaml.NewMap()
	hosts := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[easy_ha_proxy]" {
				return nil, fmt.Errorf("%s: section %s is not supported by the Go installer yet", path, line)
			}
			continue
		}
		fields := strings.Fields(line)
		if fields[0] != "localhost" {
			return nil, fmt.Errorf("%s: host %s is not supported by the Go installer yet", path, fields[0])
		}
		hosts++
		for _, kv := range fields[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("%s: %q is not key=value", path, kv)
			}
			if parsed, err := literalEval(v); err == nil {
				out.Set(k, parsed)
			} else {
				out.Set(k, v)
			}
		}
	}
	if hosts != 1 {
		return nil, fmt.Errorf("%s: expected exactly one host line, found %d", path, hosts)
	}
	return out, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

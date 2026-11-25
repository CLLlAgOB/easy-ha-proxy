// Package stages holds the Go installer's stages, each a transcription of the
// Ansible task files it replaces: same order, same conditions, the task names
// kept so a run's journal reads like the Ansible log.
package stages

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

// Context is what a stage is built from.
type Context struct {
	SourceDir, ConfigDir string
	Facts                map[string]any
	Extra                map[string]any
	Sys                  *engine.System
}

// Part is one task file of a role, the unit Ansible hands to the agent during
// the hybrid period: roles/<Role>/tasks/<Name>.yml. Its steps are built with
// the variables of the role entry that runs it (task_stage defaults to Name).
type Part struct {
	// Name is how Ansible and "apply run --part" call it: the task file's
	// name for haproxy-admin, "<role>/<file>" for the other roles.
	Name, Role string
	// File is the task file's name without .yml; empty means Name.
	File string
	// PreTask marks a part the play's pre_tasks run, not a role entry.
	PreTask bool
	// Reads are registered results of other task files (or of Ansible) the
	// part's conditions read; Ansible passes the changed ones as seeds.
	Reads []string
	Build func(b *Builder) []engine.Step
}

// Stage is a named list of parts, run in order.
type Stage struct {
	Name  string
	Parts []Part
}

var (
	registry = map[string]Stage{}
	parts    = map[string]Part{}
)

func register(s Stage) {
	registry[s.Name] = s
	for _, p := range s.Parts {
		parts[p.Name] = p
	}
}

// TaskFile is the part's task file name without .yml.
func (p Part) TaskFile() string {
	if p.File != "" {
		return p.File
	}
	return p.Name
}

// Parts lists every part with the results it reads, for Ansible to ask.
func Parts() map[string]Part { return parts }

// Names lists the stages.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Run runs a stage's parts on the run.
func Run(ctx Context, name string, run *engine.Run) error {
	stage, ok := registry[name]
	if !ok {
		return fmt.Errorf("no stage %q (stages: %v)", name, Names())
	}
	for _, part := range stage.Parts {
		if err := RunPart(ctx, part.Name, "", run); err != nil {
			return err
		}
	}
	return nil
}

// RunPart runs one part with the variables of the role entry task_stage
// ("" means the part's own name).
func RunPart(ctx Context, name, taskStage string, run *engine.Run) error {
	part, ok := parts[name]
	if !ok {
		return fmt.Errorf("no part %q", name)
	}
	if taskStage == "" {
		taskStage = part.TaskFile()
	}
	set, err := vars.Load(vars.Options{SourceDir: ctx.SourceDir, ConfigDir: ctx.ConfigDir, Role: part.Role,
		Params: map[string]any{"task_stage": taskStage}, Extra: ctx.Extra, Facts: ctx.Facts})
	if err != nil {
		return fmt.Errorf("%s/%s: %w", part.Role, part.Name, err)
	}
	b := &Builder{Set: set, Sys: ctx.Sys, RoleDir: filepath.Join(ctx.SourceDir, "ansible", "roles", part.Role)}
	steps := part.Build(b)
	if b.err != nil {
		return fmt.Errorf("%s/%s: %w", part.Role, part.Name, b.err)
	}
	return run.Do(part.Role+"/"+part.Name, steps)
}

// Builder gives a part's steps their values; the first error is kept and
// fails the part before any step runs.
type Builder struct {
	Set     *vars.Set
	Sys     *engine.System
	RoleDir string
	err     error
}

func (b *Builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

// S templates a task argument.
func (b *Builder) S(expr string) string {
	out, err := b.Set.Render(expr)
	if err != nil {
		b.fail(fmt.Errorf("%q: %w", expr, err))
	}
	return out
}

// Bool templates a task argument to a bool, as a when: condition reads it.
func (b *Builder) Bool(expr string) bool {
	v, err := b.Set.Template(expr)
	if err != nil {
		b.fail(fmt.Errorf("%q: %w", expr, err))
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "True" || x == "true"
	}
	return v != nil
}

// Mode reads an octal mode.
func (b *Builder) Mode(s string) os.FileMode {
	m, err := engine.ParseMode(b.S(s))
	if err != nil {
		b.fail(err)
	}
	return m
}

// Exists is stat: path.exists (following links unless lstat).
func (b *Builder) Exists(path string, lstat bool) bool {
	stat := os.Stat
	if lstat {
		stat = os.Lstat
	}
	_, err := stat(b.Sys.Path(path))
	return err == nil
}

// Template is a template task's file, rendered when the step runs.
func (b *Builder) Template(src, dest, owner, group, mode string, opts ...func(*FileOpts)) func(*engine.Run) (engine.Resource, error) {
	o := FileOpts{Force: true}
	for _, opt := range opts {
		opt(&o)
	}
	dest, owner, group, m := b.S(dest), b.S(owner), b.S(group), b.Mode(mode)
	return func(*engine.Run) (engine.Resource, error) {
		out, err := b.Set.RenderFile(filepath.Join(b.RoleDir, "templates", src), nil, vars.TemplateOptions{LstripBlocks: o.LstripBlocks})
		if err != nil {
			return nil, err
		}
		return &engine.File{Path: dest, Content: []byte(out), Owner: owner, Group: group, Mode: m, OnlyIfMissing: !o.Force}, nil
	}
}

// CopyFile is a copy task with src: a file of the role's files/ directory.
func (b *Builder) CopyFile(src, dest, owner, group, mode string, opts ...func(*FileOpts)) func(*engine.Run) (engine.Resource, error) {
	o := FileOpts{Force: true}
	for _, opt := range opts {
		opt(&o)
	}
	dest, owner, group, m := b.S(dest), b.S(owner), b.S(group), b.Mode(mode)
	return func(*engine.Run) (engine.Resource, error) {
		raw, err := os.ReadFile(filepath.Join(b.RoleDir, "files", src))
		if err != nil {
			return nil, err
		}
		return &engine.File{Path: dest, Content: raw, Owner: owner, Group: group, Mode: m, OnlyIfMissing: !o.Force}, nil
	}
}

// CopyContent is a copy task with content: (templated like any argument).
func (b *Builder) CopyContent(content, dest, owner, group, mode string, opts ...func(*FileOpts)) func(*engine.Run) (engine.Resource, error) {
	o := FileOpts{Force: true}
	for _, opt := range opts {
		opt(&o)
	}
	dest, owner, group, m := b.S(dest), b.S(owner), b.S(group), b.Mode(mode)
	return func(*engine.Run) (engine.Resource, error) {
		out, err := b.Set.Render(content)
		if err != nil {
			return nil, err
		}
		return &engine.File{Path: dest, Content: []byte(out), Owner: owner, Group: group, Mode: m, OnlyIfMissing: !o.Force}, nil
	}
}

// List templates a task argument to a list of strings (a loop: list).
func (b *Builder) List(expr string) []string {
	v, err := b.Set.Template(expr)
	if err != nil {
		b.fail(fmt.Errorf("%q: %w", expr, err))
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		if v == nil || v == "" {
			return nil
		}
		b.fail(fmt.Errorf("%q is not a list", expr))
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			b.fail(fmt.Errorf("%q: item %v is not a string", expr, item))
			return nil
		}
		out = append(out, s)
	}
	return out
}

// Dir is a file task with state: directory.
func (b *Builder) Dir(path, owner, group, mode string) *engine.Dir {
	return &engine.Dir{Path: b.S(path), Owner: b.S(owner), Group: b.S(group), Mode: b.Mode(mode)}
}

// FileOpts are a template task's options.
type FileOpts struct{ Force, LstripBlocks bool }

// NoForce is force: false.
func NoForce(o *FileOpts) { o.Force = false }

// Changed is a when: condition over registered results.
func Changed(registers ...string) func(*engine.Run) bool {
	return func(r *engine.Run) bool { return r.ChangedAny(registers...) }
}

// Unit is a systemd task for a unit.
func Unit(name string, enabled *bool, state string) *engine.Unit {
	return &engine.Unit{Name: name, Enabled: enabled, State: state}
}

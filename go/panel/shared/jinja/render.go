package jinja

import (
	"strings"
	"sync"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Loader returns a template's source by name.
type Loader func(name string) (string, error)

// Environment holds globals, filters, tests and the template cache.
type Environment struct {
	Loader  Loader
	Globals map[string]any
	Filters map[string]FilterFunc
	Tests   map[string]TestFunc
	// JSONDumps is the tojson policy (Flask: sort_keys, ensure_ascii).
	JSONDumps func(v any) (string, error)
	// Autoescape, TrimBlocks and LstripBlocks are the Jinja Environment options.
	Autoescape   bool
	TrimBlocks   bool
	LstripBlocks bool
	// MaxRenderSteps caps the nodes and loop iterations of one render;
	// zero means DefaultMaxRenderSteps.
	MaxRenderSteps int
	// Resolve, when set, is asked for a name that neither the template nor
	// the render's vars define: Ansible templates a variable only when a
	// template reads it, so a value may depend on another one lazily.
	Resolve func(name string) (any, bool)
	// StrictUndefined makes printing an undefined name an *UndefinedError
	// instead of "", as Ansible's undefined does.
	StrictUndefined bool

	mu    sync.Mutex
	cache map[string]*Template
}

// FilterFunc implements a filter; value is the filtered value.
type FilterFunc func(env *Environment, value any, args []any, kwargs *Map) (any, error)

// TestFunc implements a test.
type TestFunc func(env *Environment, value any, args []any) (bool, error)

// NewEnvironment returns an environment with Jinja's built-in filters and tests.
func NewEnvironment(loader Loader) *Environment {
	env := &Environment{Loader: loader, Globals: map[string]any{}, cache: map[string]*Template{}, Autoescape: true}
	env.Filters = builtinFilters()
	env.Tests = builtinTests()
	env.Globals["range"] = Func(builtinRange)
	env.Globals["dict"] = Func(func(args []any, kwargs *Map) (any, error) {
		m := pyyaml.NewMap()
		if len(args) == 1 {
			if src, ok := normalize(args[0]).(*Map); ok {
				src.Each(func(k, v any) { m.Set(k, v) })
			}
		}
		kwargs.Each(func(k, v any) { m.Set(k, v) })
		return m, nil
	})
	env.Globals["namespace"] = Func(func(args []any, kwargs *Map) (any, error) {
		m := pyyaml.NewMap()
		if len(args) == 1 {
			if src, ok := normalize(args[0]).(*Map); ok {
				src.Each(func(k, v any) { m.Set(k, v) })
			}
		}
		kwargs.Each(func(k, v any) { m.Set(k, v) })
		return Namespace{M: m}, nil
	})
	return env
}

// Template parses (and caches) a template by name.
func (env *Environment) Template(name string) (*Template, error) {
	env.mu.Lock()
	t, ok := env.cache[name]
	env.mu.Unlock()
	if ok {
		return t, nil
	}
	src, err := env.Loader(name)
	if err != nil {
		return nil, err
	}
	t, err = parseWith(name, src, env.lexOpts())
	if err != nil {
		return nil, err
	}
	env.mu.Lock()
	env.cache[name] = t
	env.mu.Unlock()
	return t, nil
}

// FromString parses a template that is not loaded by name.
func (env *Environment) FromString(name, src string) (*Template, error) {
	return parseWith(name, src, env.lexOpts())
}

func (env *Environment) lexOpts() lexOpts {
	return lexOpts{trimBlocks: env.TrimBlocks, lstripBlocks: env.LstripBlocks}
}

// output is how a value reaches the page: escaped under autoescape.
func (env *Environment) output(v any) string {
	if env.Autoescape {
		return string(Escape(v))
	}
	return Str(v)
}

// markup wraps rendered text: Markup under autoescape, str otherwise.
func (env *Environment) markup(s string) any {
	if env.Autoescape {
		return Markup(s)
	}
	return s
}

// Render renders the named template with vars.
func (env *Environment) Render(name string, vars map[string]any) (string, error) {
	t, err := env.Template(name)
	if err != nil {
		return "", err
	}
	return env.RenderTemplate(t, vars)
}

// DefaultMaxRenderSteps stops a runaway loop, not a large configuration:
// haproxy.cfg.j2 takes some 250-500 steps per site, so the earlier 200,000
// failed between 400 and 800 plain sites, where Python's Jinja has no
// limit at all. Five million leaves room for ten thousand rich sites and
// still ends a runaway render within seconds.
const DefaultMaxRenderSteps = 5_000_000

const (
	maxRenderDepth = 64
	maxOutputBytes = 16 << 20
)

type renderBudget struct {
	depth    int
	steps    int
	output   int
	maxSteps int
}

func (b *renderBudget) enter() error {
	b.depth++
	if b.depth > maxRenderDepth {
		b.depth--
		return errf("maximum template recursion depth (%d) exceeded", maxRenderDepth)
	}
	return nil
}

func (b *renderBudget) leave() {
	if b.depth > 0 {
		b.depth--
	}
}

func (b *renderBudget) step() error {
	b.steps++
	if b.steps > b.maxSteps {
		return errf("template execution budget (%d steps) exceeded", b.maxSteps)
	}
	return nil
}

func (b *renderBudget) addOutput(n int) error {
	if n <= 0 {
		return nil
	}
	b.output += n
	if b.output > maxOutputBytes {
		return errf("template output budget (%d bytes) exceeded", maxOutputBytes)
	}
	return nil
}

func (env *Environment) maxRenderSteps() int {
	if env.MaxRenderSteps > 0 {
		return env.MaxRenderSteps
	}
	return DefaultMaxRenderSteps
}

// RenderTemplate renders a parsed template.
func (env *Environment) RenderTemplate(t *Template, vars map[string]any) (string, error) {
	ctx := &context{
		env:    env,
		parent: map[string]any{},
		vars:   map[string]any{},
		blocks: map[string][]*blockNode{},
		budget: &renderBudget{maxSteps: env.maxRenderSteps()},
	}
	for k, v := range env.Globals {
		ctx.parent[k] = v
	}
	for k, v := range vars {
		ctx.parent[k] = normalize(v)
	}
	var out strings.Builder
	if err := ctx.renderRoot(t, &out); err != nil {
		return "", err
	}
	return out.String(), nil
}

// context is jinja2.runtime.Context: render-time vars (parent) plus the
// template-level assignments (vars) shared across the inheritance chain.
type context struct {
	env    *Environment
	parent map[string]any
	vars   map[string]any
	blocks map[string][]*blockNode
	budget *renderBudget
}

type frame struct {
	vars     map[string]any
	parent   *frame
	toplevel bool // assignments go to the context vars
	ctx      *context
	block    *blockStack
}

type blockStack struct {
	name  string
	index int
}

func (f *frame) resolve(name string) (any, bool) {
	for fr := f; fr != nil; fr = fr.parent {
		if v, ok := fr.vars[name]; ok {
			return v, true
		}
	}
	if v, ok := f.ctx.vars[name]; ok {
		return v, true
	}
	if v, ok := f.ctx.parent[name]; ok {
		return v, true
	}
	if f.ctx.env.Resolve != nil {
		if v, ok := f.ctx.env.Resolve(name); ok {
			return normalize(v), true
		}
	}
	return nil, false
}

func (f *frame) assign(name string, v any) {
	if f.toplevel {
		f.ctx.vars[name] = v
		return
	}
	f.vars[name] = v
}

func (f *frame) child() *frame {
	return &frame{vars: map[string]any{}, parent: f, ctx: f.ctx, block: f.block}
}

// all flattens the visible names for an include.
func (f *frame) all() map[string]any {
	out := map[string]any{}
	for k, v := range f.ctx.parent {
		out[k] = v
	}
	for k, v := range f.ctx.vars {
		out[k] = v
	}
	var chain []*frame
	for fr := f; fr != nil; fr = fr.parent {
		chain = append(chain, fr)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		for k, v := range chain[i].vars {
			out[k] = v
		}
	}
	return out
}

type renderState struct {
	parentTmpl *Template
}

func (ctx *context) renderRoot(t *Template, out *strings.Builder) error {
	if err := ctx.budget.enter(); err != nil {
		return err
	}
	defer ctx.budget.leave()
	for name, b := range t.blocks {
		ctx.blocks[name] = append(ctx.blocks[name], b)
	}
	st := &renderState{}
	f := &frame{vars: map[string]any{}, toplevel: true, ctx: ctx}
	if err := ctx.renderNodes(t, t.body, f, out, st); err != nil {
		return err
	}
	if st.parentTmpl != nil {
		return ctx.renderRoot(st.parentTmpl, out)
	}
	return nil
}

func (ctx *context) renderNodes(t *Template, nodes []node, f *frame, out *strings.Builder, st *renderState) error {
	for _, n := range nodes {
		if err := ctx.budget.step(); err != nil {
			return err
		}
		if err := ctx.renderNode(t, n, f, out, st); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *context) write(out *strings.Builder, st *renderState, s string) error {
	if st != nil && st.parentTmpl != nil {
		return nil
	}
	if err := ctx.budget.addOutput(len(s)); err != nil {
		return err
	}
	out.WriteString(s)
	return nil
}

func (ctx *context) renderNode(t *Template, n node, f *frame, out *strings.Builder, st *renderState) error {
	switch x := n.(type) {
	case *textNode:
		return ctx.write(out, st, x.text)
	case *outputNode:
		if st != nil && st.parentTmpl != nil {
			return nil
		}
		v, err := ctx.eval(x.e, f)
		if err != nil {
			return wrapErr(t, x.line, err)
		}
		if ctx.env.StrictUndefined {
			switch u := v.(type) {
			case Undefined:
				return wrapErr(t, x.line, &UndefinedError{Name: u.Name})
			case *Undefined:
				return wrapErr(t, x.line, &UndefinedError{Name: u.Name})
			}
		}
		s := ctx.env.output(v)
		if err := ctx.budget.addOutput(len(s)); err != nil {
			return wrapErr(t, x.line, err)
		}
		out.WriteString(s)
	case *ifNode:
		for i, test := range x.tests {
			v, err := ctx.eval(test, f)
			if err != nil {
				return err
			}
			if Truthy(v) {
				return ctx.renderNodes(t, x.bodies[i], f, out, st)
			}
		}
		return ctx.renderNodes(t, x.els, f, out, st)
	case *forNode:
		return ctx.renderFor(t, x, f, out, st)
	case *setNode:
		v, err := ctx.eval(x.value, f)
		if err != nil {
			return wrapErr(t, x.line, err)
		}
		return ctx.assignTarget(x.target, v, f)
	case *setBlockNode:
		var buf strings.Builder
		if err := ctx.renderNodes(t, x.body, f.child(), &buf, nil); err != nil {
			return err
		}
		v := ctx.env.markup(buf.String())
		for _, flt := range x.filters {
			var err error
			if v, err = ctx.applyFilter(flt, v, f); err != nil {
				return err
			}
		}
		f.assign(x.name, v)
	case *blockNode:
		if st != nil && st.parentTmpl != nil {
			return nil
		}
		return ctx.renderBlock(x.name, 0, f, out)
	case *extendsNode:
		v, err := ctx.eval(x.tmpl, f)
		if err != nil {
			return err
		}
		pt, err := ctx.env.Template(Str(v))
		if err != nil {
			return err
		}
		st.parentTmpl = pt
	case *includeNode:
		if st != nil && st.parentTmpl != nil {
			return nil
		}
		v, err := ctx.eval(x.tmpl, f)
		if err != nil {
			return err
		}
		it, err := ctx.env.Template(Str(v))
		if err != nil {
			if x.ignoreMissing {
				return nil
			}
			return err
		}
		vars := map[string]any{}
		if x.withContext {
			vars = f.all()
		} else {
			for k, v := range ctx.env.Globals {
				vars[k] = v
			}
		}
		sub := &context{env: ctx.env, parent: vars, vars: map[string]any{}, blocks: map[string][]*blockNode{}, budget: ctx.budget}
		return sub.renderRoot(it, out)
	case *macroNode:
		m := &Macro{node: x, tmpl: t, ctx: ctx, closure: f}
		f.assign(x.name, m)
	default:
		return errf("unknown node %T", n)
	}
	return nil
}

func wrapErr(t *Template, line int, err error) error {
	if t == nil {
		return err
	}
	if e, ok := err.(*Error); ok && !strings.HasPrefix(e.Msg, t.Name+":") {
		return &Error{Msg: t.Name + ":" + itoa(line) + ": " + e.Msg}
	}
	return err
}

func itoa(n int) string { return Str(int64(n)) }

func (ctx *context) renderBlock(name string, index int, f *frame, out *strings.Builder) error {
	if err := ctx.budget.enter(); err != nil {
		return err
	}
	defer ctx.budget.leave()
	stack := ctx.blocks[name]
	if index >= len(stack) {
		return errf("no parent block '%s'", name)
	}
	b := stack[index]
	var bf *frame
	if b.scoped {
		bf = f.child()
	} else {
		bf = &frame{vars: map[string]any{}, ctx: ctx}
	}
	bf.toplevel = false
	bf.block = &blockStack{name: name, index: index}
	return ctx.renderNodes(nil, b.body, bf, out, nil)
}

func (ctx *context) assignTarget(target expr, v any, f *frame) error {
	switch t := target.(type) {
	case *nameExpr:
		f.assign(t.name, v)
	case *nsRefExpr:
		ns, ok := f.resolve(t.name)
		nsv, isNS := ns.(Namespace)
		if !ok || !isNS {
			return errf("cannot assign attribute on non-namespace object")
		}
		nsv.M.Set(t.attr, v)
	case *tupleExpr:
		items, err := iterate(v)
		if err != nil {
			return err
		}
		if len(items) != len(t.items) {
			return errf("cannot unpack %d values into %d names", len(items), len(t.items))
		}
		for i, it := range t.items {
			if err := ctx.assignTarget(it, items[i], f); err != nil {
				return err
			}
		}
	default:
		return errf("cannot assign to %T", target)
	}
	return nil
}

// loopObj is jinja2.runtime.LoopContext.
type loopObj struct {
	items []any
	index int
}

func (l *loopObj) attr(name string) (any, bool) {
	n := len(l.items)
	switch name {
	case "index":
		return int64(l.index + 1), true
	case "index0":
		return int64(l.index), true
	case "revindex":
		return int64(n - l.index), true
	case "revindex0":
		return int64(n - l.index - 1), true
	case "first":
		return l.index == 0, true
	case "last":
		return l.index == n-1, true
	case "length":
		return int64(n), true
	case "depth":
		return int64(1), true
	case "depth0":
		return int64(0), true
	case "previtem":
		if l.index > 0 {
			return l.items[l.index-1], true
		}
		return Undefined{Name: "previtem"}, true
	case "nextitem":
		if l.index < n-1 {
			return l.items[l.index+1], true
		}
		return Undefined{Name: "nextitem"}, true
	case "cycle":
		return Func(func(args []any, _ *Map) (any, error) {
			if len(args) == 0 {
				return nil, errf("no items for cycling given")
			}
			return args[l.index%len(args)], nil
		}), true
	}
	return nil, false
}

func (ctx *context) renderFor(t *Template, x *forNode, f *frame, out *strings.Builder, st *renderState) error {
	iterVal, err := ctx.eval(x.iter, f)
	if err != nil {
		return wrapErr(t, x.line, err)
	}
	items, err := iterate(iterVal)
	if err != nil {
		return wrapErr(t, x.line, err)
	}
	if x.cond != nil {
		lf := f.child()
		var kept []any
		for _, it := range items {
			if err := ctx.budget.step(); err != nil {
				return wrapErr(t, x.line, err)
			}
			if err := ctx.assignTarget(x.target, it, lf); err != nil {
				return err
			}
			v, err := ctx.eval(x.cond, lf)
			if err != nil {
				return err
			}
			if Truthy(v) {
				kept = append(kept, it)
			}
		}
		items = kept
	}
	if len(items) == 0 {
		return ctx.renderNodes(t, x.els, f, out, st)
	}
	for i, it := range items {
		if err := ctx.budget.step(); err != nil {
			return err
		}
		// Each iteration starts from the enclosing scope again: a name set in
		// the body does not carry into the next iteration (Jinja 3).
		lf := f.child()
		lf.vars["loop"] = &loopObj{items: items, index: i}
		if err := ctx.assignTarget(x.target, it, lf); err != nil {
			return err
		}
		if err := ctx.renderNodes(t, x.body, lf, out, st); err != nil {
			return err
		}
	}
	return nil
}

// Macro is a {% macro %}; calling it renders its body to Markup.
type Macro struct {
	node    *macroNode
	tmpl    *Template
	ctx     *context
	closure *frame
}

func (m *Macro) Call(args []any, kwargs *Map) (any, error) {
	if err := m.ctx.budget.enter(); err != nil {
		return nil, err
	}
	defer m.ctx.budget.leave()
	mf := &frame{vars: map[string]any{}, parent: m.closure, ctx: m.ctx}
	if m.closure.toplevel {
		mf.parent = nil
	}
	n := m.node
	firstDefault := len(n.args) - len(n.defaults)
	var varargs []any
	for i, name := range n.args {
		switch {
		case i < len(args):
			mf.vars[name] = args[i]
		case kwargs != nil && hasKey(kwargs, name):
			mf.vars[name] = kwargs.Value(name)
		case i >= firstDefault:
			v, err := m.ctx.eval(n.defaults[i-firstDefault], mf)
			if err != nil {
				return nil, err
			}
			mf.vars[name] = v
		default:
			mf.vars[name] = Undefined{Name: name}
		}
	}
	if len(args) > len(n.args) {
		varargs = args[len(n.args):]
	}
	mf.vars["varargs"] = Tuple(varargs)
	extra := pyyaml.NewMap()
	if kwargs != nil {
		kwargs.Each(func(k, v any) {
			ks, _ := k.(string)
			found := false
			for _, a := range n.args {
				if a == ks {
					found = true
				}
			}
			if !found {
				extra.Set(k, v)
			}
		})
	}
	mf.vars["kwargs"] = extra
	var buf strings.Builder
	if err := m.ctx.renderNodes(m.tmpl, n.body, mf, &buf, nil); err != nil {
		return nil, err
	}
	return m.ctx.env.markup(buf.String()), nil
}

func hasKey(m *Map, k any) bool {
	_, ok := m.Get(k)
	return ok
}

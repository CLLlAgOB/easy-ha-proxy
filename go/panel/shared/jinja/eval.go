package jinja

import (
	"strings"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func (ctx *context) eval(e expr, f *frame) (any, error) {
	switch x := e.(type) {
	case *constExpr:
		return x.v, nil
	case *nameExpr:
		if v, ok := f.resolve(x.name); ok {
			return v, nil
		}
		if x.name == "super" && f.block != nil {
			b := f.block
			return Func(func(args []any, kwargs *Map) (any, error) {
				var buf strings.Builder
				if err := ctx.renderBlock(b.name, b.index+1, f, &buf); err != nil {
					return nil, err
				}
				return Markup(buf.String()), nil
			}), nil
		}
		return Undefined{Name: x.name}, nil
	case *getattrExpr:
		obj, err := ctx.eval(x.obj, f)
		if err != nil {
			return nil, err
		}
		return getAttr(obj, x.attr)
	case *getitemExpr:
		obj, err := ctx.eval(x.obj, f)
		if err != nil {
			return nil, err
		}
		if s, ok := x.arg.(*sliceExpr); ok {
			return ctx.evalSlice(obj, s, f)
		}
		arg, err := ctx.eval(x.arg, f)
		if err != nil {
			return nil, err
		}
		return getItem(obj, arg)
	case *callExpr:
		if ga, ok := x.fn.(*getattrExpr); ok && (ga.attr == "append" || ga.attr == "extend") {
			if handled, v, err := ctx.listMutation(ga, x, f); handled {
				return v, err
			}
		}
		fn, err := ctx.eval(x.fn, f)
		if err != nil {
			return nil, err
		}
		args, kwargs, err := ctx.evalArgs(x.args, x.kwargs, x.dyn, x.dynKw, f)
		if err != nil {
			return nil, err
		}
		return callValue(fn, args, kwargs)
	case *filterExpr:
		var v any
		if x.node != nil {
			var err error
			if v, err = ctx.eval(x.node, f); err != nil {
				return nil, err
			}
		}
		return ctx.applyFilter(x, v, f)
	case *testExpr:
		v, err := ctx.eval(x.node, f)
		if err != nil {
			return nil, err
		}
		test, ok := ctx.env.Tests[x.name]
		if !ok {
			return nil, errf("No test named '%s'.", x.name)
		}
		args, _, err := ctx.evalArgs(x.args, x.kwargs, nil, nil, f)
		if err != nil {
			return nil, err
		}
		r, err := test(ctx.env, v, args)
		if err != nil {
			return nil, err
		}
		return r != x.negate, nil
	case *binExpr:
		l, err := ctx.eval(x.l, f)
		if err != nil {
			return nil, err
		}
		r, err := ctx.eval(x.r, f)
		if err != nil {
			return nil, err
		}
		return binop(x.op, l, r)
	case *unaryExpr:
		v, err := ctx.eval(x.e, f)
		if err != nil {
			return nil, err
		}
		i, fl, isInt, ok := asNumber(v)
		if !ok {
			return nil, errf("bad operand type for unary %s: '%s'", x.op, typeName(v))
		}
		if x.op == "+" {
			if isInt {
				return i, nil
			}
			return fl, nil
		}
		if isInt {
			return -i, nil
		}
		return -fl, nil
	case *compareExpr:
		l, err := ctx.eval(x.first, f)
		if err != nil {
			return nil, err
		}
		for i, op := range x.ops {
			r, err := ctx.eval(x.rest[i], f)
			if err != nil {
				return nil, err
			}
			ok, err := compareOp(op, l, r)
			if err != nil {
				return nil, err
			}
			if !ok {
				return false, nil
			}
			l = r
		}
		return true, nil
	case *andExpr:
		l, err := ctx.eval(x.l, f)
		if err != nil {
			return nil, err
		}
		if !Truthy(l) {
			return l, nil
		}
		return ctx.eval(x.r, f)
	case *orExpr:
		l, err := ctx.eval(x.l, f)
		if err != nil {
			return nil, err
		}
		if Truthy(l) {
			return l, nil
		}
		return ctx.eval(x.r, f)
	case *notExpr:
		v, err := ctx.eval(x.e, f)
		if err != nil {
			return nil, err
		}
		return !Truthy(v), nil
	case *condExpr:
		t, err := ctx.eval(x.test, f)
		if err != nil {
			return nil, err
		}
		if Truthy(t) {
			return ctx.eval(x.a, f)
		}
		if x.b == nil {
			return Undefined{Name: "<conditional>"}, nil
		}
		return ctx.eval(x.b, f)
	case *listExpr:
		out := make([]any, 0, len(x.items))
		for _, it := range x.items {
			v, err := ctx.eval(it, f)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case *tupleExpr:
		out := make(Tuple, 0, len(x.items))
		for _, it := range x.items {
			v, err := ctx.eval(it, f)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case *dictExpr:
		m := pyyaml.NewMap()
		for i := range x.keys {
			k, err := ctx.eval(x.keys[i], f)
			if err != nil {
				return nil, err
			}
			v, err := ctx.eval(x.vals[i], f)
			if err != nil {
				return nil, err
			}
			if err := checkHashable(k); err != nil {
				return nil, err
			}
			m.Set(normalize(k), v)
		}
		return m, nil
	case *concatExpr:
		parts := make([]any, 0, len(x.items))
		for _, it := range x.items {
			v, err := ctx.eval(it, f)
			if err != nil {
				return nil, err
			}
			parts = append(parts, v)
		}
		if !ctx.env.Autoescape {
			var b strings.Builder
			for _, p := range parts {
				b.WriteString(Str(p))
			}
			return b.String(), nil
		}
		return markupJoin(parts), nil
	case *nsRefExpr:
		ns, _ := f.resolve(x.name)
		return getAttr(ns, x.attr)
	}
	return nil, errf("cannot evaluate %T", e)
}

func compareOp(op string, l, r any) (bool, error) {
	switch op {
	case "==":
		return Equal(l, r), nil
	case "!=":
		return !Equal(l, r), nil
	case "in":
		return Contains(l, r)
	case "notin":
		ok, err := Contains(l, r)
		return !ok, err
	}
	if isUndefined(l) || isUndefined(r) {
		return false, errf("'%s' is undefined", undefName(l, r))
	}
	c, err := compare(l, r)
	if err != nil {
		return false, err
	}
	switch op {
	case "<":
		return c < 0, nil
	case ">":
		return c > 0, nil
	case "<=":
		return c <= 0, nil
	case ">=":
		return c >= 0, nil
	}
	return false, errf("unknown operator %s", op)
}

func (ctx *context) evalArgs(args []expr, kwargs []kwarg, dyn, dynKw expr, f *frame) ([]any, *Map, error) {
	out := make([]any, 0, len(args))
	for _, a := range args {
		v, err := ctx.eval(a, f)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, v)
	}
	if dyn != nil {
		v, err := ctx.eval(dyn, f)
		if err != nil {
			return nil, nil, err
		}
		items, err := iterate(v)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, items...)
	}
	kw := pyyaml.NewMap()
	for _, k := range kwargs {
		v, err := ctx.eval(k.val, f)
		if err != nil {
			return nil, nil, err
		}
		kw.Set(k.name, v)
	}
	if dynKw != nil {
		v, err := ctx.eval(dynKw, f)
		if err != nil {
			return nil, nil, err
		}
		if m, ok := normalize(v).(*Map); ok {
			m.Each(func(k, v any) { kw.Set(k, v) })
		}
	}
	return out, kw, nil
}

func (ctx *context) applyFilter(x *filterExpr, v any, f *frame) (any, error) {
	flt, ok := ctx.env.Filters[x.name]
	if !ok {
		return nil, errf("No filter named '%s'.", x.name)
	}
	args, kwargs, err := ctx.evalArgs(x.args, x.kwargs, x.dyn, x.dynKw, f)
	if err != nil {
		return nil, err
	}
	return flt(ctx.env, v, args, kwargs)
}

func callValue(fn any, args []any, kwargs *Map) (any, error) {
	switch c := fn.(type) {
	case Callable:
		return c.Call(args, kwargs)
	case func(args []any, kwargs *Map) (any, error):
		return c(args, kwargs)
	case Undefined:
		return nil, errf("'%s' is undefined", c.Name)
	}
	return nil, errf("'%s' object is not callable", typeName(fn))
}

func (ctx *context) evalSlice(obj any, s *sliceExpr, f *frame) (any, error) {
	var idx [3]any
	for i, e := range []expr{s.start, s.stop, s.step} {
		if e == nil {
			continue
		}
		v, err := ctx.eval(e, f)
		if err != nil {
			return nil, err
		}
		idx[i] = v
	}
	return sliceValue(obj, idx[0], idx[1], idx[2])
}

func sliceIndices(n int, start, stop, step any) ([]int, error) {
	st := int64(1)
	if step != nil {
		s, _, isInt, ok := asNumber(step)
		if !ok || !isInt {
			return nil, errf("slice indices must be integers or None")
		}
		if s == 0 {
			return nil, errf("slice step cannot be zero")
		}
		st = s
	}
	conv := func(v any, def int64) (int64, error) {
		if v == nil {
			return def, nil
		}
		i, _, isInt, ok := asNumber(v)
		if !ok || !isInt {
			return 0, errf("slice indices must be integers or None")
		}
		if i < 0 {
			i += int64(n)
			if i < 0 {
				if st < 0 {
					i = -1
				} else {
					i = 0
				}
			}
		} else if i >= int64(n) {
			if st < 0 {
				i = int64(n) - 1
			} else {
				i = int64(n)
			}
		}
		return i, nil
	}
	var a, b int64
	var err error
	if st > 0 {
		if a, err = conv(start, 0); err != nil {
			return nil, err
		}
		if b, err = conv(stop, int64(n)); err != nil {
			return nil, err
		}
	} else {
		if a, err = conv(start, int64(n)-1); err != nil {
			return nil, err
		}
		if stop == nil {
			b = -1
		} else if b, err = conv(stop, -1); err != nil {
			return nil, err
		}
	}
	var out []int
	if st > 0 {
		for i := a; i < b; i += st {
			out = append(out, int(i))
		}
	} else {
		for i := a; i > b; i += st {
			out = append(out, int(i))
		}
	}
	return out, nil
}

func sliceValue(obj, start, stop, step any) (any, error) {
	obj = normalize(obj)
	switch x := obj.(type) {
	case []any:
		ix, err := sliceIndices(len(x), start, stop, step)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(ix))
		for _, i := range ix {
			out = append(out, x[i])
		}
		return out, nil
	case Tuple:
		ix, err := sliceIndices(len(x), start, stop, step)
		if err != nil {
			return nil, err
		}
		out := make(Tuple, 0, len(ix))
		for _, i := range ix {
			out = append(out, x[i])
		}
		return out, nil
	case string, Markup:
		s, _ := isStr(x)
		rs := []rune(s)
		ix, err := sliceIndices(len(rs), start, stop, step)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		for _, i := range ix {
			b.WriteRune(rs[i])
		}
		if _, ok := x.(Markup); ok {
			return Markup(b.String()), nil
		}
		return b.String(), nil
	case Undefined:
		return nil, errf("'%s' is undefined", x.Name)
	}
	return Undefined{}, nil
}

// getAttr is Environment.getattr: attribute first, then item.
func getAttr(obj any, attr string) (any, error) {
	obj = normalize(obj)
	switch x := obj.(type) {
	case Undefined:
		return nil, errf("'%s' is undefined", undefLabel(x))
	case *Undefined:
		return nil, errf("'%s' is undefined", undefLabel(*x))
	case Obj:
		if v, ok := x[attr]; ok {
			return normalize(v), nil
		}
		return Undefined{Name: attr}, nil
	case Namespace:
		if v, ok := x.M.Get(attr); ok {
			return v, nil
		}
		return Undefined{Name: attr}, nil
	case *loopObj:
		if v, ok := x.attr(attr); ok {
			return v, nil
		}
		return Undefined{Name: attr}, nil
	case AttrGetter:
		if v, ok := x.GetAttr(attr); ok {
			return normalize(v), nil
		}
		return Undefined{Name: attr}, nil
	}
	if m, ok := method(obj, attr); ok {
		return m, nil
	}
	if v, ok := itemLookup(obj, attr); ok {
		return v, nil
	}
	return Undefined{Name: attr}, nil
}

func undefLabel(u Undefined) string {
	if u.Name == "" {
		return "undefined"
	}
	return u.Name
}

// AttrGetter lets Go values expose Python-style attributes.
type AttrGetter interface {
	GetAttr(name string) (any, bool)
}

// getItem is Environment.getitem: item first, then attribute for str keys.
func getItem(obj, arg any) (any, error) {
	obj = normalize(obj)
	arg = normalize(arg)
	switch x := obj.(type) {
	case Undefined:
		return nil, errf("'%s' is undefined", undefLabel(x))
	case *Undefined:
		return nil, errf("'%s' is undefined", undefLabel(*x))
	}
	if t, ok := arg.(Tuple); ok {
		_ = t
	}
	if v, ok := itemLookup(obj, arg); ok {
		return v, nil
	}
	if s, ok := arg.(string); ok {
		switch x := obj.(type) {
		case Obj:
			if v, ok := x[s]; ok {
				return normalize(v), nil
			}
		case Namespace:
			if v, ok := x.M.Get(s); ok {
				return v, nil
			}
		case *loopObj:
			if v, ok := x.attr(s); ok {
				return v, nil
			}
		case AttrGetter:
			if v, ok := x.GetAttr(s); ok {
				return normalize(v), nil
			}
		}
		if m, ok := method(obj, s); ok {
			return m, nil
		}
	}
	return Undefined{Name: Str(arg)}, nil
}

func itemLookup(obj, key any) (any, bool) {
	switch x := obj.(type) {
	case *Map:
		if v, ok := x.Get(key); ok {
			return v, true
		}
		return nil, false
	case []any:
		return indexSeq(x, key)
	case Tuple:
		return indexSeq([]any(x), key)
	case string, Markup:
		s, _ := isStr(x)
		rs := []rune(s)
		i, _, isInt, ok := asNumber(key)
		if !ok || !isInt {
			return nil, false
		}
		if i < 0 {
			i += int64(len(rs))
		}
		if i < 0 || i >= int64(len(rs)) {
			return nil, false
		}
		return string(rs[i]), true
	}
	return nil, false
}

func indexSeq(x []any, key any) (any, bool) {
	// A bool indexes like 0 or 1, as in Python: asNumber reads it as an int.
	i, _, isInt, ok := asNumber(key)
	if !ok || !isInt {
		return nil, false
	}
	if i < 0 {
		i += int64(len(x))
	}
	if i < 0 || i >= int64(len(x)) {
		return nil, false
	}
	return x[i], true
}

// listMutation implements list.append/extend: Go slices are values, so the
// grown list is stored back into the namespace, dict or variable it came from.
func (ctx *context) listMutation(ga *getattrExpr, call *callExpr, f *frame) (bool, any, error) {
	obj, err := ctx.eval(ga.obj, f)
	if err != nil {
		return true, nil, err
	}
	list, ok := obj.([]any)
	if !ok {
		return false, nil, nil
	}
	args, _, err := ctx.evalArgs(call.args, call.kwargs, call.dyn, call.dynKw, f)
	if err != nil {
		return true, nil, err
	}
	if len(args) != 1 {
		return true, nil, errf("%s() takes exactly one argument (%d given)", ga.attr, len(args))
	}
	grown := append(append([]any{}, list...), args[0])
	if ga.attr == "extend" {
		items, err := iterate(args[0])
		if err != nil {
			return true, nil, err
		}
		grown = append(append([]any{}, list...), items...)
	}
	switch target := ga.obj.(type) {
	case *getattrExpr:
		holder, err := ctx.eval(target.obj, f)
		if err != nil {
			return true, nil, err
		}
		switch h := holder.(type) {
		case Namespace:
			h.M.Set(target.attr, grown)
		case *Map:
			h.Set(target.attr, grown)
		default:
			return true, nil, errf("cannot append to a list held by %s", typeName(holder))
		}
	case *getitemExpr:
		holder, err := ctx.eval(target.obj, f)
		if err != nil {
			return true, nil, err
		}
		key, err := ctx.eval(target.arg, f)
		if err != nil {
			return true, nil, err
		}
		if h, ok := holder.(*Map); ok {
			h.Set(normalize(key), grown)
		}
	case *nameExpr:
		for fr := f; fr != nil; fr = fr.parent {
			if _, ok := fr.vars[target.name]; ok {
				fr.vars[target.name] = grown
				return true, nil, nil
			}
		}
		if _, ok := f.ctx.vars[target.name]; ok {
			f.ctx.vars[target.name] = grown
		} else {
			f.ctx.parent[target.name] = grown
		}
	default:
		return true, nil, errf("cannot append here")
	}
	return true, nil, nil
}

package jinja

import (
	"html"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"easy-ha-proxy/panel/internal/pyyaml"
)

func builtinRange(args []any, _ *Map) (any, error) {
	ints := make([]int64, len(args))
	for i, a := range args {
		n, _, isInt, ok := asNumber(a)
		if !ok || !isInt {
			return nil, errf("'%s' object cannot be interpreted as an integer", typeName(a))
		}
		ints[i] = n
	}
	var start, stop int64
	step := int64(1)
	switch len(ints) {
	case 1:
		stop = ints[0]
	case 2:
		start, stop = ints[0], ints[1]
	case 3:
		start, stop, step = ints[0], ints[1], ints[2]
	default:
		return nil, errf("range expected 1 to 3 arguments")
	}
	if step == 0 {
		return nil, errf("range() arg 3 must not be zero")
	}
	out := []any{}
	for i := start; (step > 0 && i < stop) || (step < 0 && i > stop); i += step {
		out = append(out, i)
		if len(out) > 100000 {
			return nil, errf("range too big")
		}
	}
	return out, nil
}

// SortKeysDeep returns v with every dict's keys sorted (json sort_keys=True).
func SortKeysDeep(v any) any {
	switch x := normalize(v).(type) {
	case *Map:
		keys := x.Keys()
		sort.SliceStable(keys, func(i, j int) bool { return Str(keys[i]) < Str(keys[j]) })
		m := pyyaml.NewMap()
		for _, k := range keys {
			m.Set(k, SortKeysDeep(x.Value(k)))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = SortKeysDeep(e)
		}
		return out
	case Tuple:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = SortKeysDeep(e)
		}
		return out
	case Markup:
		return string(x)
	case Undefined:
		return nil
	}
	return v
}

// FlaskJSONDumps is flask.json.dumps: sort_keys=True, ensure_ascii=True.
func FlaskJSONDumps(v any) (string, error) {
	return pyyaml.JSONDumps(SortKeysDeep(v), true, false)
}

var htmlSafeJSON = strings.NewReplacer(
	"<", "\\"+"u003c",
	">", "\\"+"u003e",
	"&", "\\"+"u0026",
	"'", "\\"+"u0027",
)

func getAttrPath(item any, attr string) (any, error) {
	if attr == "" {
		return item, nil
	}
	v := item
	for _, part := range strings.Split(attr, ".") {
		var key any = part
		if n, err := strconv.ParseInt(part, 10, 64); err == nil && isAllDigits(part) {
			key = n
		}
		var err error
		if v, err = getItem(v, key); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func kw(kwargs *Map, name string) (any, bool) {
	if kwargs == nil {
		return nil, false
	}
	return kwargs.Get(name)
}

func sortKey(v any, caseSensitive bool) any {
	if !caseSensitive {
		if s, ok := isStr(v); ok {
			return strings.ToLower(s)
		}
	}
	return v
}

var (
	stripCommentsRe = regexp.MustCompile(`(?s)<!--.*?-->`)
	stripTagsRe     = regexp.MustCompile(`(?s)<.*?>`)
)

func selectOrReject(env *Environment, value any, args []any, attrMode, selectMode bool) (any, error) {
	items, err := iterate(value)
	if err != nil {
		return nil, err
	}
	attr := ""
	if attrMode {
		if len(args) == 0 {
			return nil, errf("Missing parameter for attribute name")
		}
		attr = Str(args[0])
		args = args[1:]
	}
	var test TestFunc
	var testArgs []any
	if len(args) > 0 {
		name := Str(args[0])
		t, ok := env.Tests[name]
		if !ok {
			return nil, errf("No test named '%s'.", name)
		}
		test = t
		testArgs = args[1:]
	}
	out := []any{}
	for _, it := range items {
		v := it
		if attrMode {
			if v, err = getAttrPath(it, attr); err != nil {
				return nil, err
			}
		}
		var ok bool
		if test == nil {
			ok = Truthy(v)
		} else if ok, err = test(env, v, testArgs); err != nil {
			return nil, err
		}
		if ok == selectMode {
			out = append(out, it)
		}
	}
	return out, nil
}

func builtinFilters() map[string]FilterFunc {
	f := map[string]FilterFunc{}
	f["default"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		def := argOr(args, kwargs, 0, "default_value", "")
		boolean := Truthy(argOr(args, kwargs, 1, "boolean", false))
		if isUndefined(v) || (boolean && !Truthy(v)) {
			return def, nil
		}
		return v, nil
	}
	f["d"] = f["default"]
	f["join"] = func(env *Environment, v any, args []any, kwargs *Map) (any, error) {
		d := argOr(args, kwargs, 0, "d", "")
		attr, _ := kw(kwargs, "attribute")
		if len(args) > 1 {
			attr = args[1]
		}
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		items = append([]any{}, items...)
		if attr != nil {
			for i, it := range items {
				if items[i], err = getAttrPath(it, Str(attr)); err != nil {
					return nil, err
				}
			}
		}
		html := false
		if !env.Autoescape {
			parts := make([]string, len(items))
			for i, it := range items {
				parts[i] = Str(it)
			}
			return strings.Join(parts, Str(d)), nil
		}
		if _, ok := d.(Markup); ok {
			html = true
		}
		for _, it := range items {
			if _, ok := it.(Markup); ok {
				html = true
			}
		}
		parts := make([]string, len(items))
		for i, it := range items {
			if html {
				parts[i] = string(Escape(it))
			} else {
				parts[i] = Str(it)
			}
		}
		if html {
			return Markup(strings.Join(parts, string(Escape(d)))), nil
		}
		return strings.Join(parts, Str(d)), nil
	}
	f["length"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return length(v) }
	f["count"] = f["length"]
	f["list"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		return append([]any{}, items...), nil
	}
	f["tojson"] = func(env *Environment, v any, _ []any, _ *Map) (any, error) {
		dumps := env.JSONDumps
		if dumps == nil {
			dumps = FlaskJSONDumps
		}
		s, err := dumps(v)
		if err != nil {
			return nil, err
		}
		return Markup(htmlSafeJSON.Replace(s)), nil
	}
	f["selectattr"] = func(env *Environment, v any, args []any, _ *Map) (any, error) {
		return selectOrReject(env, v, args, true, true)
	}
	f["rejectattr"] = func(env *Environment, v any, args []any, _ *Map) (any, error) {
		return selectOrReject(env, v, args, true, false)
	}
	f["select"] = func(env *Environment, v any, args []any, _ *Map) (any, error) {
		return selectOrReject(env, v, args, false, true)
	}
	f["reject"] = func(env *Environment, v any, args []any, _ *Map) (any, error) {
		return selectOrReject(env, v, args, false, false)
	}
	f["map"] = func(env *Environment, v any, args []any, kwargs *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(items))
		if attr, ok := kw(kwargs, "attribute"); ok {
			def, hasDef := kw(kwargs, "default")
			for _, it := range items {
				val, err := getAttrPath(it, Str(attr))
				if err != nil {
					return nil, err
				}
				if hasDef && isUndefined(val) {
					val = def
				}
				out = append(out, val)
			}
			return out, nil
		}
		if len(args) == 0 {
			return out, nil
		}
		name := Str(args[0])
		flt, ok := env.Filters[name]
		if !ok {
			return nil, errf("No filter named '%s'.", name)
		}
		for _, it := range items {
			val, err := flt(env, it, args[1:], kwargs)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	}
	f["string"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return softStr(v), nil }
	f["lower"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		s := softStr(v)
		if m, ok := s.(Markup); ok {
			return Markup(strings.ToLower(string(m))), nil
		}
		return strings.ToLower(s.(string)), nil
	}
	f["upper"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		s := softStr(v)
		if m, ok := s.(Markup); ok {
			return Markup(strings.ToUpper(string(m))), nil
		}
		return strings.ToUpper(s.(string)), nil
	}
	f["trim"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		s := softStr(v)
		chars := argOr(args, kwargs, 0, "chars", nil)
		str, _ := isStr(s)
		if chars == nil {
			str = strings.TrimFunc(str, unicode.IsSpace)
		} else {
			str = strings.Trim(str, Str(chars))
		}
		if _, ok := s.(Markup); ok {
			return Markup(str), nil
		}
		return str, nil
	}
	f["replace"] = func(env *Environment, v any, args []any, kwargs *Map) (any, error) {
		old := argOr(args, kwargs, 0, "old", "")
		nw := argOr(args, kwargs, 1, "new", "")
		count := int64(-1)
		if c := argOr(args, kwargs, 2, "count", nil); c != nil {
			count, _, _, _ = asNumber(c)
		}
		if !env.Autoescape {
			return strings.Replace(Str(v), Str(old), Str(nw), int(count)), nil
		}
		_, oldHTML := old.(Markup)
		_, newHTML := nw.(Markup)
		_, sHTML := v.(Markup)
		var s any
		if oldHTML || (newHTML && !sHTML) {
			s = Escape(v)
		} else {
			s = softStr(v)
		}
		if m, ok := s.(Markup); ok {
			return Markup(strings.Replace(string(m), string(Escape(old)), string(Escape(nw)), int(count))), nil
		}
		return strings.Replace(s.(string), Str(old), Str(nw), int(count)), nil
	}
	f["striptags"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		s := stripCommentsRe.ReplaceAllString(Str(v), "")
		s = stripTagsRe.ReplaceAllString(s, "")
		s = strings.Join(strings.Fields(s), " ")
		return html.UnescapeString(s), nil
	}
	f["format"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		s := softStr(v)
		str, _ := isStr(s)
		if kwargs != nil && kwargs.Len() > 0 {
			return percentFormat(s, str, kwargs)
		}
		return percentFormat(s, str, Tuple(args))
	}
	f["forceescape"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		return Markup(escapeString(Str(v))), nil
	}
	f["escape"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return Escape(v), nil }
	f["e"] = f["escape"]
	f["safe"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return Markup(Str(v)), nil }
	f["dictsort"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		m, ok := normalize(v).(*Map)
		if !ok {
			return nil, errf("You can only sort by either 'key' or 'value'")
		}
		caseSensitive := Truthy(argOr(args, kwargs, 0, "case_sensitive", false))
		by := Str(argOr(args, kwargs, 1, "by", "key"))
		reverse := Truthy(argOr(args, kwargs, 2, "reverse", false))
		pos := 0
		if by == "value" {
			pos = 1
		}
		items := []any{}
		m.Each(func(k, val any) { items = append(items, Tuple{k, val}) })
		var sortErr error
		sort.SliceStable(items, func(i, j int) bool {
			a := sortKey(items[i].(Tuple)[pos], caseSensitive)
			b := sortKey(items[j].(Tuple)[pos], caseSensitive)
			c, err := compare(a, b)
			if err != nil {
				sortErr = err
			}
			if reverse {
				return c > 0
			}
			return c < 0
		})
		return items, sortErr
	}
	f["sort"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		items = append([]any{}, items...)
		reverse := Truthy(argOr(args, kwargs, 0, "reverse", false))
		caseSensitive := Truthy(argOr(args, kwargs, 1, "case_sensitive", false))
		attr := argOr(args, kwargs, 2, "attribute", nil)
		var sortErr error
		key := func(it any) any {
			if attr != nil {
				val, err := getAttrPath(it, Str(attr))
				if err != nil {
					sortErr = err
				}
				it = val
			}
			return sortKey(it, caseSensitive)
		}
		sort.SliceStable(items, func(i, j int) bool {
			c, err := compare(key(items[i]), key(items[j]))
			if err != nil {
				sortErr = err
			}
			if reverse {
				return c > 0
			}
			return c < 0
		})
		return items, sortErr
	}
	f["first"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return Undefined{Name: "first"}, nil
		}
		return items[0], nil
	}
	f["last"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return Undefined{Name: "last"}, nil
		}
		return items[len(items)-1], nil
	}
	f["reverse"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		if s, ok := isStr(v); ok {
			rs := []rune(s)
			for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
				rs[i], rs[j] = rs[j], rs[i]
			}
			return string(rs), nil
		}
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		out := make([]any, len(items))
		for i, it := range items {
			out[len(items)-1-i] = it
		}
		return out, nil
	}
	f["unique"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		caseSensitive := Truthy(argOr(args, kwargs, 0, "case_sensitive", false))
		var seen []any
		out := []any{}
		for _, it := range items {
			if err := checkHashable(it); err != nil {
				return nil, err
			}
			k := sortKey(it, caseSensitive)
			dup := false
			for _, s := range seen {
				if Equal(s, k) {
					dup = true
					break
				}
			}
			if !dup {
				seen = append(seen, k)
				out = append(out, it)
			}
		}
		return out, nil
	}
	f["int"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		def := argOr(args, kwargs, 0, "default", int64(0))
		if s, ok := isStr(v); ok {
			t := strings.TrimSpace(strings.ReplaceAll(s, "_", ""))
			if n, err := strconv.ParseInt(t, 10, 64); err == nil {
				return n, nil
			}
			if fl, err := strconv.ParseFloat(t, 64); err == nil && !math.IsInf(fl, 0) && !math.IsNaN(fl) {
				return int64(fl), nil
			}
			return def, nil
		}
		if n, fl, isInt, ok := asNumber(v); ok {
			if isInt {
				return n, nil
			}
			return int64(fl), nil
		}
		return def, nil
	}
	f["float"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		def := argOr(args, kwargs, 0, "default", 0.0)
		if s, ok := isStr(v); ok {
			if fl, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				return fl, nil
			}
			return def, nil
		}
		if _, fl, _, ok := asNumber(v); ok {
			return fl, nil
		}
		return def, nil
	}
	f["abs"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		n, fl, isInt, ok := asNumber(v)
		if !ok {
			return nil, errf("bad operand type for abs(): '%s'", typeName(v))
		}
		if isInt {
			if n < 0 {
				return -n, nil
			}
			return n, nil
		}
		return math.Abs(fl), nil
	}
	f["round"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		precision, _, _, _ := asNumber(argOr(args, kwargs, 0, "precision", int64(0)))
		method := Str(argOr(args, kwargs, 1, "method", "common"))
		_, fl, _, ok := asNumber(v)
		if !ok {
			return nil, errf("must be real number, not %s", typeName(v))
		}
		p := math.Pow(10, float64(precision))
		switch method {
		case "ceil":
			return math.Ceil(fl*p) / p, nil
		case "floor":
			return math.Floor(fl*p) / p, nil
		}
		// Python round() on the value is half-to-even on the binary value;
		// strconv formatting rounds the exact binary value the same way for
		// non-negative precision. Negative precision rounds to powers of 10.
		if precision < 0 {
			scale := math.Pow(10, float64(-precision))
			if math.IsInf(scale, 0) || scale == 0 {
				return 0.0, nil
			}
			return math.RoundToEven(fl/scale) * scale, nil
		}
		s := strconv.FormatFloat(fl, 'f', int(precision), 64)
		r, _ := strconv.ParseFloat(s, 64)
		return r, nil
	}
	f["sum"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		attr := argOr(args, kwargs, 0, "attribute", nil)
		var total any = argOr(args, kwargs, 1, "start", int64(0))
		for _, it := range items {
			if attr != nil {
				if it, err = getAttrPath(it, Str(attr)); err != nil {
					return nil, err
				}
			}
			if total, err = binop("+", total, it); err != nil {
				return nil, err
			}
		}
		return total, nil
	}
	minmax := func(wantMax bool) FilterFunc {
		return func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
			items, err := iterate(v)
			if err != nil {
				return nil, err
			}
			if len(items) == 0 {
				return Undefined{Name: "min"}, nil
			}
			caseSensitive := Truthy(argOr(args, kwargs, 0, "case_sensitive", false))
			attr := argOr(args, kwargs, 1, "attribute", nil)
			best := items[0]
			key := func(it any) any {
				if attr != nil {
					it, _ = getAttrPath(it, Str(attr))
				}
				return sortKey(it, caseSensitive)
			}
			for _, it := range items[1:] {
				c, err := compare(key(it), key(best))
				if err != nil {
					return nil, err
				}
				if (wantMax && c > 0) || (!wantMax && c < 0) {
					best = it
				}
			}
			return best, nil
		}
	}
	f["max"] = minmax(true)
	f["min"] = minmax(false)
	f["items"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		if isUndefined(v) {
			return []any{}, nil
		}
		m, ok := normalize(v).(*Map)
		if !ok {
			return nil, errf("Can only get item pairs from a mapping.")
		}
		out := []any{}
		m.Each(func(k, val any) { out = append(out, Tuple{k, val}) })
		return out, nil
	}
	f["title"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return pyTitle(Str(v)), nil }
	f["capitalize"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return pyCapitalize(Str(v)), nil }
	f["urlencode"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		if m, ok := normalize(v).(*Map); ok {
			parts := []string{}
			m.Each(func(k, val any) {
				parts = append(parts, url.QueryEscape(Str(k))+"="+url.QueryEscape(Str(val)))
			})
			return strings.Join(parts, "&"), nil
		}
		return strings.ReplaceAll(url.PathEscape(Str(v)), "+", "%2B"), nil
	}
	f["wordcount"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) {
		return int64(len(regexp.MustCompile(`\w+`).FindAllString(Str(v), -1))), nil
	}
	f["attr"] = func(_ *Environment, v any, args []any, _ *Map) (any, error) {
		return getAttr(v, Str(argOr(args, nil, 0, "", "")))
	}
	f["truncate"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		s := Str(v)
		n, _, _, _ := asNumber(argOr(args, kwargs, 0, "length", int64(255)))
		killwords := Truthy(argOr(args, kwargs, 1, "killwords", false))
		end := Str(argOr(args, kwargs, 2, "end", "..."))
		leeway, _, _, _ := asNumber(argOr(args, kwargs, 3, "leeway", int64(5)))
		rs := []rune(s)
		if int64(len(rs)) <= n+leeway {
			return s, nil
		}
		cut := int(n) - len([]rune(end))
		if cut < 0 {
			cut = 0
		}
		if killwords {
			return string(rs[:cut]) + end, nil
		}
		head := string(rs[:cut])
		if i := strings.LastIndex(head, " "); i >= 0 {
			head = head[:i]
		}
		return head + end, nil
	}
	f["batch"] = func(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
		items, err := iterate(v)
		if err != nil {
			return nil, err
		}
		n, _, _, _ := asNumber(argOr(args, kwargs, 0, "linecount", int64(1)))
		fill := argOr(args, kwargs, 1, "fill_with", nil)
		out := []any{}
		var cur []any
		for _, it := range items {
			cur = append(cur, it)
			if int64(len(cur)) == n {
				out = append(out, cur)
				cur = nil
			}
		}
		if len(cur) > 0 {
			if fill != nil {
				for int64(len(cur)) < n {
					cur = append(cur, fill)
				}
			}
			out = append(out, cur)
		}
		return out, nil
	}
	f["pprint"] = func(_ *Environment, v any, _ []any, _ *Map) (any, error) { return Repr(v), nil }
	return f
}

func builtinTests() map[string]TestFunc {
	t := map[string]TestFunc{}
	t["defined"] = func(_ *Environment, v any, _ []any) (bool, error) { return !isUndefined(v), nil }
	t["undefined"] = func(_ *Environment, v any, _ []any) (bool, error) { return isUndefined(v), nil }
	t["none"] = func(_ *Environment, v any, _ []any) (bool, error) { return v == nil, nil }
	t["mapping"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := normalize(v).(*Map)
		return ok, nil
	}
	t["string"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := isStr(v)
		return ok, nil
	}
	t["number"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, _, _, ok := asNumber(v)
		return ok, nil
	}
	t["integer"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := normalize(v).(int64)
		return ok, nil
	}
	t["float"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := normalize(v).(float64)
		return ok, nil
	}
	t["boolean"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := v.(bool)
		return ok, nil
	}
	t["true"] = func(_ *Environment, v any, _ []any) (bool, error) { return v == true, nil }
	t["false"] = func(_ *Environment, v any, _ []any) (bool, error) { return v == false, nil }
	t["sequence"] = func(_ *Environment, v any, _ []any) (bool, error) {
		switch normalize(v).(type) {
		case string, Markup, []any, Tuple, *Map, Undefined:
			return true, nil
		}
		return false, nil
	}
	t["iterable"] = func(_ *Environment, v any, _ []any) (bool, error) {
		switch normalize(v).(type) {
		case string, Markup, []any, Tuple, *Map, Undefined:
			return true, nil
		}
		return false, nil
	}
	t["callable"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := v.(Callable)
		return ok, nil
	}
	t["sameas"] = func(_ *Environment, v any, args []any) (bool, error) {
		if len(args) != 1 {
			return false, errf("sameas needs one argument")
		}
		a, b := normalize(v), normalize(args[0])
		switch x := a.(type) {
		case nil:
			return b == nil, nil
		case bool:
			y, ok := b.(bool)
			return ok && x == y, nil
		case int64:
			y, ok := b.(int64)
			return ok && x == y && x >= -5 && x <= 256, nil
		}
		return false, nil
	}
	eq := func(_ *Environment, v any, args []any) (bool, error) {
		return Equal(v, argOr(args, nil, 0, "", nil)), nil
	}
	t["equalto"], t["eq"], t["=="] = eq, eq, eq
	ne := func(_ *Environment, v any, args []any) (bool, error) {
		return !Equal(v, argOr(args, nil, 0, "", nil)), nil
	}
	t["ne"], t["!="] = ne, ne
	cmpTest := func(op string) TestFunc {
		return func(_ *Environment, v any, args []any) (bool, error) {
			return compareOp(op, v, argOr(args, nil, 0, "", nil))
		}
	}
	t["lt"], t["<"] = cmpTest("<"), cmpTest("<")
	t["le"], t["<="] = cmpTest("<="), cmpTest("<=")
	t["gt"], t[">"], t["greaterthan"] = cmpTest(">"), cmpTest(">"), cmpTest(">")
	t["ge"], t[">="] = cmpTest(">="), cmpTest(">=")
	t["lessthan"] = cmpTest("<")
	t["in"] = func(_ *Environment, v any, args []any) (bool, error) {
		return Contains(v, argOr(args, nil, 0, "", nil))
	}
	t["odd"] = func(_ *Environment, v any, _ []any) (bool, error) {
		n, _, _, _ := asNumber(v)
		return pyMod(n, 2) == 1, nil
	}
	t["even"] = func(_ *Environment, v any, _ []any) (bool, error) {
		n, _, _, _ := asNumber(v)
		return pyMod(n, 2) == 0, nil
	}
	t["divisibleby"] = func(_ *Environment, v any, args []any) (bool, error) {
		n, _, _, _ := asNumber(v)
		d, _, _, _ := asNumber(argOr(args, nil, 0, "", int64(1)))
		return d != 0 && pyMod(n, d) == 0, nil
	}
	t["lower"] = func(_ *Environment, v any, _ []any) (bool, error) {
		s := Str(v)
		return s == strings.ToLower(s) && s != strings.ToUpper(s), nil
	}
	t["upper"] = func(_ *Environment, v any, _ []any) (bool, error) {
		s := Str(v)
		return s == strings.ToUpper(s) && s != strings.ToLower(s), nil
	}
	t["escaped"] = func(_ *Environment, v any, _ []any) (bool, error) {
		_, ok := v.(Markup)
		return ok, nil
	}
	return t
}

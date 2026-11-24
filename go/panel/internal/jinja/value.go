// Package jinja renders the Flask panel's Jinja2 templates unchanged, so the
// Go panel serves the same pages as the Python one. It implements the part of
// Jinja2 3.1 (with Flask's environment: autoescape on, default Undefined, no
// trim_blocks/lstrip_blocks) that the templates use, with Python value
// semantics for truthiness, str(), comparisons and arithmetic.
package jinja

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"easy-ha-proxy/panel/internal/pyyaml"
)

// Map is a Python dict (ordered).
type Map = pyyaml.Map

// Markup is markupsafe.Markup: a string that is already HTML.
type Markup string

// Tuple is a Python tuple (prints with parentheses).
type Tuple []any

// Undefined is jinja2.Undefined: falsy, prints as "", fails on attribute access.
type Undefined struct{ Name string }

// Obj is a Python object exposing attributes only (no item access), such as
// request or g.
type Obj map[string]any

// Namespace is jinja2's namespace(): attributes that a {% set ns.x %} can change.
type Namespace struct{ M *Map }

// Func is a callable global, filter-like helper or bound method.
type Func func(args []any, kwargs *Map) (any, error)

// Callable lets context values be called from a template.
type Callable interface {
	Call(args []any, kwargs *Map) (any, error)
}

func (f Func) Call(args []any, kwargs *Map) (any, error) { return f(args, kwargs) }

// Error is a template runtime error.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// normalize turns Go values a caller may pass into the engine's Python types.
func normalize(v any) any {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		return int64(x)
	case float32:
		return float64(x)
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, m := range x {
			out[i] = mapFromGo(m)
		}
		return out
	case map[string]any:
		return mapFromGo(x)
	case map[string]string:
		m := pyyaml.NewMap()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.Set(k, x[k])
		}
		return m
	}
	return v
}

func mapFromGo(x map[string]any) *Map {
	m := pyyaml.NewMap()
	keys := make([]string, 0, len(x))
	for k := range x {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m.Set(k, normalize(x[k]))
	}
	return m
}

// Truthy is bool(v).
func Truthy(v any) bool {
	switch x := normalize(v).(type) {
	case nil:
		return false
	case Undefined, *Undefined:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case Markup:
		return x != ""
	case []any:
		return len(x) > 0
	case Tuple:
		return len(x) > 0
	case *Map:
		return x.Len() > 0
	case Obj:
		return true
	case *loopObj:
		return true
	}
	return true
}

func isUndefined(v any) bool {
	switch v.(type) {
	case Undefined, *Undefined:
		return true
	}
	return false
}

// Str is str(v).
func Str(v any) string {
	switch x := normalize(v).(type) {
	case nil:
		return "None"
	case Undefined, *Undefined:
		return ""
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return pyyaml.FloatRepr(x)
	case string:
		return x
	case Markup:
		return string(x)
	case Macro, *Macro:
		return "<Macro>"
	}
	return Repr(v)
}

// Repr is repr(v).
func Repr(v any) string {
	switch x := normalize(v).(type) {
	case string:
		return reprString(x)
	case Markup:
		return "Markup(" + reprString(string(x)) + ")"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case Tuple:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		if len(x) == 1 {
			return "(" + parts[0] + ",)"
		}
		return "(" + strings.Join(parts, ", ") + ")"
	case *Map:
		parts := make([]string, 0, x.Len())
		x.Each(func(k, val any) { parts = append(parts, Repr(k)+": "+Repr(val)) })
		return "{" + strings.Join(parts, ", ") + "}"
	case Undefined, *Undefined:
		return "Undefined"
	case Namespace:
		return "<Namespace>"
	case nil, bool, int64, float64:
		return Str(x)
	}
	return fmt.Sprintf("%v", v)
}

func reprString(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == rune(quote):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case !isPrintable(r):
			switch {
			case r <= 0xff:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// isPrintable approximates str.isprintable() for one character.
func isPrintable(r rune) bool {
	if r == ' ' {
		return true
	}
	if unicode.IsSpace(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
		return false
	}
	return unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r)
}

// Escape is markupsafe.escape(v).
func Escape(v any) Markup {
	switch x := v.(type) {
	case Markup:
		return x
	}
	return Markup(escapeString(Str(v)))
}

func escapeString(s string) string {
	if !strings.ContainsAny(s, "&<>\"'") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&#34;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// softStr is markupsafe.soft_str: keeps Markup, str() for the rest.
func softStr(v any) any {
	if m, ok := v.(Markup); ok {
		return m
	}
	return Str(v)
}

func asNumber(v any) (int64, float64, bool, bool) {
	switch x := normalize(v).(type) {
	case bool:
		if x {
			return 1, 1, true, true
		}
		return 0, 0, true, true
	case int64:
		return x, float64(x), true, true
	case float64:
		return 0, x, false, true
	}
	return 0, 0, false, false
}

func isStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case Markup:
		return string(x), true
	}
	return "", false
}

func seqOf(v any) ([]any, bool) {
	switch x := normalize(v).(type) {
	case []any:
		return x, true
	case Tuple:
		return []any(x), true
	}
	return nil, false
}

func typeName(v any) string {
	switch normalize(v).(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int64:
		return "int"
	case float64:
		return "float"
	case string, Markup:
		return "str"
	case []any:
		return "list"
	case Tuple:
		return "tuple"
	case *Map:
		return "dict"
	case Undefined, *Undefined:
		return "Undefined"
	}
	return fmt.Sprintf("%T", v)
}

// Equal is a == b.
func Equal(a, b any) bool {
	a, b = normalize(a), normalize(b)
	if isUndefined(a) || isUndefined(b) {
		return isUndefined(a) && isUndefined(b)
	}
	if ai, af, aint, ok := asNumber(a); ok {
		if bi, bf, bint, ok2 := asNumber(b); ok2 {
			if aint && bint {
				return ai == bi
			}
			return af == bf
		}
		return false
	}
	if as, ok := isStr(a); ok {
		bs, ok2 := isStr(b)
		return ok2 && as == bs
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case []any:
		y, ok := b.([]any)
		return ok && seqEqual(x, y)
	case Tuple:
		y, ok := b.(Tuple)
		return ok && seqEqual(x, y)
	case *Map:
		y, ok := b.(*Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		eq := true
		x.Each(func(k, v any) {
			w, found := y.Get(k)
			if !found || !Equal(v, w) {
				eq = false
			}
		})
		return eq
	case Namespace:
		y, ok := b.(Namespace)
		return ok && x.M == y.M
	}
	return false
}

func seqEqual(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// compare returns -1/0/1 for a < b ordering, or an error for unorderable types.
func compare(a, b any) (int, error) {
	a, b = normalize(a), normalize(b)
	if ai, af, aint, ok := asNumber(a); ok {
		if bi, bf, bint, ok2 := asNumber(b); ok2 {
			if aint && bint {
				switch {
				case ai < bi:
					return -1, nil
				case ai > bi:
					return 1, nil
				}
				return 0, nil
			}
			switch {
			case af < bf:
				return -1, nil
			case af > bf:
				return 1, nil
			}
			return 0, nil
		}
	}
	if as, ok := isStr(a); ok {
		if bs, ok2 := isStr(b); ok2 {
			return strings.Compare(as, bs), nil
		}
	}
	if x, ok := seqOf(a); ok {
		if y, ok2 := seqOf(b); ok2 && typeName(a) == typeName(b) {
			for i := 0; i < len(x) && i < len(y); i++ {
				if !Equal(x[i], y[i]) {
					return compare(x[i], y[i])
				}
			}
			switch {
			case len(x) < len(y):
				return -1, nil
			case len(x) > len(y):
				return 1, nil
			}
			return 0, nil
		}
	}
	return 0, errf("'<' not supported between instances of '%s' and '%s'", typeName(a), typeName(b))
}

// Contains is needle in haystack.
func Contains(needle, haystack any) (bool, error) {
	haystack = normalize(haystack)
	switch h := haystack.(type) {
	case string, Markup:
		hs, _ := isStr(h)
		ns, ok := isStr(needle)
		if !ok {
			return false, errf("'in <string>' requires string as left operand, not %s", typeName(needle))
		}
		return strings.Contains(hs, ns), nil
	case []any:
		for _, e := range h {
			if Equal(e, needle) {
				return true, nil
			}
		}
		return false, nil
	case Tuple:
		for _, e := range h {
			if Equal(e, needle) {
				return true, nil
			}
		}
		return false, nil
	case *Map:
		if err := checkHashable(needle); err != nil {
			return false, err
		}
		_, ok := h.Get(normalize(needle))
		return ok, nil
	case Undefined, *Undefined:
		return false, nil
	case Namespace:
		return false, errf("argument of type 'Namespace' is not iterable")
	}
	return false, errf("argument of type '%s' is not iterable", typeName(haystack))
}

// iterate is iter(v) as a list.
func iterate(v any) ([]any, error) {
	switch x := normalize(v).(type) {
	case []any:
		return x, nil
	case Tuple:
		return []any(x), nil
	case *Map:
		return x.Keys(), nil
	case string:
		out := make([]any, 0, len(x))
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	case Markup:
		out := make([]any, 0, len(x))
		for _, r := range string(x) {
			out = append(out, string(r))
		}
		return out, nil
	case Undefined, *Undefined:
		return nil, nil
	case nil:
		return nil, errf("'NoneType' object is not iterable")
	}
	return nil, errf("'%s' object is not iterable", typeName(v))
}

func length(v any) (int64, error) {
	switch x := normalize(v).(type) {
	case string:
		return int64(utf8.RuneCountInString(x)), nil
	case Markup:
		return int64(utf8.RuneCountInString(string(x))), nil
	case []any:
		return int64(len(x)), nil
	case Tuple:
		return int64(len(x)), nil
	case *Map:
		return int64(x.Len()), nil
	case Undefined, *Undefined:
		return 0, nil
	}
	return 0, errf("object of type '%s' has no len()", typeName(v))
}

// markupJoin is jinja2.runtime.markup_join (the ~ operator under autoescape).
func markupJoin(parts []any) any {
	html := false
	for _, p := range parts {
		if _, ok := p.(Markup); ok {
			html = true
		}
	}
	var b strings.Builder
	for _, p := range parts {
		if html {
			b.WriteString(string(Escape(p)))
		} else {
			b.WriteString(Str(p))
		}
	}
	if html {
		return Markup(b.String())
	}
	return b.String()
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func pyMod(a, b int64) int64 {
	m := a % b
	if m != 0 && ((m < 0) != (b < 0)) {
		m += b
	}
	return m
}

func binop(op string, a, b any) (any, error) {
	a, b = normalize(a), normalize(b)
	if isUndefined(a) || isUndefined(b) {
		return nil, errf("'%s' is undefined", undefName(a, b))
	}
	ai, af, aint, aok := asNumber(a)
	bi, bf, bint, bok := asNumber(b)
	if aok && bok {
		switch op {
		case "+":
			if aint && bint {
				return ai + bi, nil
			}
			return af + bf, nil
		case "-":
			if aint && bint {
				return ai - bi, nil
			}
			return af - bf, nil
		case "*":
			if aint && bint {
				return ai * bi, nil
			}
			return af * bf, nil
		case "/":
			if bf == 0 {
				return nil, errf("division by zero")
			}
			return af / bf, nil
		case "//":
			if bf == 0 {
				return nil, errf("integer division or modulo by zero")
			}
			if aint && bint {
				return floorDiv(ai, bi), nil
			}
			return math.Floor(af / bf), nil
		case "%":
			if bf == 0 {
				return nil, errf("integer division or modulo by zero")
			}
			if aint && bint {
				return pyMod(ai, bi), nil
			}
			m := math.Mod(af, bf)
			if m != 0 && (m < 0) != (bf < 0) {
				m += bf
			}
			return m, nil
		case "**":
			if aint && bint && bi >= 0 {
				return intPow(ai, bi)
			}
			return math.Pow(af, bf), nil
		}
	}
	switch op {
	case "+":
		if am, ok := a.(Markup); ok {
			if _, ok2 := isStr(b); ok2 {
				return am + Escape(b), nil
			}
		}
		if bm, ok := b.(Markup); ok {
			if _, ok2 := isStr(a); ok2 {
				return Escape(a) + bm, nil
			}
		}
		if as, ok := a.(string); ok {
			if bs, ok2 := b.(string); ok2 {
				return as + bs, nil
			}
		}
		if x, ok := a.([]any); ok {
			if y, ok2 := b.([]any); ok2 {
				out := append(append([]any{}, x...), y...)
				return out, nil
			}
		}
		if x, ok := a.(Tuple); ok {
			if y, ok2 := b.(Tuple); ok2 {
				return append(append(Tuple{}, x...), y...), nil
			}
		}
	case "*":
		if s, ok := isStr(a); ok && bok && bint {
			return repeatStr(a, s, bi)
		}
		if s, ok := isStr(b); ok && aok && aint {
			return repeatStr(b, s, ai)
		}
		if x, ok := a.([]any); ok && bok && bint {
			return repeatSlice(x, bi)
		}
		if x, ok := b.([]any); ok && aok && aint {
			return repeatSlice(x, ai)
		}
	case "%":
		if s, ok := isStr(a); ok {
			return percentFormat(a, s, b)
		}
	}
	return nil, errf("unsupported operand type(s) for %s: '%s' and '%s'", op, typeName(a), typeName(b))
}

func undefName(a, b any) string {
	for _, v := range []any{a, b} {
		switch u := v.(type) {
		case Undefined:
			return u.Name
		case *Undefined:
			return u.Name
		}
	}
	return ""
}

const (
	maxRepeatBytes = 1 << 20
	maxRepeatItems = 100_000
	maxPowExponent = 1024
)

func mulInt64Overflow(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, false
	}
	res := a * b
	if res/b != a || (a == -1 && b == math.MinInt64) || (b == -1 && a == math.MinInt64) {
		return 0, true
	}
	return res, false
}

func intPow(base, exp int64) (int64, error) {
	if exp < 0 {
		return 0, errf("negative integer exponent")
	}
	if exp == 0 {
		return 1, nil
	}
	if base == 0 {
		return 0, nil
	}
	if base == 1 {
		return 1, nil
	}
	if base == -1 {
		if exp%2 == 0 {
			return 1, nil
		}
		return -1, nil
	}
	if exp > maxPowExponent {
		return 0, errf("exponent %d exceeds maximum allowed (%d)", exp, maxPowExponent)
	}
	res := int64(1)
	b := base
	e := exp
	for e > 0 {
		if e&1 == 1 {
			next, ov := mulInt64Overflow(res, b)
			if ov {
				return 0, errf("integer exponentiation overflow")
			}
			res = next
		}
		e >>= 1
		if e > 0 {
			next, ov := mulInt64Overflow(b, b)
			if ov {
				return 0, errf("integer exponentiation overflow")
			}
			b = next
		}
	}
	return res, nil
}

func repeatStr(orig any, s string, n int64) (any, error) {
	if n <= 0 || len(s) == 0 {
		if _, ok := orig.(Markup); ok {
			return Markup(""), nil
		}
		return "", nil
	}
	if n > int64(maxRepeatBytes)/int64(len(s)) {
		return nil, errf("string repetition exceeds maximum allowed size (%d bytes)", maxRepeatBytes)
	}
	r := strings.Repeat(s, int(n))
	if _, ok := orig.(Markup); ok {
		return Markup(r), nil
	}
	return r, nil
}

func repeatSlice(x []any, n int64) ([]any, error) {
	if n <= 0 || len(x) == 0 {
		return []any{}, nil
	}
	if n > int64(maxRepeatItems)/int64(len(x)) {
		return nil, errf("list repetition exceeds maximum allowed length (%d items)", maxRepeatItems)
	}
	out := make([]any, 0, int(n)*len(x))
	for i := int64(0); i < n; i++ {
		out = append(out, x...)
	}
	return out, nil
}

// percentFormat is str % args for the conversions templates use.
func percentFormat(orig any, format string, args any) (any, error) {
	html := false
	if _, ok := orig.(Markup); ok {
		html = true
	}
	var list []any
	var mapping *Map
	switch x := normalize(args).(type) {
	case Tuple:
		list = []any(x)
	case *Map:
		mapping = x
		list = []any{x}
	default:
		list = []any{x}
	}
	conv := func(v any) any {
		if html {
			return Escape(v)
		}
		return v
	}
	var b strings.Builder
	idx := 0
	next := func() (any, error) {
		if idx >= len(list) {
			return nil, errf("not enough arguments for format string")
		}
		v := list[idx]
		idx++
		return v, nil
	}
	rs := []rune(format)
	for i := 0; i < len(rs); i++ {
		if rs[i] != '%' {
			b.WriteRune(rs[i])
			continue
		}
		i++
		if i >= len(rs) {
			return nil, errf("incomplete format")
		}
		var key string
		hasKey := false
		if rs[i] == '(' {
			end := i
			for end < len(rs) && rs[end] != ')' {
				end++
			}
			key = string(rs[i+1 : end])
			hasKey = true
			i = end + 1
		}
		spec := ""
		for i < len(rs) && strings.ContainsRune("-+ #0123456789.", rs[i]) {
			spec += string(rs[i])
			i++
		}
		if i >= len(rs) {
			return nil, errf("incomplete format")
		}
		verb := rs[i]
		if verb == '%' {
			b.WriteByte('%')
			continue
		}
		var v any
		if hasKey {
			if mapping == nil {
				return nil, errf("format requires a mapping")
			}
			v = mapping.Value(key)
		} else {
			var err error
			if v, err = next(); err != nil {
				return nil, err
			}
		}
		switch verb {
		case 's':
			b.WriteString(fmt.Sprintf("%"+spec+"s", Str(conv(v))))
		case 'r':
			repr := Repr(v)
			if html {
				repr = escapeString(repr)
			}
			b.WriteString(fmt.Sprintf("%"+spec+"s", repr))
		case 'd', 'i':
			n, f, isInt, ok := asNumber(v)
			if !ok {
				return nil, errf("%%d format: a real number is required, not %s", typeName(v))
			}
			if !isInt {
				n = int64(f)
			}
			b.WriteString(fmt.Sprintf("%"+spec+"d", n))
		case 'f', 'F', 'e', 'g':
			_, f, _, ok := asNumber(v)
			if !ok {
				return nil, errf("must be real number, not %s", typeName(v))
			}
			if !strings.Contains(spec, ".") {
				if verb == 'g' {
					spec += ""
				} else {
					spec += ".6"
				}
			}
			b.WriteString(fmt.Sprintf("%"+spec+string(verb), f))
		case 'x', 'X', 'o':
			n, _, _, _ := asNumber(v)
			b.WriteString(fmt.Sprintf("%"+spec+string(verb), n))
		default:
			return nil, errf("unsupported format character '%c'", verb)
		}
	}
	if mapping == nil && idx < len(list) {
		return nil, errf("not all arguments converted during string formatting")
	}
	if html {
		return Markup(b.String()), nil
	}
	return b.String(), nil
}

// checkHashable raises Python's TypeError for a list or dict used as a key.
func checkHashable(v any) error {
	switch x := normalize(v).(type) {
	case []any:
		return errf("unhashable type: 'list'")
	case *Map:
		return errf("unhashable type: 'dict'")
	case Tuple:
		for _, e := range x {
			if err := checkHashable(e); err != nil {
				return err
			}
		}
	}
	return nil
}

package jinja

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// jsonOpts are the json.dumps keywords the filters pass on.
type jsonOpts struct {
	indent      int // < 0: one line
	sortKeys    bool
	ensureASCII bool
}

func (o jsonOpts) with(kwargs *Map) jsonOpts {
	if kwargs == nil {
		return o
	}
	if n, ok := kwargs.Value("indent").(int64); ok {
		o.indent = int(n)
	}
	if v, ok := kwargs.Get("sort_keys"); ok {
		o.sortKeys = Truthy(v)
	}
	if v, ok := kwargs.Get("ensure_ascii"); ok {
		o.ensureASCII = Truthy(v)
	}
	return o
}

// AnsibleToJSON is to_json: json.dumps(value, **kwargs) -- ", " and ": "
// separators, keys in their own order, ensure_ascii unless told otherwise.
func AnsibleToJSON(_ *Environment, v any, _ []any, kwargs *Map) (any, error) {
	return pyDumps(normalize(v), jsonOpts{indent: -1, ensureASCII: true}.with(kwargs), 0)
}

// AnsibleToNiceJSON is to_nice_json: json.dumps(value, indent=4,
// sort_keys=True, separators=(",", ": "), **kwargs).
func AnsibleToNiceJSON(_ *Environment, v any, _ []any, kwargs *Map) (any, error) {
	return pyDumps(normalize(v), jsonOpts{indent: 4, sortKeys: true, ensureASCII: true}.with(kwargs), 0)
}

// AnsibleToNiceYAML is to_nice_yaml: yaml.dump(value, indent=2,
// allow_unicode=True, default_flow_style=False) with PyYAML's sorted keys.
// Only the default indent of 2 is supported.
func AnsibleToNiceYAML(_ *Environment, v any, _ []any, kwargs *Map) (any, error) {
	if kwargs != nil {
		if n, ok := kwargs.Value("indent").(int64); ok && n != 2 {
			return nil, errf("to_nice_yaml: only indent=2 is supported, not %d", n)
		}
	}
	return pyyaml.Dump(normalize(v), pyyaml.Options{AllowUnicode: true, SortKeys: true})
}

// AnsibleTernary is ternary(true_value, false_value[, none_value]).
func AnsibleTernary(_ *Environment, v any, args []any, _ *Map) (any, error) {
	if len(args) < 2 {
		return nil, errf("ternary needs a true and a false value")
	}
	if v == nil && len(args) > 2 {
		return args[2], nil
	}
	if Truthy(v) {
		return args[0], nil
	}
	return args[1], nil
}

// pyDumps is json.dumps: indent < 0 is the one-line form.
func pyDumps(v any, o jsonOpts, depth int) (string, error) {
	pad, end, item, colon := "", "", ", ", ": "
	if o.indent >= 0 {
		pad = "\n" + strings.Repeat(" ", o.indent*(depth+1))
		end = "\n" + strings.Repeat(" ", o.indent*depth)
		item = ","
	}
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		return strconv.FormatBool(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		switch {
		case math.IsInf(x, 1):
			return "Infinity", nil
		case math.IsInf(x, -1):
			return "-Infinity", nil
		case math.IsNaN(x):
			return "NaN", nil
		}
		return pyyaml.FloatRepr(x), nil
	case string:
		return pyJSONString(x, o.ensureASCII), nil
	case Markup:
		return pyJSONString(string(x), o.ensureASCII), nil
	case *Map:
		if x.Len() == 0 {
			return "{}", nil
		}
		var keys []string
		values := map[string]any{}
		var err error
		x.Each(func(k, val any) {
			ks, ok := k.(string)
			if !ok {
				ks = Str(k)
			}
			keys = append(keys, ks)
			values[ks] = val
		})
		if o.sortKeys {
			sort.Strings(keys)
		}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			s, e := pyDumps(normalize(values[k]), o, depth+1)
			if e != nil {
				err = e
			}
			parts = append(parts, pad+pyJSONString(k, o.ensureASCII)+colon+s)
		}
		return "{" + strings.Join(parts, item) + end + "}", err
	case []any, Tuple:
		items, _ := iterate(x)
		if len(items) == 0 {
			return "[]", nil
		}
		parts := make([]string, len(items))
		for i, it := range items {
			s, err := pyDumps(normalize(it), o, depth+1)
			if err != nil {
				return "", err
			}
			parts[i] = pad + s
		}
		return "[" + strings.Join(parts, item) + end + "]", nil
	}
	return "", fmt.Errorf("Object of type %T is not JSON serializable", v)
}

// pyJSONString is a JSON string as json.dumps writes it; without
// ensureASCII only '"', '\\' and control characters are escaped.
func pyJSONString(s string, ensureASCII bool) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || (ensureASCII && r >= 0x7f && r < 0x10000):
			fmt.Fprintf(&b, `\u%04x`, r)
		case ensureASCII && r >= 0x10000:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// AnsibleRegexFindall is regex_findall(regex, multiline=False,
// ignorecase=False): re.findall -- the whole matches without groups, the
// group with one, a tuple of groups with more.
func AnsibleRegexFindall(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
	pattern := Str(argOr(args, kwargs, 0, "regex", ""))
	flags := ""
	if Truthy(argOr(nil, kwargs, 9, "multiline", false)) {
		flags += "m"
	}
	if Truthy(argOr(nil, kwargs, 9, "ignorecase", false)) {
		flags += "i"
	}
	if flags != "" {
		pattern = "(?" + flags + ")" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errf("bad regex %q: %v", pattern, err)
	}
	out := []any{}
	for _, m := range re.FindAllStringSubmatch(Str(v), -1) {
		switch len(m) {
		case 1:
			out = append(out, m[0])
		case 2:
			out = append(out, m[1])
		default:
			groups := make(Tuple, len(m)-1)
			for i, g := range m[1:] {
				groups[i] = g
			}
			out = append(out, groups)
		}
	}
	return out, nil
}

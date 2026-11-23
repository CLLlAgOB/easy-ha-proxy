package app

// Python's json.dumps with the options the Flask code uses.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"easy-ha-proxy/panel/internal/jinja"
	"easy-ha-proxy/panel/internal/pyyaml"
)

// JSONOpts are json.dumps keyword arguments.
type JSONOpts struct {
	EnsureASCII bool
	SortKeys    bool
	Indent      int  // 0: no indentation
	Compact     bool // separators=(",", ":")
	DefaultStr  bool // default=str
}

// PyJSON is json.dumps(v, ...).
func PyJSON(v any, o JSONOpts) (string, error) {
	var b strings.Builder
	if err := pyJSONValue(&b, v, o, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

// MustJSON is PyJSON for values known to serialize.
func MustJSON(v any, o JSONOpts) string {
	s, err := PyJSON(v, o)
	if err != nil {
		panic(err)
	}
	return s
}

func jsonKey(k any) (string, error) {
	switch x := k.(type) {
	case string:
		return x, nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case nil:
		return "null", nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		return pyyaml.FloatRepr(x), nil
	}
	return "", &TypeError{fmt.Sprintf("keys must be str, int, float, bool or None, not %s", pyTypeName(k))}
}

func pyJSONValue(b *strings.Builder, v any, o JSONOpts, level int) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case jinja.Undefined:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(pyyaml.FloatRepr(x))
		}
	case string:
		writeJSONString(b, x, o.EnsureASCII)
	case jinja.Markup:
		writeJSONString(b, string(x), o.EnsureASCII)
	case []any:
		return writeJSONList(b, x, o, level)
	case jinja.Tuple:
		return writeJSONList(b, []any(x), o, level)
	case []string:
		items := make([]any, len(x))
		for i, s := range x {
			items[i] = s
		}
		return writeJSONList(b, items, o, level)
	case *pyyaml.Map:
		return writeJSONMap(b, x, o, level)
	case map[string]any:
		m := pyyaml.NewMap()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.Set(k, x[k])
		}
		return writeJSONMap(b, m, o, level)
	default:
		if o.DefaultStr {
			writeJSONString(b, pyStr(v), o.EnsureASCII)
			return nil
		}
		return &TypeError{fmt.Sprintf("Object of type %s is not JSON serializable", pyTypeName(v))}
	}
	return nil
}

func (o JSONOpts) seps() (string, string) {
	if o.Compact {
		return ",", ":"
	}
	if o.Indent > 0 {
		return ",", ": "
	}
	return ", ", ": "
}

func writeJSONList(b *strings.Builder, items []any, o JSONOpts, level int) error {
	if len(items) == 0 {
		b.WriteString("[]")
		return nil
	}
	itemSep, _ := o.seps()
	b.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			b.WriteString(itemSep)
		}
		if o.Indent > 0 {
			b.WriteString("\n" + strings.Repeat(" ", o.Indent*(level+1)))
		}
		if err := pyJSONValue(b, it, o, level+1); err != nil {
			return err
		}
	}
	if o.Indent > 0 {
		b.WriteString("\n" + strings.Repeat(" ", o.Indent*level))
	}
	b.WriteByte(']')
	return nil
}

func writeJSONMap(b *strings.Builder, m *pyyaml.Map, o JSONOpts, level int) error {
	if m.Len() == 0 {
		b.WriteString("{}")
		return nil
	}
	keys := m.Keys()
	type kv struct {
		key string
		val any
	}
	pairs := make([]kv, 0, len(keys))
	for _, k := range keys {
		ks, err := jsonKey(k)
		if err != nil {
			return err
		}
		pairs = append(pairs, kv{ks, m.Value(k)})
	}
	if o.SortKeys {
		sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
	}
	itemSep, keySep := o.seps()
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteString(itemSep)
		}
		if o.Indent > 0 {
			b.WriteString("\n" + strings.Repeat(" ", o.Indent*(level+1)))
		}
		writeJSONString(b, p.key, o.EnsureASCII)
		b.WriteString(keySep)
		if err := pyJSONValue(b, p.val, o, level+1); err != nil {
			return err
		}
	}
	if o.Indent > 0 {
		b.WriteString("\n" + strings.Repeat(" ", o.Indent*level))
	}
	b.WriteByte('}')
	return nil
}

func writeJSONString(b *strings.Builder, s string, ensureASCII bool) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case r < 0x7f || !ensureASCII:
				if r == utf8.RuneError && size == 1 {
					b.WriteString(`�`)
				} else {
					b.WriteRune(r)
				}
			case r == 0x7f:
				b.WriteRune(r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}

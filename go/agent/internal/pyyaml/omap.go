// Package pyyaml reproduces the parts of PyYAML (yaml.safe_load and
// yaml.safe_dump) and of Python's json module that the ported daemons need
// to read and write the same files, byte for byte, as their Python
// counterparts: mappings keep insertion order, plain scalars resolve with
// the YAML 1.1 rules PyYAML uses, and the emitter follows PyYAML's styles,
// indentation and 80-column folding.
package pyyaml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// Map is a Python dict: keys keep the order they were first set in.
type Map struct {
	keys []any
	vals []any
}

// NewMap returns an empty Map.
func NewMap() *Map { return &Map{} }

// Len is len(d).
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// Keys returns the keys in order.
func (m *Map) Keys() []any {
	if m == nil {
		return nil
	}
	return append([]any(nil), m.keys...)
}

func (m *Map) index(key any) int {
	if m == nil {
		return -1
	}
	for i, k := range m.keys {
		if keyEqual(k, key) {
			return i
		}
	}
	return -1
}

func keyEqual(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case int64:
		switch y := b.(type) {
		case int64:
			return x == y
		case bool:
			return (x == 1 && y) || (x == 0 && !y)
		}
	case bool:
		switch y := b.(type) {
		case bool:
			return x == y
		case int64:
			return keyEqual(y, x)
		}
	case nil:
		return b == nil
	}
	return fmt.Sprint(a) == fmt.Sprint(b) && fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b)
}

// Get is d.get(key).
func (m *Map) Get(key any) (any, bool) {
	if i := m.index(key); i >= 0 {
		return m.vals[i], true
	}
	return nil, false
}

// Value is d.get(key) without the found flag.
func (m *Map) Value(key any) any {
	v, _ := m.Get(key)
	return v
}

// Set is d[key] = value: an existing key keeps its position.
func (m *Map) Set(key, value any) {
	if i := m.index(key); i >= 0 {
		m.vals[i] = value
		return
	}
	m.keys = append(m.keys, key)
	m.vals = append(m.vals, value)
}

// Delete is d.pop(key, None).
func (m *Map) Delete(key any) {
	if i := m.index(key); i >= 0 {
		m.keys = append(m.keys[:i], m.keys[i+1:]...)
		m.vals = append(m.vals[:i], m.vals[i+1:]...)
	}
}

// Each calls f for every pair in order.
func (m *Map) Each(f func(key, value any)) {
	if m == nil {
		return
	}
	for i := range m.keys {
		f(m.keys[i], m.vals[i])
	}
}

// Sorted returns a copy with keys in sorted order (sort_keys=True).
func (m *Map) Sorted() *Map {
	out := &Map{keys: append([]any(nil), m.keys...), vals: append([]any(nil), m.vals...)}
	idx := make([]int, len(out.keys))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keyLess(m.keys[idx[a]], m.keys[idx[b]]) })
	for i, j := range idx {
		out.keys[i], out.vals[i] = m.keys[j], m.vals[j]
	}
	return out
}

func keyLess(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return lessCodepoints(as, bs)
	}
	if an, ok := numberKey(a); ok {
		if bn, ok := numberKey(b); ok {
			return an < bn
		}
	}
	return fmt.Sprint(a) < fmt.Sprint(b)
}

func lessCodepoints(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

// DeepCopy is copy.deepcopy for decoded values.
func DeepCopy(v any) any {
	switch x := v.(type) {
	case *Map:
		out := &Map{keys: append([]any(nil), x.keys...), vals: make([]any, len(x.vals))}
		for i, val := range x.vals {
			out.vals[i] = DeepCopy(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = DeepCopy(val)
		}
		return out
	}
	return v
}

func marshalJSONString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// MarshalJSON writes the pairs in order, keys turned into strings the way
// json.dumps does.
func (m *Map) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(marshalJSONString(jsonKey(m.keys[i])))
		buf.WriteByte(':')
		v, err := marshalValue(m.vals[i])
		if err != nil {
			return nil, err
		}
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func jsonKey(k any) string {
	switch x := k.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	case float64:
		return FloatRepr(x)
	}
	return fmt.Sprint(k)
}

func marshalValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	switch x := v.(type) {
	case *Map:
		return x.MarshalJSON()
	case float64:
		switch {
		case math.IsNaN(x):
			return []byte("NaN"), nil
		case math.IsInf(x, 1):
			return []byte("Infinity"), nil
		case math.IsInf(x, -1):
			return []byte("-Infinity"), nil
		default:
			return []byte(FloatRepr(x)), nil
		}
	case Timestamp:
		return nil, fmt.Errorf("Object of type datetime is not JSON serializable")
	case []any:
		buf.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			b, err := marshalValue(it)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// JSONDumps is json.dumps(value, ensure_ascii=ensureASCII) with Python's
// default separators (", " and ": ") when pretty is false-compact is not
// asked; compact selects separators=(",", ":").
func JSONDumps(value any, ensureASCII, compact bool) (string, error) {
	raw, err := marshalValue(value)
	if err != nil {
		return "", err
	}
	return pythonJSON(raw, ensureASCII, compact), nil
}

func pythonJSON(raw []byte, ensureASCII, compact bool) string {
	var out strings.Builder
	inString, escaped := false, false
	for _, r := range string(raw) {
		if inString {
			switch {
			case escaped:
				escaped = false
				out.WriteRune(r)
			case r == '\\':
				escaped = true
				out.WriteRune(r)
			case r == '"':
				inString = false
				out.WriteRune(r)
			case ensureASCII && r > 0x7e:
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(&out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
				} else {
					fmt.Fprintf(&out, `\u%04x`, r)
				}
			default:
				out.WriteRune(r)
			}
			continue
		}
		out.WriteRune(r)
		switch r {
		case '"':
			inString = true
		case ',', ':':
			if !compact {
				out.WriteByte(' ')
			}
		}
	}
	s := out.String()
	if !ensureASCII {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "\\"+"u2028", string(rune(0x2028))), "\\"+"u2029", string(rune(0x2029)))
	}
	return s
}

// JSONLoads is json.loads keeping object key order (objects become *Map,
// integers int64, other numbers float64).
func JSONLoads(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("Extra data")
	}
	return v, nil
}

func decodeJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := NewMap()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				val, err := decodeJSONValue(dec)
				if err != nil {
					return nil, err
				}
				m.Set(kt.(string), val)
			}
			_, err := dec.Token()
			return m, err
		case '[':
			list := []any{}
			for dec.More() {
				val, err := decodeJSONValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, val)
			}
			_, err := dec.Token()
			return list, err
		}
	case json.Number:
		if n, err := t.Int64(); err == nil && !strings.ContainsAny(t.String(), ".eE") {
			return n, nil
		}
		f, err := t.Float64()
		return f, err
	}
	return tok, nil
}

func numberKey(k any) (float64, bool) {
	switch x := k.(type) {
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	case float64:
		return x, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

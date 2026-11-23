package app

// Python value semantics the ported services lean on: int(), str(), repr(),
// isinstance checks on decoded YAML/JSON values.

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode"

	"easy-ha-proxy/panel/internal/jinja"
	"easy-ha-proxy/panel/internal/pyyaml"
)

// Map is a Python dict.
type Map = pyyaml.Map

func pyRepr(v any) string { return jinja.Repr(v) }

var errNotInt = errors.New("invalid literal for int()")

// pyInt is int(v): bools are 0/1, floats truncate, strings parse in base 10
// with surrounding whitespace, a sign and digit-separating underscores.
func pyInt(v any) (int64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return 0, errNotInt
		}
		return int64(x), nil
	case string:
		return parsePyIntString(x)
	}
	return 0, errNotInt
}

func parsePyIntString(s string) (int64, error) {
	t := strings.TrimFunc(s, unicode.IsSpace)
	if t == "" {
		return 0, errNotInt
	}
	sign := ""
	if t[0] == '+' || t[0] == '-' {
		if t[0] == '-' {
			sign = "-"
		}
		t = t[1:]
	}
	if t == "" || t[0] == '_' || t[len(t)-1] == '_' || strings.Contains(t, "__") {
		return 0, errNotInt
	}
	var b strings.Builder
	for _, r := range t {
		switch {
		case r == '_':
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case unicode.IsDigit(r):
			b.WriteRune('0' + rune(digitValue(r)))
		default:
			return 0, errNotInt
		}
	}
	n, err := strconv.ParseInt(sign+b.String(), 10, 64)
	if err != nil {
		return 0, errNotInt
	}
	return n, nil
}

func digitValue(r rune) int {
	for base := r; base >= r-9; base-- {
		if !unicode.IsDigit(base - 1) {
			return int(r - base)
		}
	}
	return 0
}

func isPyInt(v any) bool {
	switch v.(type) {
	case int64, int:
		return true
	}
	return false
}

func asMap(v any) (*Map, bool) {
	m, ok := v.(*Map)
	return m, ok && m != nil
}

func asList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

// get is d.get(key) on a dict-like value (nil when absent or not a dict).
func get(v any, key string) any {
	if m, ok := asMap(v); ok {
		return m.Value(key)
	}
	return nil
}

func has(v any, key string) bool {
	if m, ok := asMap(v); ok {
		_, found := m.Get(key)
		return found
	}
	return false
}

// strip is str(v).strip().
func strip(v any) string { return strings.TrimFunc(pyStr(v), unicode.IsSpace) }

// orStr is str(v or "").strip().
func orStr(v any) string { return strings.TrimFunc(strOrEmpty(v), unicode.IsSpace) }

func pyIsDigit(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func pyLen(s string) int { return len([]rune(s)) }

func copyMap(m *Map) *Map {
	out := pyyaml.NewMap()
	m.Each(func(k, v any) { out.Set(k, v) })
	return out
}

func jinjaEqual(a, b any) bool { return jinja.Equal(a, b) }

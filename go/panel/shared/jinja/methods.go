package jinja

import (
	"strconv"
	"strings"
	"unicode"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func argOr(args []any, kwargs *Map, i int, name string, def any) any {
	if i < len(args) {
		return args[i]
	}
	if kwargs != nil {
		if v, ok := kwargs.Get(name); ok {
			return v
		}
	}
	return def
}

// method returns a bound Python method of a dict, list or str.
func method(obj any, name string) (any, bool) {
	switch x := obj.(type) {
	case *Map:
		return dictMethod(x, name)
	case []any:
		return listMethod(x, name)
	case string:
		return strMethod(x, false, name)
	case Markup:
		return strMethod(string(x), true, name)
	}
	return nil, false
}

func dictMethod(m *Map, name string) (any, bool) {
	switch name {
	case "get":
		return Func(func(args []any, kwargs *Map) (any, error) {
			if len(args) == 0 {
				return nil, errf("get expected at least 1 argument, got 0")
			}
			if err := checkHashable(args[0]); err != nil {
				return nil, err
			}
			if v, ok := m.Get(normalize(args[0])); ok {
				return v, nil
			}
			return argOr(args, nil, 1, "", nil), nil
		}), true
	case "items":
		return Func(func([]any, *Map) (any, error) {
			out := make([]any, 0, m.Len())
			m.Each(func(k, v any) { out = append(out, Tuple{k, v}) })
			return out, nil
		}), true
	case "keys":
		return Func(func([]any, *Map) (any, error) { return m.Keys(), nil }), true
	case "values":
		return Func(func([]any, *Map) (any, error) {
			out := make([]any, 0, m.Len())
			m.Each(func(_, v any) { out = append(out, v) })
			return out, nil
		}), true
	case "copy":
		return Func(func([]any, *Map) (any, error) {
			c := pyyaml.NewMap()
			m.Each(func(k, v any) { c.Set(k, v) })
			return c, nil
		}), true
	case "update":
		return Func(func(args []any, kwargs *Map) (any, error) {
			if len(args) > 0 {
				if src, ok := normalize(args[0]).(*Map); ok {
					src.Each(func(k, v any) { m.Set(k, v) })
				}
			}
			kwargs.Each(func(k, v any) { m.Set(k, v) })
			return nil, nil
		}), true
	case "setdefault":
		return Func(func(args []any, _ *Map) (any, error) {
			k := normalize(argOr(args, nil, 0, "", nil))
			if v, ok := m.Get(k); ok {
				return v, nil
			}
			d := argOr(args, nil, 1, "", nil)
			m.Set(k, d)
			return d, nil
		}), true
	case "pop":
		return Func(func(args []any, _ *Map) (any, error) {
			k := normalize(argOr(args, nil, 0, "", nil))
			if v, ok := m.Get(k); ok {
				m.Delete(k)
				return v, nil
			}
			if len(args) > 1 {
				return args[1], nil
			}
			return nil, errf("KeyError: %s", Repr(k))
		}), true
	}
	return nil, false
}

func listMethod(l []any, name string) (any, bool) {
	switch name {
	case "append":
		// Lists are values in Go; append works through the shared backing
		// array only when capacity allows, so the engine keeps lists in
		// *[]any form when a template appends. See listRef.
		return nil, false
	case "index":
		return Func(func(args []any, _ *Map) (any, error) {
			for i, v := range l {
				if Equal(v, argOr(args, nil, 0, "", nil)) {
					return int64(i), nil
				}
			}
			return nil, errf("ValueError: not in list")
		}), true
	case "count":
		return Func(func(args []any, _ *Map) (any, error) {
			n := int64(0)
			for _, v := range l {
				if Equal(v, argOr(args, nil, 0, "", nil)) {
					n++
				}
			}
			return n, nil
		}), true
	}
	return nil, false
}

func strResult(html bool, s string) any {
	if html {
		return Markup(s)
	}
	return s
}

func strArg(v any, html bool) string {
	if html {
		return string(Escape(v))
	}
	return Str(v)
}

func strMethod(s string, html bool, name string) (any, bool) {
	switch name {
	case "startswith", "endswith":
		return Func(func(args []any, _ *Map) (any, error) {
			check := strings.HasPrefix
			if name == "endswith" {
				check = strings.HasSuffix
			}
			arg := argOr(args, nil, 0, "", "")
			if t, ok := normalize(arg).(Tuple); ok {
				for _, p := range t {
					if check(s, Str(p)) {
						return true, nil
					}
				}
				return false, nil
			}
			return check(s, Str(arg)), nil
		}), true
	case "lower":
		return Func(func([]any, *Map) (any, error) { return strResult(html, strings.ToLower(s)), nil }), true
	case "upper":
		return Func(func([]any, *Map) (any, error) { return strResult(html, strings.ToUpper(s)), nil }), true
	case "strip", "lstrip", "rstrip":
		return Func(func(args []any, _ *Map) (any, error) {
			chars := argOr(args, nil, 0, "", nil)
			var r string
			if chars == nil {
				switch name {
				case "strip":
					r = strings.TrimFunc(s, unicode.IsSpace)
				case "lstrip":
					r = strings.TrimLeftFunc(s, unicode.IsSpace)
				default:
					r = strings.TrimRightFunc(s, unicode.IsSpace)
				}
			} else {
				c := Str(chars)
				switch name {
				case "strip":
					r = strings.Trim(s, c)
				case "lstrip":
					r = strings.TrimLeft(s, c)
				default:
					r = strings.TrimRight(s, c)
				}
			}
			return strResult(html, r), nil
		}), true
	case "split", "rsplit":
		return Func(func(args []any, kwargs *Map) (any, error) {
			sep := argOr(args, kwargs, 0, "sep", nil)
			maxsplit := int64(-1)
			if v := argOr(args, kwargs, 1, "maxsplit", nil); v != nil {
				maxsplit, _, _, _ = asNumber(v)
			}
			var parts []string
			if sep == nil {
				parts = pySplitWhitespace(s, int(maxsplit), name == "rsplit")
			} else {
				n := int(maxsplit)
				if n >= 0 {
					n++
				}
				if name == "rsplit" && n > 0 {
					all := strings.Split(s, Str(sep))
					if len(all) > n {
						head := strings.Join(all[:len(all)-n+1], Str(sep))
						parts = append([]string{head}, all[len(all)-n+1:]...)
					} else {
						parts = all
					}
				} else {
					parts = strings.SplitN(s, Str(sep), n)
				}
			}
			out := make([]any, len(parts))
			for i, p := range parts {
				out[i] = strResult(html, p)
			}
			return out, nil
		}), true
	case "replace":
		return Func(func(args []any, _ *Map) (any, error) {
			n := -1
			if len(args) > 2 {
				c, _, _, _ := asNumber(args[2])
				n = int(c)
			}
			return strResult(html, strings.Replace(s, strArg(argOr(args, nil, 0, "", ""), html), strArg(argOr(args, nil, 1, "", ""), html), n)), nil
		}), true
	case "join":
		return Func(func(args []any, _ *Map) (any, error) {
			items, err := iterate(argOr(args, nil, 0, "", nil))
			if err != nil {
				return nil, err
			}
			parts := make([]string, len(items))
			for i, it := range items {
				parts[i] = strArg(it, html)
			}
			return strResult(html, strings.Join(parts, s)), nil
		}), true
	case "title":
		return Func(func([]any, *Map) (any, error) { return strResult(html, pyTitle(s)), nil }), true
	case "capitalize":
		return Func(func([]any, *Map) (any, error) { return strResult(html, pyCapitalize(s)), nil }), true
	case "isdigit":
		return Func(func([]any, *Map) (any, error) {
			if s == "" {
				return false, nil
			}
			for _, r := range s {
				if !unicode.IsDigit(r) {
					return false, nil
				}
			}
			return true, nil
		}), true
	case "find":
		return Func(func(args []any, _ *Map) (any, error) {
			i := strings.Index(s, Str(argOr(args, nil, 0, "", "")))
			if i < 0 {
				return int64(-1), nil
			}
			return int64(len([]rune(s[:i]))), nil
		}), true
	case "count":
		return Func(func(args []any, _ *Map) (any, error) {
			return int64(strings.Count(s, Str(argOr(args, nil, 0, "", "")))), nil
		}), true
	case "format":
		return Func(func(args []any, kwargs *Map) (any, error) { return strFormat(s, html, args, kwargs) }), true
	case "splitlines":
		return Func(func([]any, *Map) (any, error) {
			lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
			if len(lines) > 0 && lines[len(lines)-1] == "" {
				lines = lines[:len(lines)-1]
			}
			out := make([]any, len(lines))
			for i, l := range lines {
				out[i] = strResult(html, l)
			}
			return out, nil
		}), true
	}
	return nil, false
}

func pySplitWhitespace(s string, maxsplit int, fromRight bool) []string {
	fields := strings.FieldsFunc(s, unicode.IsSpace)
	if maxsplit < 0 || len(fields) <= maxsplit+1 {
		return fields
	}
	if fromRight {
		// rare; approximate by joining the leading fields
		head := strings.Join(fields[:len(fields)-maxsplit], " ")
		return append([]string{head}, fields[len(fields)-maxsplit:]...)
	}
	out := []string{}
	rest := strings.TrimLeftFunc(s, unicode.IsSpace)
	for i := 0; i < maxsplit; i++ {
		idx := strings.IndexFunc(rest, unicode.IsSpace)
		if idx < 0 {
			break
		}
		out = append(out, rest[:idx])
		rest = strings.TrimLeftFunc(rest[idx:], unicode.IsSpace)
	}
	if rest != "" {
		out = append(out, rest)
	}
	return out
}

func pyTitle(s string) string {
	var b strings.Builder
	prevCased := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if prevCased {
				b.WriteRune(unicode.ToLower(r))
			} else {
				b.WriteRune(unicode.ToTitle(r))
			}
			prevCased = true
		} else {
			b.WriteRune(r)
			prevCased = false
		}
	}
	return b.String()
}

func pyCapitalize(s string) string {
	rs := []rune(s)
	for i := range rs {
		if i == 0 {
			rs[i] = unicode.ToTitle(rs[i])
		} else {
			rs[i] = unicode.ToLower(rs[i])
		}
	}
	return string(rs)
}

// strFormat is str.format for "{}", "{0}" and "{name}" fields.
func strFormat(s string, html bool, args []any, kwargs *Map) (any, error) {
	var b strings.Builder
	auto := 0
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '{' {
			if i+1 < len(rs) && rs[i+1] == '{' {
				b.WriteRune('{')
				i++
				continue
			}
			end := i + 1
			for end < len(rs) && rs[end] != '}' {
				end++
			}
			if end >= len(rs) {
				return nil, errf("Single '{' encountered in format string")
			}
			field := string(rs[i+1 : end])
			spec := ""
			if j := strings.Index(field, ":"); j >= 0 {
				spec = field[j+1:]
				field = field[:j]
			}
			var v any
			switch {
			case field == "":
				if auto >= len(args) {
					return nil, errf("Replacement index %d out of range", auto)
				}
				v = args[auto]
				auto++
			case field[0] >= '0' && field[0] <= '9':
				allDigits := true
				for _, d := range field {
					if d < '0' || d > '9' {
						allDigits = false
						break
					}
				}
				if !allDigits {
					return nil, errf("invalid format field %q", field)
				}
				n, err := strconv.Atoi(field)
				if err != nil || n < 0 || n >= len(args) {
					return nil, errf("Replacement index %s out of range", field)
				}
				v = args[n]
			default:
				var ok bool
				if kwargs != nil {
					v, ok = kwargs.Get(field)
				}
				if !ok {
					return nil, errf("KeyError: %s", Repr(field))
				}
			}
			text := Str(v)
			if spec != "" {
				formatted, err := percentFormat(nil, "%"+translateSpec(spec), Tuple{v})
				if err != nil {
					return nil, err
				}
				text = Str(formatted)
			}
			if html {
				text = string(Escape(text))
				if m, ok := v.(Markup); ok && spec == "" {
					text = string(m)
				}
			}
			b.WriteString(text)
			i = end
			continue
		}
		if c == '}' && i+1 < len(rs) && rs[i+1] == '}' {
			b.WriteRune('}')
			i++
			continue
		}
		b.WriteRune(c)
	}
	return strResult(html, b.String()), nil
}

func translateSpec(spec string) string {
	if spec == "" {
		return "s"
	}
	last := spec[len(spec)-1]
	if strings.ContainsRune("dfFeEgGxXo%s", rune(last)) {
		return spec
	}
	return spec + "s"
}

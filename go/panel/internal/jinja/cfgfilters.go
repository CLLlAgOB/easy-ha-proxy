package jinja

import (
	"regexp"
	"strings"

	"easy-ha-proxy/panel/internal/pyyaml"
)

// RegexReplaceFilter is the haproxy.cfg renderer's regex_replace (re.sub).
func RegexReplaceFilter(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
	if v == nil {
		return "", nil
	}
	pattern := Str(argOr(args, kwargs, 0, "pattern", ""))
	repl := Str(argOr(args, kwargs, 1, "replacement", ""))
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errf("bad regex %q: %v", pattern, err)
	}
	escaped := strings.ReplaceAll(repl, "$", "$$")
	escaped = pyReplacement.ReplaceAllString(escaped, "$${$1$2}")
	return re.ReplaceAllString(Str(v), escaped), nil
}

var pyReplacement = regexp.MustCompile(`\\(?:(\d+)|g<(\w+)>)`)

// CombineFilter is the haproxy.cfg renderer's combine (a minimal Ansible combine).
func CombineFilter(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
	other := argOr(args, nil, 0, "", nil)
	recursive := false
	if r, ok := kw(kwargs, "recursive"); ok {
		recursive = Truthy(r)
	}
	if len(args) > 1 {
		recursive = Truthy(args[1])
	}
	return combine(v, other, recursive)
}

func combine(v, other any, recursive bool) (any, error) {
	base := pyyaml.NewMap()
	if v != nil {
		src, err := pyDict(v)
		if err != nil {
			return nil, err
		}
		src.Each(func(k, val any) { base.Set(k, val) })
	}
	if other == nil {
		return base, nil
	}
	o, err := pyDict(other)
	if err != nil {
		return nil, err
	}
	o.Each(func(k, val any) {
		cur, has := base.Get(k)
		_, curMap := normalize(cur).(*Map)
		_, valMap := normalize(val).(*Map)
		if recursive && has && curMap && valMap {
			merged, e := combine(cur, val, true)
			if e != nil {
				err = e
			}
			base.Set(k, merged)
			return
		}
		base.Set(k, val)
	})
	return base, err
}

// pyDict is dict(v): a mapping, or an iterable of key/value pairs.
func pyDict(v any) (*Map, error) {
	if m, ok := normalize(v).(*Map); ok {
		return m, nil
	}
	items, err := iterate(v)
	if err != nil {
		return nil, err
	}
	out := pyyaml.NewMap()
	for i, it := range items {
		pair, err := iterate(it)
		if err != nil {
			return nil, errf("cannot convert dictionary update sequence element #%d to a sequence", i)
		}
		if len(pair) != 2 {
			return nil, errf("dictionary update sequence element #%d has length %d; 2 is required", i, len(pair))
		}
		if err := checkHashable(pair[0]); err != nil {
			return nil, err
		}
		out.Set(normalize(pair[0]), pair[1])
	}
	return out, nil
}

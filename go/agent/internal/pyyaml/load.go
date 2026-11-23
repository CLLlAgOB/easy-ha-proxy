package pyyaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Timestamp is a plain scalar PyYAML would turn into a date or datetime.
// It is kept as text and written back as it was read.
type Timestamp string

var (
	boolRE      = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	intRE       = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	floatRE     = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	nullRE      = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	timestampRE = regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)
	mergeRE     = regexp.MustCompile(`^(?:<<)$`)
	valueRE     = regexp.MustCompile(`^(?:=)$`)
)

// resolvedTag is what PyYAML's resolver gives a plain scalar.
func resolvedTag(value string) string {
	first := ""
	if value != "" {
		first = value[:1]
	}
	switch {
	case strings.Contains("yYnNtTfFoO", first) && first != "" && boolRE.MatchString(value):
		return "bool"
	case strings.Contains("-+0123456789.", first) && first != "" && floatRE.MatchString(value):
		return "float"
	case strings.Contains("-+0123456789", first) && first != "" && intRE.MatchString(value):
		return "int"
	case first == "<" && mergeRE.MatchString(value):
		return "merge"
	case (first == "" || strings.Contains("~nN", first)) && nullRE.MatchString(value):
		return "null"
	case strings.Contains("0123456789", first) && first != "" && timestampRE.MatchString(value):
		return "timestamp"
	case first == "=" && valueRE.MatchString(value):
		return "value"
	case first != "" && strings.Contains("!&*", first) && len(value) == 1:
		return "yaml"
	}
	return "str"
}

func constructInt(value string) (any, error) {
	v := strings.ReplaceAll(value, "_", "")
	sign := int64(1)
	if strings.HasPrefix(v, "-") {
		sign = -1
	}
	if v != "" && (v[0] == '-' || v[0] == '+') {
		v = v[1:]
	}
	switch {
	case v == "0":
		return int64(0), nil
	case strings.HasPrefix(v, "0b"):
		n, err := strconv.ParseInt(v[2:], 2, 64)
		return sign * n, err
	case strings.HasPrefix(v, "0x"):
		n, err := strconv.ParseInt(v[2:], 16, 64)
		return sign * n, err
	case v[0] == '0':
		n, err := strconv.ParseInt(v, 8, 64)
		return sign * n, err
	case strings.Contains(v, ":"):
		var total int64
		base := int64(1)
		parts := strings.Split(v, ":")
		for i := len(parts) - 1; i >= 0; i-- {
			n, err := strconv.ParseInt(parts[i], 10, 64)
			if err != nil {
				return nil, err
			}
			total += n * base
			base *= 60
		}
		return sign * total, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return sign * n, err
}

func constructFloat(value string) (any, error) {
	v := strings.ToLower(strings.ReplaceAll(value, "_", ""))
	sign := 1.0
	if strings.HasPrefix(v, "-") {
		sign = -1
	}
	if v != "" && (v[0] == '-' || v[0] == '+') {
		v = v[1:]
	}
	switch {
	case v == ".inf":
		return sign * math.Inf(1), nil
	case v == ".nan":
		return math.NaN(), nil
	case strings.Contains(v, ":"):
		total, base := 0.0, 1.0
		parts := strings.Split(v, ":")
		for i := len(parts) - 1; i >= 0; i-- {
			f, err := strconv.ParseFloat(parts[i], 64)
			if err != nil {
				return nil, err
			}
			total += f * base
			base *= 60
		}
		return sign * total, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	return sign * f, err
}

func constructPlain(value string) (any, error) {
	switch resolvedTag(value) {
	case "bool":
		l := strings.ToLower(value)
		return l == "yes" || l == "true" || l == "on", nil
	case "int":
		return constructInt(value)
	case "float":
		return constructFloat(value)
	case "null":
		return nil, nil
	case "timestamp":
		return Timestamp(value), nil
	}
	return value, nil
}

type loader struct {
	cache   map[*yaml.Node]any
	aliased bool
}

// Load is yaml.safe_load: nil for an empty document.
func Load(raw []byte) (any, error) {
	v, _, err := LoadAliases(raw)
	return v, err
}

// LoadAliases also reports whether an alias pointed at a mapping or a
// sequence: Python then holds the same object twice.
func LoadAliases(raw []byte) (any, bool, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, false, fmt.Errorf("expected a single document in the stream")
	} else if !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	l := &loader{cache: map[*yaml.Node]any{}}
	if len(doc.Content) == 0 {
		return nil, false, nil
	}
	v, err := l.node(doc.Content[0])
	return v, l.aliased, err
}

func explicitTag(n *yaml.Node) string {
	if n.Style&yaml.TaggedStyle == 0 {
		return ""
	}
	return strings.TrimPrefix(n.Tag, "!!")
}

func (l *loader) node(n *yaml.Node) (any, error) {
	if v, ok := l.cache[n]; ok {
		return v, nil
	}
	switch n.Kind {
	case yaml.AliasNode:
		v, err := l.node(n.Alias)
		if err != nil {
			return nil, err
		}
		switch v.(type) {
		case *Map, []any:
			l.aliased = true
		}
		return v, nil
	case yaml.ScalarNode:
		tag := explicitTag(n)
		quoted := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
		switch tag {
		case "str":
			return n.Value, nil
		case "int":
			return constructInt(n.Value)
		case "float":
			return constructFloat(n.Value)
		case "bool":
			return constructPlain(n.Value)
		case "null":
			return nil, nil
		case "":
		default:
			return n.Value, nil
		}
		if quoted {
			return n.Value, nil
		}
		return constructPlain(n.Value)
	case yaml.SequenceNode:
		list := []any{}
		l.cache[n] = list
		for _, c := range n.Content {
			v, err := l.node(c)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		l.cache[n] = list
		return list, nil
	case yaml.MappingNode:
		m := NewMap()
		l.cache[n] = m
		pairs, err := l.flatten(n)
		if err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(pairs); i += 2 {
			k, err := l.node(pairs[i])
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case *Map, []any:
				return nil, fmt.Errorf("found unhashable key")
			}
			v, err := l.node(pairs[i+1])
			if err != nil {
				return nil, err
			}
			m.Set(k, v)
		}
		return m, nil
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return l.node(n.Content[0])
	}
	return nil, fmt.Errorf("unsupported YAML node")
}

func isMergeKey(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Style == 0 && n.Value == "<<"
}

func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// flatten is SafeConstructor.flatten_mapping: merged pairs first.
func (l *loader) flatten(n *yaml.Node) ([]*yaml.Node, error) {
	merge := []*yaml.Node{}
	own := []*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if !isMergeKey(key) {
			own = append(own, key, value)
			continue
		}
		target := deref(value)
		switch target.Kind {
		case yaml.MappingNode:
			sub, err := l.flatten(target)
			if err != nil {
				return nil, err
			}
			merge = append(merge, sub...)
		case yaml.SequenceNode:
			subs := [][]*yaml.Node{}
			for _, item := range target.Content {
				item = deref(item)
				if item.Kind != yaml.MappingNode {
					return nil, fmt.Errorf("expected a mapping for merging, but found %s", kindName(item))
				}
				sub, err := l.flatten(item)
				if err != nil {
					return nil, err
				}
				subs = append(subs, sub)
			}
			for i := len(subs) - 1; i >= 0; i-- {
				merge = append(merge, subs[i]...)
			}
		default:
			return nil, fmt.Errorf("expected a mapping or list of mappings for merging, but found %s", kindName(target))
		}
	}
	return append(merge, own...), nil
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		return "scalar"
	case yaml.SequenceNode:
		return "sequence"
	}
	return "mapping"
}

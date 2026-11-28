package vars

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// errNotLiteral means the text is not a literal ast.literal_eval accepts.
var errNotLiteral = errors.New("not a Python literal")

// literalEval is the part of Python's ast.literal_eval that Ansible's
// templating round-trips through: dicts, lists, tuples, strings, numbers,
// True, False and None. Dicts keep their order (*pyyaml.Map), tuples become
// lists. Anything else, sets and bytes included, is errNotLiteral, and the
// caller keeps the text as it was.
func literalEval(s string) (any, error) {
	p := &litParser{src: s}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.src) {
		return nil, errNotLiteral
	}
	return v, nil
}

type litParser struct {
	src string
	pos int
}

func (p *litParser) space() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			p.pos++
		case '\\':
			// A backslash-newline joins lines outside strings too.
			if strings.HasPrefix(p.src[p.pos:], "\\\n") {
				p.pos += 2
				continue
			}
			return
		default:
			return
		}
	}
}

func (p *litParser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *litParser) value() (any, error) {
	p.space()
	switch c := p.peek(); {
	case c == '{':
		return p.dict()
	case c == '[':
		return p.seq('[', ']')
	case c == '(':
		return p.tuple()
	case c == '\'' || c == '"':
		return p.strings()
	case c == '-' || c == '+':
		p.pos++
		p.space()
		n, err := p.number()
		if err != nil {
			return nil, err
		}
		if c == '-' {
			switch x := n.(type) {
			case int64:
				return -x, nil
			case float64:
				return -x, nil
			}
		}
		return n, nil
	case c >= '0' && c <= '9' || c == '.':
		return p.number()
	case isNameStart(c):
		start := p.pos
		for p.pos < len(p.src) && isNameChar(p.src[p.pos]) {
			p.pos++
		}
		word := p.src[start:p.pos]
		if p.peek() == '\'' || p.peek() == '"' {
			// A string prefix: r and u are literals, bytes are not.
			switch strings.ToLower(word) {
			case "r", "u":
				p.pos = start
				return p.strings()
			}
			return nil, errNotLiteral
		}
		switch word {
		case "True":
			return true, nil
		case "False":
			return false, nil
		case "None":
			return nil, nil
		}
		return nil, errNotLiteral
	}
	return nil, errNotLiteral
}

func isNameStart(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isNameChar(c byte) bool  { return isNameStart(c) || c >= '0' && c <= '9' }

func (p *litParser) dict() (any, error) {
	p.pos++ // {
	m := pyyaml.NewMap()
	for {
		p.space()
		if p.peek() == '}' {
			p.pos++
			return m, nil
		}
		k, err := p.value()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.peek() != ':' {
			return nil, errNotLiteral // a set, or garbage
		}
		p.pos++
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		switch k.(type) {
		case *pyyaml.Map, []any:
			return nil, errNotLiteral // unhashable key
		}
		m.Set(k, v)
		p.space()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return m, nil
		default:
			return nil, errNotLiteral
		}
	}
}

func (p *litParser) seq(open, close byte) (any, error) {
	p.pos++ // open
	out := []any{}
	for {
		p.space()
		if p.peek() == close {
			p.pos++
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.space()
		switch p.peek() {
		case ',':
			p.pos++
		case close:
			p.pos++
			return out, nil
		default:
			return nil, errNotLiteral
		}
	}
}

// tuple is "()" , "(x,)" or "(x, y)"; "(x)" is just x.
func (p *litParser) tuple() (any, error) {
	start := p.pos
	p.pos++
	p.space()
	if p.peek() == ')' {
		p.pos++
		return []any{}, nil
	}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.peek() == ')' {
		p.pos++
		return v, nil
	}
	p.pos = start
	return p.seq('(', ')')
}

// strings reads one or more adjacent string literals and joins them.
func (p *litParser) strings() (any, error) {
	var b strings.Builder
	read := false
	for {
		p.space()
		save := p.pos
		raw := false
		if c := p.peek(); c == 'r' || c == 'R' || c == 'u' || c == 'U' {
			raw = c == 'r' || c == 'R'
			p.pos++
		}
		q := p.peek()
		if q != '\'' && q != '"' {
			p.pos = save
			if !read {
				return nil, errNotLiteral
			}
			return b.String(), nil
		}
		s, err := p.stringBody(raw)
		if err != nil {
			return nil, err
		}
		b.WriteString(s)
		read = true
	}
}

func (p *litParser) stringBody(raw bool) (string, error) {
	q := p.src[p.pos]
	triple := strings.HasPrefix(p.src[p.pos:], strings.Repeat(string(q), 3))
	if triple {
		p.pos += 3
	} else {
		p.pos++
	}
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == q && (!triple || strings.HasPrefix(p.src[p.pos:], strings.Repeat(string(q), 3))) {
			if triple {
				p.pos += 3
			} else {
				p.pos++
			}
			return b.String(), nil
		}
		if c == '\n' && !triple {
			return "", errNotLiteral
		}
		if c == '\\' && p.pos+1 < len(p.src) {
			if raw {
				b.WriteString(p.src[p.pos : p.pos+2])
				p.pos += 2
				continue
			}
			if err := p.escape(&b); err != nil {
				return "", err
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(p.src[p.pos:])
		b.WriteRune(r)
		p.pos += size
	}
	return "", errNotLiteral
}

func (p *litParser) escape(b *strings.Builder) error {
	c := p.src[p.pos+1]
	p.pos += 2
	simple := map[byte]string{'\\': "\\", '\'': "'", '"': "\"", 'n': "\n", 'r': "\r", 't': "\t",
		'a': "\a", 'b': "\b", 'f': "\f", 'v': "\v", '\n': ""}
	if s, ok := simple[c]; ok {
		b.WriteString(s)
		return nil
	}
	hex := func(n int) error {
		if p.pos+n > len(p.src) {
			return errNotLiteral
		}
		v, err := strconv.ParseUint(p.src[p.pos:p.pos+n], 16, 32)
		if err != nil || v > utf8.MaxRune {
			return errNotLiteral
		}
		b.WriteRune(rune(v))
		p.pos += n
		return nil
	}
	switch {
	case c == 'x':
		return hex(2)
	case c == 'u':
		return hex(4)
	case c == 'U':
		return hex(8)
	case c >= '0' && c <= '7':
		end := p.pos - 1
		for end < len(p.src) && end < p.pos+2 && p.src[end] >= '0' && p.src[end] <= '7' {
			end++
		}
		v, _ := strconv.ParseUint(p.src[p.pos-1:end], 8, 32)
		b.WriteRune(rune(v))
		p.pos = end
		return nil
	}
	// An unknown escape keeps its backslash, as Python does.
	b.WriteByte('\\')
	b.WriteByte(c)
	return nil
}

func (p *litParser) number() (any, error) {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' {
			p.pos++
			continue
		}
		if (c == '+' || c == '-') && p.pos > start && (p.src[p.pos-1] == 'e' || p.src[p.pos-1] == 'E') &&
			!strings.HasPrefix(strings.ToLower(p.src[start:]), "0x") {
			p.pos++
			continue
		}
		break
	}
	text := p.src[start:p.pos]
	if text == "" || strings.HasSuffix(text, "_") || strings.Contains(text, "__") {
		return nil, errNotLiteral
	}
	clean := strings.ReplaceAll(text, "_", "")
	lower := strings.ToLower(clean)
	base := 10
	digits := lower
	switch {
	case strings.HasPrefix(lower, "0x"):
		base, digits = 16, lower[2:]
	case strings.HasPrefix(lower, "0o"):
		base, digits = 8, lower[2:]
	case strings.HasPrefix(lower, "0b"):
		base, digits = 2, lower[2:]
	}
	if base != 10 || !strings.ContainsAny(lower, ".e") {
		if base == 10 && len(digits) > 1 && digits[0] == '0' && strings.Trim(digits, "0") != "" {
			return nil, errNotLiteral // 012 is a syntax error in Python 3
		}
		n, err := strconv.ParseInt(digits, base, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errNotLiteral, err)
		}
		return n, nil
	}
	if strings.HasSuffix(lower, "j") {
		return nil, errNotLiteral
	}
	f, err := strconv.ParseFloat(lower, 64)
	if err != nil || math.IsInf(f, 0) && !strings.Contains(lower, "e") {
		return nil, errNotLiteral
	}
	return f, nil
}

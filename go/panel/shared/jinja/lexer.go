package jinja

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind int

const (
	tData tokKind = iota
	tVarBegin
	tVarEnd
	tBlockBegin
	tBlockEnd
	tName
	tString
	tInt
	tFloat
	tOp
	tEOF
)

type token struct {
	kind tokKind
	val  string
	num  any
	line int
}

func (t token) is(kind tokKind, val string) bool { return t.kind == kind && t.val == val }

func isSpaceRune(r rune) bool { return unicode.IsSpace(r) }

// normalizeSource applies Jinja's newline handling: every line break becomes
// "\n" and one trailing newline is dropped (keep_trailing_newline=False).
func normalizeSource(src string) string {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	src = strings.ReplaceAll(src, "\r", "\n")
	return strings.TrimSuffix(src, "\n")
}

var operators = []string{"//", "**", "==", "!=", "<=", ">=", "+", "-", "*", "/", "%", "~", "<", ">", "=", "(", ")", "[", "]", "{", "}", ",", ".", ":", "|", ";"}

// lexOpts are the Environment's whitespace options.
type lexOpts struct {
	trimBlocks   bool // drop the first newline after a block or comment tag
	lstripBlocks bool // drop spaces/tabs before a block or comment tag on its own line
}

// skipSpace returns the position after the whitespace run at p, the number
// of newlines in it and whether it ended with a newline.
func skipSpace(src string, p int) (int, int, bool) {
	start := p
	for p < len(src) {
		r, size := utf8.DecodeRuneInString(src[p:])
		if !isSpaceRune(r) {
			break
		}
		p += size
	}
	run := src[start:p]
	return p, strings.Count(run, "\n"), strings.HasSuffix(run, "\n")
}

func lex(name, src string, o lexOpts) ([]token, error) {
	src = normalizeSource(src)
	var toks []token
	line := 1
	pos := 0
	lstripNext := false
	lineStarting := true
	addData := func(s string) {
		if lstripNext {
			s = strings.TrimLeftFunc(s, isSpaceRune)
			lstripNext = false
		}
		if s != "" {
			toks = append(toks, token{kind: tData, val: s, line: line})
		}
		line += strings.Count(s, "\n")
	}
	for pos < len(src) {
		idx := indexTagStart(src, pos)
		if idx < 0 {
			addData(src[pos:])
			break
		}
		data := src[pos:idx]
		kind := src[idx+1]
		inner := idx + 2
		sign := byte(0)
		if inner < len(src) && (src[inner] == '-' || src[inner] == '+') {
			sign = src[inner]
			inner++
		}
		if sign == '-' {
			trimmed := strings.TrimRightFunc(data, isSpaceRune)
			line += strings.Count(data[len(trimmed):], "\n")
			data = trimmed
		} else if sign != '+' && o.lstripBlocks && kind != '{' {
			lpos := strings.LastIndex(data, "\n") + 1
			if (lpos > 0 || lineStarting) && lpos < len(data) && strings.TrimLeft(data[lpos:], " \t\f\v\r") == "" {
				data = data[:lpos]
			}
		}
		addData(data)
		switch kind {
		case '#':
			end := strings.Index(src[inner:], "#}")
			if end < 0 {
				return nil, errf("%s:%d: missing end of comment tag", name, line)
			}
			body := src[inner : inner+end]
			line += strings.Count(body, "\n")
			pos = inner + end + 2
			lineStarting = false
			switch {
			case strings.HasSuffix(body, "-"):
				var n int
				pos, n, lineStarting = skipSpace(src, pos)
				line += n
			case strings.HasSuffix(body, "+"):
			case o.trimBlocks && pos < len(src) && src[pos] == '\n':
				pos++
				line++
				lineStarting = true
			}
			continue
		case '{':
			toks = append(toks, token{kind: tVarBegin, line: line})
		case '%':
			// {% raw %} ... {% endraw %}
			rest := strings.TrimLeftFunc(src[inner:], isSpaceRune)
			if strings.HasPrefix(rest, "raw") {
				after := strings.TrimLeftFunc(rest[3:], isSpaceRune)
				if strings.HasPrefix(after, "%}") || strings.HasPrefix(after, "-%}") {
					closeStrip := strings.HasPrefix(after, "-")
					bodyStart := len(src) - len(after) + 2
					if closeStrip {
						bodyStart++
					}
					endIdx, endTagEnd, endStrip, err := findEndRaw(src, bodyStart)
					if err != nil {
						return nil, errf("%s:%d: %v", name, line, err)
					}
					body := src[bodyStart:endIdx]
					if closeStrip {
						body = strings.TrimLeftFunc(body, isSpaceRune)
					}
					if endStrip {
						body = strings.TrimRightFunc(body, isSpaceRune)
					}
					if body != "" {
						toks = append(toks, token{kind: tData, val: body, line: line})
					}
					line += strings.Count(src[idx:endTagEnd], "\n")
					pos = endTagEnd
					continue
				}
			}
			toks = append(toks, token{kind: tBlockBegin, line: line})
		}
		endDelim := "}}"
		endKind := tVarEnd
		if kind == '%' {
			endDelim = "%}"
			endKind = tBlockEnd
		}
		p := inner
		for {
			for p < len(src) && (src[p] == ' ' || src[p] == '\t' || src[p] == '\n' || src[p] == '\r') {
				if src[p] == '\n' {
					line++
				}
				p++
			}
			if p >= len(src) {
				return nil, errf("%s:%d: unexpected end of template inside tag", name, line)
			}
			if strings.HasPrefix(src[p:], "-"+endDelim) {
				toks = append(toks, token{kind: endKind, line: line})
				var n int
				p, n, lineStarting = skipSpace(src, p+1+len(endDelim))
				line += n
				break
			}
			if strings.HasPrefix(src[p:], "+"+endDelim) {
				p += 1 + len(endDelim)
				toks = append(toks, token{kind: endKind, line: line})
				lineStarting = false
				break
			}
			if strings.HasPrefix(src[p:], endDelim) {
				p += len(endDelim)
				toks = append(toks, token{kind: endKind, line: line})
				lineStarting = false
				if kind == '%' && o.trimBlocks && p < len(src) && src[p] == '\n' {
					p++
					line++
					lineStarting = true
				}
				break
			}
			c := src[p]
			switch {
			case c == '"' || c == '\'':
				val, n, err := lexString(src[p:])
				if err != nil {
					return nil, errf("%s:%d: %v", name, line, err)
				}
				line += strings.Count(src[p:p+n], "\n")
				toks = append(toks, token{kind: tString, val: val, line: line})
				p += n
			case c >= '0' && c <= '9':
				n, tok := lexNumber(src[p:])
				tok.line = line
				toks = append(toks, tok)
				p += n
			case c == '_' || isLetter(rune(c)) || c >= 0x80:
				start := p
				for p < len(src) {
					r := rune(src[p])
					if r == '_' || isLetter(r) || (r >= '0' && r <= '9') || src[p] >= 0x80 {
						p++
						continue
					}
					break
				}
				toks = append(toks, token{kind: tName, val: src[start:p], line: line})
			default:
				matched := ""
				for _, op := range operators {
					if strings.HasPrefix(src[p:], op) {
						matched = op
						break
					}
				}
				if matched == "" {
					return nil, errf("%s:%d: unexpected char %q", name, line, c)
				}
				toks = append(toks, token{kind: tOp, val: matched, line: line})
				p += len(matched)
			}
		}
		pos = p
	}
	toks = append(toks, token{kind: tEOF, line: line})
	return toks, nil
}

func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func indexTagStart(src string, pos int) int {
	for i := pos; i+1 < len(src); i++ {
		if src[i] == '{' && (src[i+1] == '{' || src[i+1] == '%' || src[i+1] == '#') {
			return i
		}
	}
	return -1
}

func findEndRaw(src string, from int) (int, int, bool, error) {
	p := from
	for {
		i := strings.Index(src[p:], "{%")
		if i < 0 {
			return 0, 0, false, errf("missing endraw")
		}
		start := p + i
		q := start + 2
		strip := false
		if q < len(src) && (src[q] == '-' || src[q] == '+') {
			strip = src[q] == '-'
			q++
		}
		rest := strings.TrimLeftFunc(src[q:], isSpaceRune)
		if strings.HasPrefix(rest, "endraw") {
			after := strings.TrimLeftFunc(rest[6:], isSpaceRune)
			if strings.HasPrefix(after, "-%}") {
				return start, len(src) - len(after) + 3, strip, nil
			}
			if strings.HasPrefix(after, "%}") {
				return start, len(src) - len(after) + 2, strip, nil
			}
		}
		p = start + 2
	}
}

func lexString(s string) (string, int, error) {
	quote := s[0]
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == quote {
			return b.String(), i + 1, nil
		}
		if c == '\\' && i+1 < len(s) {
			n := s[i+1]
			switch n {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case '\'':
				b.WriteByte('\'')
			case '"':
				b.WriteByte('"')
			case '0':
				b.WriteByte(0)
			case 'u', 'x', 'U':
				width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[n]
				if i+2+width <= len(s) {
					if v, err := strconv.ParseUint(s[i+2:i+2+width], 16, 32); err == nil {
						b.WriteRune(rune(v))
						i += 2 + width
						continue
					}
				}
				b.WriteByte('\\')
				b.WriteByte(n)
			case '\n':
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return "", 0, errf("unterminated string")
}

func lexNumber(s string) (int, token) {
	i := 0
	isFloat := false
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '_') {
		i++
	}
	if i+1 < len(s) && s[i] == '.' && s[i+1] >= '0' && s[i+1] <= '9' {
		isFloat = true
		i++
		for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '_') {
			i++
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			isFloat = true
			i = j
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		}
	}
	text := strings.ReplaceAll(s[:i], "_", "")
	if isFloat {
		f, _ := strconv.ParseFloat(text, 64)
		return i, token{kind: tFloat, val: s[:i], num: f}
	}
	n, _ := strconv.ParseInt(text, 10, 64)
	return i, token{kind: tInt, val: s[:i], num: n}
}

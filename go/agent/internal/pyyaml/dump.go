package pyyaml

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Options are the yaml.safe_dump arguments the daemons pass.
type Options struct {
	AllowUnicode bool
	SortKeys     bool
}

const bestWidth = 80

type emitter struct {
	out          strings.Builder
	opts         Options
	column       int
	whitespace   bool
	indention    bool
	openEnded    bool
	indent       int
	indents      []int
	flowLevel    int
	rootContext  bool
	mappingCtx   bool
	simpleKeyCtx bool
}

const noIndent = -1

// Dump is yaml.safe_dump(value, default_flow_style=False, ...).
func Dump(value any, opts Options) (string, error) {
	e := &emitter{opts: opts, whitespace: true, indention: true, indent: noIndent}
	e.rootContext = true
	if err := e.node(value, false, false); err != nil {
		return "", err
	}
	e.writeIndent()
	if e.openEnded {
		e.writeIndicator("...", true, false, false)
		e.writeIndent()
	}
	return e.out.String(), nil
}

func (e *emitter) write(s string) {
	e.column += utf8.RuneCountInString(s)
	e.out.WriteString(s)
}

func (e *emitter) increaseIndent(flow, indentless bool) {
	e.indents = append(e.indents, e.indent)
	if e.indent == noIndent {
		if flow {
			e.indent = 2
		} else {
			e.indent = 0
		}
	} else if !indentless {
		e.indent += 2
	}
}

func (e *emitter) popIndent() {
	e.indent = e.indents[len(e.indents)-1]
	e.indents = e.indents[:len(e.indents)-1]
}

func (e *emitter) writeIndicator(indicator string, needWhitespace, whitespace, indention bool) {
	data := indicator
	if !e.whitespace && needWhitespace {
		data = " " + indicator
	}
	e.whitespace = whitespace
	e.indention = e.indention && indention
	e.openEnded = false
	e.write(data)
}

func (e *emitter) writeIndent() {
	indent := e.indent
	if indent == noIndent {
		indent = 0
	}
	if !e.indention || e.column > indent || (e.column == indent && !e.whitespace) {
		e.writeLineBreak("")
	}
	if e.column < indent {
		e.whitespace = true
		e.write(strings.Repeat(" ", indent-e.column))
	}
}

func (e *emitter) writeLineBreak(data string) {
	if data == "" {
		data = "\n"
	}
	e.whitespace = true
	e.indention = true
	e.out.WriteString(data)
	e.column = 0
}

// node is expect_node for one value.
func (e *emitter) node(v any, mapping, simpleKey bool) error {
	root := e.rootContext
	e.rootContext = false
	e.mappingCtx = mapping
	e.simpleKeyCtx = simpleKey
	switch x := v.(type) {
	case *Map:
		if e.flowLevel > 0 || x.Len() == 0 {
			return e.flowCollection("{", "}", x.Len())
		}
		return e.blockMapping(x)
	case []any:
		if e.flowLevel > 0 || len(x) == 0 {
			return e.flowCollection("[", "]", len(x))
		}
		return e.blockSequence(x)
	}
	text, implicit, err := represent(v)
	if err != nil {
		return err
	}
	e.increaseIndent(true, false)
	e.scalar(text, implicit, root)
	e.popIndent()
	return nil
}

func (e *emitter) flowCollection(open, close string, n int) error {
	if n != 0 {
		return fmt.Errorf("flow collections are not supported")
	}
	e.writeIndicator(open, true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.popIndent()
	e.flowLevel--
	e.writeIndicator(close, false, false, false)
	return nil
}

func (e *emitter) blockSequence(items []any) error {
	indentless := e.mappingCtx && !e.indention
	e.increaseIndent(false, indentless)
	for _, it := range items {
		e.writeIndent()
		e.writeIndicator("-", true, false, true)
		if err := e.node(it, false, false); err != nil {
			return err
		}
	}
	e.popIndent()
	return nil
}

func (e *emitter) blockMapping(m *Map) error {
	if e.opts.SortKeys {
		if sortable(m.keys) {
			m = m.Sorted()
		}
	}
	e.increaseIndent(false, false)
	for i := range m.keys {
		k, v := m.keys[i], m.vals[i]
		e.writeIndent()
		if e.simpleKey(k) {
			if err := e.node(k, true, true); err != nil {
				return err
			}
			e.writeIndicator(":", false, false, false)
			if err := e.node(v, true, false); err != nil {
				return err
			}
			continue
		}
		e.writeIndicator("?", true, false, true)
		if err := e.node(k, true, false); err != nil {
			return err
		}
		e.writeIndent()
		e.writeIndicator(":", true, false, true)
		if err := e.node(v, true, false); err != nil {
			return err
		}
	}
	e.popIndent()
	return nil
}

func (e *emitter) simpleKey(k any) bool {
	switch x := k.(type) {
	case *Map:
		return x.Len() == 0
	case []any:
		return len(x) == 0
	}
	text, _, err := represent(k)
	if err != nil {
		return false
	}
	a := e.analyze(text)
	return utf8.RuneCountInString(text) < 128 && !a.empty && !a.multiline
}

// represent is SafeRepresenter: the scalar text and whether the plain
// form resolves back to the same type (implicit[0]).
func represent(v any) (string, bool, error) {
	switch x := v.(type) {
	case nil:
		return "null", true, nil
	case bool:
		if x {
			return "true", true, nil
		}
		return "false", true, nil
	case int:
		return strconv.Itoa(x), true, nil
	case int64:
		return strconv.FormatInt(x, 10), true, nil
	case float64:
		return yamlFloat(x), true, nil
	case string:
		return x, resolvedTag(x) == "str", nil
	case Timestamp:
		return string(x), true, nil
	}
	return "", false, fmt.Errorf("cannot represent an object: %v", v)
}

func yamlFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return ".nan"
	case math.IsInf(f, 1):
		return ".inf"
	case math.IsInf(f, -1):
		return "-.inf"
	}
	value := strings.ToLower(FloatRepr(f))
	if !strings.Contains(value, ".") && strings.Contains(value, "e") {
		value = strings.Replace(value, "e", ".0e", 1)
	}
	return value
}

// FloatRepr is repr(float).
func FloatRepr(f float64) string {
	if math.IsInf(f, 1) {
		return "inf"
	}
	if math.IsInf(f, -1) {
		return "-inf"
	}
	if math.IsNaN(f) {
		return "nan"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expText, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expText)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	sign := ""
	if neg {
		sign = "-"
	}
	if exp < -4 || exp >= 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := "+"
		if exp < 0 {
			es = "-"
			exp = -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, m, es, exp)
	}
	if exp < 0 {
		return sign + "0." + strings.Repeat("0", -exp-1) + digits
	}
	if len(digits) <= exp+1 {
		return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
	}
	return sign + digits[:exp+1] + "." + digits[exp+1:]
}

type analysis struct {
	empty, multiline                             bool
	allowFlowPlain, allowBlockPlain, allowSingle bool
	allowDouble, allowBlock                      bool
}

func isSpaceLike(r rune) bool {
	return r == 0 || r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == 0x85 || r == 0x2028 || r == 0x2029
}

func isBreak(r rune) bool { return r == '\n' || r == 0x85 || r == 0x2028 || r == 0x2029 }

func (e *emitter) analyze(scalar string) analysis {
	if scalar == "" {
		return analysis{empty: true, allowBlockPlain: true, allowSingle: true, allowDouble: true}
	}
	rs := []rune(scalar)
	blockInd, flowInd, lineBreaks, special := false, false, false, false
	leadingSpace, leadingBreak, trailingSpace, trailingBreak, breakSpace := false, false, false, false, false
	if strings.HasPrefix(scalar, "---") || strings.HasPrefix(scalar, "...") {
		blockInd, flowInd = true, true
	}
	preceded := true
	followed := len(rs) == 1 || isSpaceLike(rs[1])
	prevSpace, prevBreak := false, false
	for i, ch := range rs {
		if i == 0 {
			if strings.ContainsRune("#,[]{}&*!|>'\"%@`", ch) {
				flowInd, blockInd = true, true
			}
			if ch == '?' || ch == ':' {
				flowInd = true
				if followed {
					blockInd = true
				}
			}
			if ch == '-' && followed {
				flowInd, blockInd = true, true
			}
		} else {
			if strings.ContainsRune(",?[]{}", ch) {
				flowInd = true
			}
			if ch == ':' {
				flowInd = true
				if followed {
					blockInd = true
				}
			}
			if ch == '#' && preceded {
				flowInd, blockInd = true, true
			}
		}
		if isBreak(ch) {
			lineBreaks = true
		}
		if !(ch == '\n' || (ch >= 0x20 && ch <= 0x7e)) {
			if (ch == 0x85 || (ch >= 0xa0 && ch <= 0xd7ff) || (ch >= 0xe000 && ch <= 0xfffd) || (ch >= 0x10000 && ch < 0x10ffff)) && ch != 0xfeff {
				if !e.opts.AllowUnicode {
					special = true
				}
			} else {
				special = true
			}
		}
		switch {
		case ch == ' ':
			if i == 0 {
				leadingSpace = true
			}
			if i == len(rs)-1 {
				trailingSpace = true
			}
			if prevBreak {
				breakSpace = true
			}
			prevSpace, prevBreak = true, false
		case isBreak(ch):
			if i == 0 {
				leadingBreak = true
			}
			if i == len(rs)-1 {
				trailingBreak = true
			}
			prevSpace, prevBreak = false, true
		default:
			prevSpace, prevBreak = false, false
		}
		_ = prevSpace
		preceded = isSpaceLike(ch)
		followed = i+2 >= len(rs) || isSpaceLike(rs[i+2])
	}
	a := analysis{multiline: lineBreaks, allowFlowPlain: true, allowBlockPlain: true, allowSingle: true, allowDouble: true, allowBlock: true}
	if leadingSpace || leadingBreak || trailingSpace || trailingBreak {
		a.allowFlowPlain, a.allowBlockPlain = false, false
	}
	if trailingSpace {
		a.allowBlock = false
	}
	if breakSpace {
		a.allowFlowPlain, a.allowBlockPlain, a.allowSingle = false, false, false
	}
	if special {
		a.allowFlowPlain, a.allowBlockPlain, a.allowSingle, a.allowBlock = false, false, false, false
	}
	if lineBreaks {
		a.allowFlowPlain, a.allowBlockPlain = false, false
	}
	if flowInd {
		a.allowFlowPlain = false
	}
	if blockInd {
		a.allowBlockPlain = false
	}
	return a
}

func (e *emitter) scalar(text string, implicit, root bool) {
	a := e.analyze(text)
	split := !e.simpleKeyCtx
	if implicit && !(e.simpleKeyCtx && (a.empty || a.multiline)) &&
		((e.flowLevel > 0 && a.allowFlowPlain) || (e.flowLevel == 0 && a.allowBlockPlain)) {
		e.writePlain(text, split, root)
		return
	}
	if a.allowSingle && !(e.simpleKeyCtx && a.multiline) {
		e.writeSingleQuoted(text, split)
		return
	}
	e.writeDoubleQuoted(text, split)
}

func (e *emitter) writePlain(text string, split, root bool) {
	if root {
		e.openEnded = true
	}
	if text == "" {
		return
	}
	if !e.whitespace {
		e.write(" ")
	}
	e.whitespace, e.indention = false, false
	rs := []rune(text)
	spaces, breaks := false, false
	start := 0
	for end := 0; end <= len(rs); end++ {
		var ch rune = -1
		if end < len(rs) {
			ch = rs[end]
		}
		switch {
		case spaces:
			if ch != ' ' {
				if start+1 == end && e.column > bestWidth && split {
					e.writeIndent()
					e.whitespace, e.indention = false, false
				} else {
					e.write(string(rs[start:end]))
				}
				start = end
			}
		case breaks:
			if ch == -1 || !isBreak(ch) {
				if rs[start] == '\n' {
					e.writeLineBreak("")
				}
				for _, br := range rs[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				e.writeIndent()
				e.whitespace, e.indention = false, false
				start = end
			}
		default:
			if ch == -1 || ch == ' ' || isBreak(ch) {
				e.write(string(rs[start:end]))
				start = end
			}
		}
		if ch != -1 {
			spaces, breaks = ch == ' ', isBreak(ch)
		}
	}
}

func (e *emitter) writeSingleQuoted(text string, split bool) {
	e.writeIndicator("'", true, false, false)
	rs := []rune(text)
	spaces, breaks := false, false
	start := 0
	for end := 0; end <= len(rs); end++ {
		var ch rune = -1
		if end < len(rs) {
			ch = rs[end]
		}
		switch {
		case spaces:
			if ch == -1 || ch != ' ' {
				if start+1 == end && e.column > bestWidth && split && start != 0 && end != len(rs) {
					e.writeIndent()
				} else {
					e.write(string(rs[start:end]))
				}
				start = end
			}
		case breaks:
			if ch == -1 || !isBreak(ch) {
				if rs[start] == '\n' {
					e.writeLineBreak("")
				}
				for _, br := range rs[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				e.writeIndent()
				start = end
			}
		default:
			if ch == -1 || ch == ' ' || isBreak(ch) || ch == '\'' {
				if start < end {
					e.write(string(rs[start:end]))
					start = end
				}
			}
		}
		if ch == '\'' {
			e.write("''")
			start = end + 1
		}
		if ch != -1 {
			spaces, breaks = ch == ' ', isBreak(ch)
		}
	}
	e.writeIndicator("'", false, false, false)
}

var escapeReplacements = map[rune]string{0: "0", 7: "a", 8: "b", 9: "t", 10: "n", 11: "v", 12: "f", 13: "r", 27: "e",
	'"': "\"", '\\': "\\", 0x85: "N", 0xa0: "_", 0x2028: "L", 0x2029: "P"}

func (e *emitter) writeDoubleQuoted(text string, split bool) {
	e.writeIndicator("\"", true, false, false)
	rs := []rune(text)
	start := 0
	for end := 0; end <= len(rs); end++ {
		var ch rune = -1
		if end < len(rs) {
			ch = rs[end]
		}
		if ch == -1 || needsEscape(ch) ||
			!((ch >= 0x20 && ch <= 0x7e) || (e.opts.AllowUnicode && ((ch >= 0xa0 && ch <= 0xd7ff) || (ch >= 0xe000 && ch <= 0xfffd)))) {
			if start < end {
				e.write(string(rs[start:end]))
				start = end
			}
			if ch != -1 {
				var data string
				if r, ok := escapeReplacements[ch]; ok {
					data = "\\" + r
				} else if ch <= 0xff {
					data = fmt.Sprintf("\\x%02X", ch)
				} else if ch <= 0xffff {
					data = fmt.Sprintf("\\u%04X", ch)
				} else {
					data = fmt.Sprintf("\\U%08X", ch)
				}
				e.write(data)
				start = end + 1
			}
		}
		if end > 0 && end < len(rs)-1 && (ch == ' ' || start >= end) && e.column+(end-start) > bestWidth && split {
			data := ""
			if start < end {
				data = string(rs[start:end])
			}
			data += string(rune(92))
			if start < end {
				start = end
			}
			e.write(data)
			e.writeIndent()
			e.whitespace, e.indention = false, false
			if rs[start] == ' ' {
				e.write("\\")
			}
		}
	}
	e.writeIndicator("\"", false, false, false)
}

func needsEscape(ch rune) bool {
	return ch == 34 || ch == 92 || ch == 0x85 || ch == 0x2028 || ch == 0x2029 || ch == 0xfeff
}

// sortable reports whether Python could sort the keys: numbers with
// numbers, strings with strings; anything else raises TypeError and
// PyYAML keeps the mapping's own order.
func sortable(keys []any) bool {
	numbers, stringsOnly := true, true
	for _, k := range keys {
		switch k.(type) {
		case int64, int, bool, float64:
			stringsOnly = false
		case string:
			numbers = false
		default:
			return len(keys) <= 1
		}
	}
	return numbers || stringsOnly
}

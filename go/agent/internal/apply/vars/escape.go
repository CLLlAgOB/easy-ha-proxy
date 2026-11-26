package vars

import "strings"

// escapeBackslashes is Ansible's _escape_backslashes (ansible.template),
// applied to every string Ansible templates except template files: inside
// {{ }} each string literal's backslashes are doubled before Jinja reads
// it, so '\n' there is a backslash and an n, not a newline. Statements
// ({% %}), comments, raw blocks and text outside the tags are left alone.
func escapeBackslashes(src string) string {
	if !strings.Contains(src, `\`) || !strings.Contains(src, "{{") {
		return src
	}
	var out strings.Builder
	i := 0
	for i < len(src) {
		start := strings.Index(src[i:], "{")
		if start < 0 || i+start+1 >= len(src) {
			out.WriteString(src[i:])
			break
		}
		start += i
		next := src[start+1]
		switch next {
		case '{', '%', '#':
		default:
			out.WriteString(src[i : start+1])
			i = start + 1
			continue
		}
		out.WriteString(src[i:start])
		switch next {
		case '#':
			end := strings.Index(src[start+2:], "#}")
			if end < 0 {
				out.WriteString(src[start:])
				return out.String()
			}
			end += start + 2 + 2
			out.WriteString(src[start:end])
			i = end
		case '%':
			end, raw := scanTag(src, start+2, "%}", false, &out, src[start:start+2])
			i = end
			if raw {
				// {% raw %} ... {% endraw %}: copied as it is.
				stop := rawEnd(src, i)
				out.WriteString(src[i:stop])
				i = stop
			}
		case '{':
			i, _ = scanTag(src, start+2, "}}", true, &out, "{{")
		}
	}
	return out.String()
}

// scanTag copies a tag from its opening (already chosen) to its close,
// doubling string literals' backslashes when double is set; raw reports a
// {% raw %} tag.
func scanTag(src string, p int, close string, double bool, out *strings.Builder, open string) (int, bool) {
	out.WriteString(open)
	body := strings.Builder{}
	for p < len(src) {
		if strings.HasPrefix(src[p:], close) {
			out.WriteString(close)
			word := strings.Trim(strings.TrimSpace(body.String()), "-+")
			return p + len(close), strings.TrimSpace(word) == "raw"
		}
		c := src[p]
		if c == '\'' || c == '"' {
			q := p + 1
			for q < len(src) && src[q] != c {
				if src[q] == '\\' && q+1 < len(src) {
					q++
				}
				q++
			}
			if q >= len(src) {
				out.WriteString(src[p:])
				return len(src), false
			}
			lit := src[p : q+1]
			if double {
				lit = strings.ReplaceAll(lit, `\`, `\\`)
			}
			out.WriteString(lit)
			body.WriteString(lit)
			p = q + 1
			continue
		}
		out.WriteByte(c)
		body.WriteByte(c)
		p++
	}
	return p, false
}

// rawEnd is where the text of a raw block ends: at its {% endraw %} tag.
func rawEnd(src string, from int) int {
	p := from
	for {
		idx := strings.Index(src[p:], "{%")
		if idx < 0 {
			return len(src)
		}
		idx += p
		end := strings.Index(src[idx:], "%}")
		if end < 0 {
			return len(src)
		}
		word := strings.Trim(strings.TrimSpace(src[idx+2:idx+end]), "-+")
		if strings.TrimSpace(word) == "endraw" {
			return idx
		}
		p = idx + 2
	}
}

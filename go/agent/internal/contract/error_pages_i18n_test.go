package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"easy-ha-proxy/panel/shared/jinja"
)

// The HAProxy static error/access pages follow the admin UI language. They
// are raw HTTP errorfiles, so the Jinja setup must never disturb the
// status-line / headers / blank-line / body structure.

const errorPagesDir = "ansible/roles/haproxy/templates"

// errorPages mirrors the Python PAGES mapping: name, status line, English
// marker, Russian marker.
var errorPages = []struct{ name, status, en, ru string }{
	{"access_granted.http.j2", "HTTP/1.0 200 OK", "Access granted", "Доступ разрешён"},
	{"maintenance.http.j2", "HTTP/1.0 503 Service Temporarily Unavailable", "Service Temporarily Unavailable", "Сервис временно недоступен"},
}

// errorPagesRender mirrors Ansible's template defaults: trim_blocks on,
// lstrip_blocks off, autoescape off, rendering the source from a string.
func errorPagesRender(t *testing.T, name, language string) string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), filepath.FromSlash(errorPagesDir))
	env := jinja.NewEnvironment(func(n string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		return string(raw), err
	})
	env.Autoescape = false
	env.TrimBlocks = true
	env.LstripBlocks = false
	tmpl, err := env.FromString(name, read(t, errorPagesDir+"/"+name))
	if err != nil {
		t.Fatal(err)
	}
	out, err := env.RenderTemplate(tmpl, map[string]any{
		"haproxy_admin_default_language": language,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// errorPagesSplitLines is Python's str.splitlines().
func errorPagesSplitLines(s string) []string {
	if s == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '\r' {
			end := i
			i += size
			if i < len(s) && s[i] == '\n' {
				i++
			}
			lines = append(lines, s[start:end])
			start = i
			continue
		}
		if errorPagesIsLineBreak(r) {
			lines = append(lines, s[start:i])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func errorPagesIsLineBreak(r rune) bool {
	switch r {
	case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// errorPagesPartition is str.partition(sep).
func errorPagesPartition(s, sep string) (head, found, body string) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, "", ""
	}
	return s[:i], sep, s[i+len(sep):]
}

func TestHTTPStructureIsPreservedForEveryLanguage(t *testing.T) {
	// Whatever the language, the errorfile keeps its status line, a short
	// header block, the blank separator and an HTML body.
	for _, p := range errorPages {
		for _, language := range []string{"ru", "en", "de", ""} {
			t.Run(p.name+"/"+language, func(t *testing.T) {
				out := errorPagesRender(t, p.name, language)
				lines := errorPagesSplitLines(out)
				if len(lines) == 0 || lines[0] != p.status {
					t.Errorf("%s (%q): first line %q, want %q", p.name, language, errorPagesFirstLine(lines), p.status)
				}
				head, sep, body := errorPagesPartition(out, "\n\n")
				if sep == "" {
					t.Errorf("%s (%q): missing header/body separator", p.name, language)
				}
				if n := len(errorPagesSplitLines(head)); n > 5 {
					t.Errorf("%s (%q): header block has %d lines, want <= 5", p.name, language, n)
				}
				if !strings.HasPrefix(strings.TrimLeftFunc(body, unicode.IsSpace), "<") {
					t.Errorf("%s (%q): body does not start with '<'", p.name, language)
				}
			})
		}
	}
}

func errorPagesFirstLine(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func TestLanguageSelectionAndFallback(t *testing.T) {
	// Russian and English render their own text; unknown and empty languages
	// fall back to English.
	for _, p := range errorPages {
		t.Run(p.name, func(t *testing.T) {
			mustContain(t, errorPagesRender(t, p.name, "ru"), p.ru, p.name+" (ru)")
			mustContain(t, errorPagesRender(t, p.name, "en"), p.en, p.name+" (en)")
			mustContain(t, errorPagesRender(t, p.name, "de"), p.en, p.name+" (de fallback)")
			mustContain(t, errorPagesRender(t, p.name, ""), p.en, p.name+" (empty fallback)")
			mustContain(t, errorPagesRender(t, p.name, "xx"), `lang="en"`, p.name+" (xx fallback)")
		})
	}
}

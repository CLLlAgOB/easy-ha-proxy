package contract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Helpers for the translation-catalog contracts: the catalogs load with
// duplicate keys refused (the Python suite's object_pairs_hook raised on
// one), keep their file order, and translate the way the panel's i18n.js
// does.

// jsonObject is a JSON object that keeps its keys in file order.
type jsonObject struct {
	keys []string
	vals map[string]any
}

func (o *jsonObject) get(key string) any { return o.vals[key] }

// parseJSONUnique decodes one JSON value, refusing a duplicate key in any
// object.
func parseJSONUnique(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := &jsonObject{vals: map[string]any{}}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key := keyTok.(string)
			if _, dup := obj.vals[key]; dup {
				return nil, fmt.Errorf("duplicate key: %s", key)
			}
			val, err := parseJSONUnique(dec)
			if err != nil {
				return nil, err
			}
			obj.keys = append(obj.keys, key)
			obj.vals[key] = val
		}
		if _, err := dec.Token(); err != nil { // the closing brace
			return nil, err
		}
		return obj, nil
	case '[':
		var arr []any
		for dec.More() {
			val, err := parseJSONUnique(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil { // the closing bracket
			return nil, err
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected delimiter %v", delim)
}

// catalog is one translation file: its meta and its messages in file order.
type catalog struct {
	code     string
	label    string
	messages map[string]string
	order    []string
}

func loadCatalog(t *testing.T, rel string) catalog {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(read(t, rel)))
	v, err := parseJSONUnique(dec)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	root, ok := v.(*jsonObject)
	if !ok {
		t.Fatalf("%s: not a JSON object", rel)
	}
	c := catalog{messages: map[string]string{}}
	if meta, ok := root.get("meta").(*jsonObject); ok {
		c.code, _ = meta.get("code").(string)
		c.label, _ = meta.get("label").(string)
	}
	if msgs, ok := root.get("messages").(*jsonObject); ok {
		for _, key := range msgs.keys {
			s, ok := msgs.get(key).(string)
			if !ok {
				t.Fatalf("%s: message %q is not a string", rel, key)
			}
			c.messages[key] = s
			c.order = append(c.order, key)
		}
	}
	return c
}

// cyrillicLetters is the Russian alphabet the UI-source checks look for
// (А-Яа-яЁё, as the Python suite's pattern).
var cyrillicLetters = regexp.MustCompile(`[\x{0410}-\x{044F}\x{0401}\x{0451}]`)

// isWordLike is Python's re.fullmatch(r"[\w-]+", s) with Unicode \w.
func isWordLike(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// isWordBoundaryRune is the [\w=-] class around a word-like source.
func isWordBoundaryRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '=' || r == '-'
}

// replaceWordLike is re.sub(rf"(?<![\w=-]){source}(?![\w=-])", target, s)
// for a word-like source: RE2 has no lookaround, so the boundary runes are
// checked by hand. A rejected occurrence cannot overlap a later accepted
// one, every rune of a word-like source being a boundary rune itself.
func replaceWordLike(s, source, target string) string {
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(s[i:], source)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		j += i
		beforeOK := true
		if j > 0 {
			r, _ := utf8.DecodeLastRuneInString(s[:j])
			beforeOK = !isWordBoundaryRune(r)
		}
		end := j + len(source)
		afterOK := true
		if end < len(s) {
			r, _ := utf8.DecodeRuneInString(s[end:])
			afterOK = !isWordBoundaryRune(r)
		}
		if beforeOK && afterOK {
			b.WriteString(s[i:j])
			b.WriteString(target)
		} else {
			b.WriteString(s[i:end])
		}
		i = end
	}
	return b.String()
}

// translateSource is the panel's translate_source: an exact message first,
// then the longest sources first, word-like ones on word boundaries.
func translateSource(value string, messages map[string]string, order []string) string {
	if translated, ok := messages[value]; ok && translated != value {
		return translated
	}
	sources := append([]string(nil), order...)
	sort.SliceStable(sources, func(i, j int) bool { return len(sources[i]) > len(sources[j]) })
	translated := value
	for _, source := range sources {
		target := messages[source]
		if isWordLike(source) {
			translated = replaceWordLike(translated, source, target)
		} else {
			translated = strings.ReplaceAll(translated, source, target)
		}
	}
	return translated
}

// The UI fragments a page shows: text between tags and the translatable
// attributes, with comments, style, script and Jinja part removed.

var templateStrip = regexp.MustCompile(`(?s)\{#.*?#\}|<!--.*?-->|<style.*?</style>|<script.*?</script>`)
var templateFragment = regexp.MustCompile(`(?s)(?:^|>)([^<>]+)(?:<|$)`)
var templateAttr = regexp.MustCompile(`(?:title|placeholder|aria-label|data-confirm)=["']([^"']+)`)
var jinjaExpr = regexp.MustCompile(`(?s)\{[{%].*?[}%]\}`)

func templateUIFragments(t *testing.T, rel string) []string {
	t.Helper()
	source := templateStrip.ReplaceAllString(read(t, rel), "")
	var out []string
	collect := func(fragment string) {
		fragment = strings.TrimSpace(jinjaExpr.ReplaceAllString(fragment, ""))
		if fragment != "" {
			out = append(out, fragment)
		}
	}
	for _, m := range templateFragment.FindAllStringSubmatch(source, -1) {
		collect(m[1])
	}
	for _, m := range templateAttr.FindAllStringSubmatch(source, -1) {
		collect(m[1])
	}
	return out
}

// jsStringLiterals are the string literals of a script, comments removed
// first, as the Python suite's literal pattern found them.
var jsComment = regexp.MustCompile(`(?sm)/\*.*?\*/|^\s*//[^\n]*$`)

func jsStringLiterals(source string) []string {
	source = jsComment.ReplaceAllString(source, "")
	var out []string
	for i := 0; i < len(source); i++ {
		q := source[i]
		if q != '"' && q != '\'' && q != '`' {
			continue
		}
		j := i + 1
		var b strings.Builder
		for j < len(source) {
			c := source[j]
			if c == '\\' && j+1 < len(source) {
				b.WriteByte(c)
				b.WriteByte(source[j+1])
				j += 2
				continue
			}
			if c == q {
				break
			}
			b.WriteByte(c)
			j++
		}
		if j < len(source) { // a closed literal, as the pattern requires
			out = append(out, b.String())
		}
		i = j
	}
	return out
}

func javascriptUIFragments(t *testing.T, rel string) []string {
	t.Helper()
	var out []string
	for _, fragment := range jsStringLiterals(read(t, rel)) {
		if fragment = strings.TrimSpace(fragment); fragment != "" {
			out = append(out, fragment)
		}
	}
	return out
}

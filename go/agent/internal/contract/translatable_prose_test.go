package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// Prose that has a translation must be able to find it. The DOM translator
// looks each text node up whole; a tag inside a sentence splits it into
// fragments that match no key, and the word-by-word fallback then shows a
// mix of both languages. Each deliberately translated paragraph must survive
// as one text node, and no catalog entry may be left that nothing can match.

// proseCatalog merges the base Russian catalog with the fragment catalogs,
// later files winning, as the panel's loader does.
func proseCatalog(t *testing.T) map[string]string {
	t.Helper()
	messages := map[string]string{}
	base := loadCatalog(t, catalogDir+"/ru.json")
	for k, v := range base.messages {
		messages[k] = v
	}
	frags, _ := filepath.Glob(filepath.Join(repoRoot(t), filepath.FromSlash(catalogDir), "ru", "*.json"))
	sort.Strings(frags)
	for _, path := range frags {
		rel, _ := filepath.Rel(repoRoot(t), path)
		c := loadCatalog(t, filepath.ToSlash(rel))
		for k, v := range c.messages {
			messages[k] = v
		}
	}
	return messages
}

var proseInterpolation = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
var proseNodeSplit = regexp.MustCompile(`(?s)<[^>]+>|\{%.*?%\}`)

// proseTextNodes approximates the pieces the translator is handed: tags and
// Jinja block statements split the text, an interpolation stays inside its
// node (as a NUL placeholder), and whitespace is collapsed.
func proseTextNodes(markup string) []string {
	markup = proseInterpolation.ReplaceAllString(markup, "\x00")
	var nodes []string
	for _, piece := range proseNodeSplit.Split(markup, -1) {
		if strings.TrimSpace(piece) == "" {
			continue
		}
		nodes = append(nodes, strings.Join(strings.Fields(piece), " "))
	}
	return nodes
}

// proseFirstRunes is s[:n] by code point, as Python slices.
func proseFirstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// proseExpected is the recently added, deliberately translated prose. A
// blanket rule over every string would fail on the many intentionally
// untranslated ones.
var proseExpected = []struct {
	name     string
	openings []string
}{
	{"haproxy_certs.html", []string{
		"One field for all of it.",
		"An authority listed above only vouches for servers.",
		"Refuses one certificate without discarding the authority",
	}},
	{"haproxy_site_edit.html", []string{
		"A separate layer from Authelia, not a replacement for it",
		"One address or network per line.",
		"Only this authority is accepted for this site.",
	}},
}

func TestEachTranslatedParagraphSurvivesAsOneTextNode(t *testing.T) {
	messages := proseCatalog(t)
	for _, tc := range proseExpected {
		markup := read(t, webDir+"/templates/"+tc.name)
		nodes := proseTextNodes(markup)
		for _, opening := range tc.openings {
			t.Run(tc.name+"/"+opening, func(t *testing.T) {
				var matching []string
				for _, node := range nodes {
					if strings.HasPrefix(node, opening) {
						matching = append(matching, node)
					}
				}
				if len(matching) == 0 {
					t.Fatalf("%q is not a whole text node in %s; a tag inside the sentence has split it", opening, tc.name)
				}
				node := matching[0]
				if _, ok := messages[node]; !ok {
					t.Fatalf("no Russian for this node in %s:\n%s", tc.name, node)
				}
			})
		}
	}
}

func TestTheCatalogHasNoEntryThatNothingCanMatch(t *testing.T) {
	// An entry whose text no longer appears anywhere is dead weight and hides
	// that the live text is going untranslated. Raw markup, not text nodes:
	// placeholders and titles live in attributes and are translated too.
	root := repoRoot(t)
	joinCollapsed := func(paths []string) string {
		var parts []string
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, strings.Join(strings.Fields(string(raw)), " "))
		}
		return strings.Join(parts, "\n")
	}
	templates, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(webDir), "templates", "*.html"))
	haystack := joinCollapsed(templates)
	scripts, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(webDir), "static", "js", "*.js"))
	scriptHay := joinCollapsed(scripts)

	fragment := loadCatalog(t, catalogDir+"/ru/client_certificates.json")
	var stale []string
	for _, key := range fragment.order {
		if utf8.RuneCountInString(key) < 40 {
			continue // short labels also come from Python and JS
		}
		flat := strings.Join(strings.Fields(key), " ")
		if !strings.Contains(haystack, flat) && !strings.Contains(scriptHay, flat) {
			stale = append(stale, proseFirstRunes(flat, 70))
		}
	}
	if len(stale) > 0 {
		t.Errorf("catalog entries nothing will ever match:\n%s", strings.Join(stale, "\n"))
	}
}

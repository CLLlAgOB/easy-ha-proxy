package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Comments, docstrings and the daemons' messages are written in English.
// The repository is public and English; the panel's Russian lives in the
// translation catalogues. Russian stays where it belongs: the catalogues,
// the Russian documentation, the Russian e-mail templates, the bilingual
// installer and helper, and the handful of comments and tests that quote
// what an operator was actually shown -- those are listed below by name.

var englishScanned = []string{"ansible/roles", "go/panel/web", "installer", ".tests", ".github"}

// quotesRussian are the files whose comments quote a mistranslation or a
// Russian page on purpose: the point of them is the Russian text.
var quotesRussian = map[string]bool{
	".tests/js/i18n.test.js":                       true,
	".tests/test_backup_schedule_page.py":          true,
	".tests/test_english_source.py":                true,
	".tests/test_i18n.py":                          true,
	".tests/test_machine_output_not_translated.py": true,
	".tests/test_translatable_prose.py":            true,
	"go/panel/web/static/js/detection_rules.js":    true,
	"go/panel/web/templates/detection_rules.html":  true,
	"go/panel/web/templates/haproxy_certs.html":    true,
}

var templateComment = regexp.MustCompile(`(?s)\{#.*?#\}|<!--.*?-->`)
var hashSuffixes = map[string]bool{
	".yml": true, ".yaml": true, ".sh": true, ".j2": true, ".cfg": true,
	".service": true, ".timer": true, ".conf": true,
}

type scannedComment struct {
	line int
	text string
}

// englishFiles walks the scanned trees, skipping the translation catalogues,
// the Russian documentation and the bytecode caches.
func englishFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var files []string
	for _, top := range englishScanned {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(top)), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				if d.Name() == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if strings.Contains(rel, "/translations/") || strings.Contains(d.Name(), ".ru.") {
				return nil
			}
			files = append(files, rel)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)
	return files
}

// pythonStringsAndComments extracts the # comments outside string literals,
// the string statements that stand where a docstring stands (the first
// statement of a logical line at bracket depth zero), and every string
// literal with its docstring flag -- what tokenize and the ast walk yield
// for the files of this repository.
func pythonStringsAndComments(text string) ([]scannedComment, []pyString) {
	var comments []scannedComment
	var literals []pyString
	line, depth, i := 1, 0, 0
	stmtStart := true
	isPrefix := func(s string) bool {
		if s == "" || len(s) > 2 {
			return false
		}
		for _, r := range strings.ToLower(s) {
			if r != 'r' && r != 'b' && r != 'u' && r != 'f' {
				return false
			}
		}
		return true
	}
	for i < len(text) {
		c := text[i]
		switch {
		case c == '\n':
			line++
			i++
			if depth == 0 {
				stmtStart = true
			}
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			j := i
			for j < len(text) && text[j] != '\n' {
				j++
			}
			comments = append(comments, scannedComment{line, text[i:j]})
			i = j
		case c == '(' || c == '[' || c == '{':
			depth++
			stmtStart = false
			i++
		case c == ')' || c == ']' || c == '}':
			if depth > 0 {
				depth--
			}
			stmtStart = false
			i++
		case c == '\'' || c == '"':
			quote := c
			triple := i+2 < len(text) && text[i+1] == quote && text[i+2] == quote
			startLine := line
			doc := stmtStart && depth == 0
			j := i + 1
			if triple {
				j = i + 3
			}
			closed := false
			for j < len(text) {
				if text[j] == '\\' && j+1 < len(text) {
					if text[j+1] == '\n' {
						line++
					}
					j += 2
					continue
				}
				if text[j] == '\n' {
					line++
				}
				if triple {
					if j+2 < len(text) && text[j] == quote && text[j+1] == quote && text[j+2] == quote {
						j += 3
						closed = true
						break
					}
					j++
				} else {
					if text[j] == quote {
						j++
						closed = true
						break
					}
					if text[j] == '\n' {
						break // an unterminated single-line string
					}
					j++
				}
			}
			if closed {
				literals = append(literals, pyString{startLine, text[i:j], doc})
				if doc {
					comments = append(comments, scannedComment{startLine, text[i:j]})
				}
			}
			stmtStart = false
			i = j
		default:
			// A string prefix (r, b, u, f and pairs) keeps the statement
			// start: the string after it still stands where it stood.
			if stmtStart && depth == 0 && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				j := i
				for j < len(text) && ((text[j] >= 'a' && text[j] <= 'z') || (text[j] >= 'A' && text[j] <= 'Z')) {
					j++
				}
				if j < len(text) && (text[j] == '\'' || text[j] == '"') && isPrefix(text[i:j]) {
					i = j
					continue
				}
			}
			stmtStart = false
			i++
		}
	}
	return comments, literals
}

type pyString struct {
	line int
	text string
	doc  bool
}

func pythonComments(text string) []scannedComment {
	comments, _ := pythonStringsAndComments(text)
	return comments
}

// lineComments are whole-line comments: the line starts with one of the
// markers.
func lineComments(text string, markers ...string) []scannedComment {
	var out []scannedComment
	for number, line := range strings.Split(text, "\n") {
		stripped := strings.TrimSpace(line)
		matched := false
		for _, m := range markers {
			if strings.HasPrefix(stripped, m) {
				matched = true
				break
			}
		}
		if matched && !strings.HasPrefix(stripped, "#}") && !strings.HasPrefix(stripped, "#!") {
			out = append(out, scannedComment{number + 1, stripped})
		}
	}
	return out
}

func templateComments(text string) []scannedComment {
	var out []scannedComment
	for _, loc := range templateComment.FindAllStringIndex(text, -1) {
		out = append(out, scannedComment{strings.Count(text[:loc[0]], "\n") + 1, text[loc[0]:loc[1]]})
	}
	return out
}

func commentsOf(t *testing.T, rel string) []scannedComment {
	t.Helper()
	text := read(t, rel)
	suffix := filepath.Ext(rel)
	switch {
	case suffix == ".py":
		return pythonComments(text)
	case suffix == ".js" || suffix == ".css":
		return lineComments(text, "//", "/*", "*")
	case suffix == ".html":
		return templateComments(text)
	case hashSuffixes[suffix]:
		var out []scannedComment
		if suffix == ".j2" {
			out = append(out, templateComments(text)...)
		}
		return append(out, lineComments(text, "#")...)
	}
	return nil
}

func TestNoRussianInCommentsOrDocstrings(t *testing.T) {
	var found []string
	for _, rel := range englishFiles(t) {
		if quotesRussian[rel] {
			continue
		}
		for _, c := range commentsOf(t, rel) {
			if cyrillic.MatchString(c.text) {
				text := strings.TrimSpace(c.text)
				if len(text) > 90 {
					text = text[:90]
				}
				found = append(found, rel+":"+strconv.Itoa(c.line)+": "+text)
			}
		}
	}
	if len(found) > 0 {
		t.Fatalf("Russian comments:\n%s", strings.Join(found, "\n"))
	}
}

func TestTheQuotingFilesStillQuote(t *testing.T) {
	// A file that no longer needs its exemption should lose it.
	var names []string
	for rel := range quotesRussian {
		if rel != ".tests/test_english_source.py" {
			names = append(names, rel)
		}
	}
	sort.Strings(names)
	for _, rel := range names {
		if !cyrillic.MatchString(read(t, rel)) {
			t.Errorf("%s no longer quotes Russian; drop its exemption", rel)
		}
	}
}

func TestHostDaemonsAnswerInEnglish(t *testing.T) {
	// What a daemon returns reaches the panel, which translates English
	// into the operator's language -- never the other way round. The
	// Python daemons are gone; the check stands for any that return.
	root := repoRoot(t)
	matches, _ := filepath.Glob(filepath.Join(root, "ansible", "roles", "*", "files", "*.py"))
	var found []string
	for _, path := range matches {
		rel, _ := filepath.Rel(root, path)
		// Runtime strings, docstrings aside.
		_, literals := pythonStringsAndComments(read(t, filepath.ToSlash(rel)))
		for _, lit := range literals {
			if cyrillic.MatchString(lit.text) && !lit.doc {
				value := lit.text
				if len(value) > 80 {
					value = value[:80]
				}
				found = append(found, filepath.ToSlash(rel)+":"+strconv.Itoa(lit.line)+": "+value)
			}
		}
	}
	if len(found) > 0 {
		t.Fatalf("Russian daemon strings:\n%s", strings.Join(found, "\n"))
	}
}

func TestTheMovedMessagesAreTranslatedForRussianOperators(t *testing.T) {
	c := loadCatalog(t, "go/panel/web/translations/ru/backend.json")
	for _, message := range []string{
		"Failed to save configuration.yml: ",
		"rules_yaml must be a YAML list",
		"The password must be 8 to 1024 characters long",
		"Log file not found",
	} {
		if !cyrillic.MatchString(c.messages[message]) {
			t.Errorf("%q has no Russian translation", message)
		}
	}
}

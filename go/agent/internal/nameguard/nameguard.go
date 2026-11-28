// Package nameguard keeps the names of real installations out of a public
// repository. The words come from the NAME_GUARD_WORDS secret, one per line,
// and never from the repository: the list would name the very installations
// it keeps out. Every tracked file is searched, and the messages of the
// commits being pushed (BASE..HEAD when both are given, or all of HEAD after
// a forced push). A hit is reported by file and line, or by commit, and
// never with the word or the line, so the log does not repeat what it found.
//
// Without the secret -- a fork, or before it has been added -- the check
// says so and passes.
package nameguard

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/text/cases"
)

var fold = cases.Fold()

// WordsFrom is the secret's lines: stripped, casefolded, unique, sorted.
func WordsFrom(text string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		seen[fold.String(line)] = true
	}
	var words []string
	for w := range seen {
		words = append(words, w)
	}
	sort.Strings(words)
	return words
}

func git(root string, args ...string) (string, int, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			return "", -1, err
		}
	}
	return out.String(), code, nil
}

// splitLines is Python's str.splitlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == 0x1c || c == 0x1d || c == 0x1e:
			end := i
			if c == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			lines = append(lines, s[start:end])
			start = i + 1
		case c == 0xc2 && i+1 < len(s) && s[i+1] == 0x85: // U+0085
			lines = append(lines, s[start:i])
			i++
			start = i + 1
		case c == 0xe2 && i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xa8 || s[i+2] == 0xa9): // U+2028, U+2029
			lines = append(lines, s[start:i])
			i += 2
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// FileHits searches every tracked file, binaries aside, and reports a hit
// by file and line only.
func FileHits(root string, words []string) []string {
	listed, _, err := git(root, "ls-files", "-z")
	if err != nil {
		return nil
	}
	var hits []string
	for _, name := range strings.Split(listed, "\x00") {
		if name == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		head := data
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.ContainsRune(head, 0) {
			continue // binary
		}
		text := strings.ToValidUTF8(string(data), "\uFFFD")
		for number, line := range splitLines(text) {
			folded := fold.String(line)
			for _, word := range words {
				if strings.Contains(folded, word) {
					hits = append(hits, fmt.Sprintf("%s:%d", name, number+1))
					break
				}
			}
		}
	}
	return hits
}

// MessageHits reads the messages of the commits being pushed. A forced push
// names a "before" that is no longer in the history, so nothing tells which
// messages are new: every message of HEAD is read.
func MessageHits(root string, words []string, base, head string) []string {
	if base == "" || head == "" || strings.Trim(base, "0") == "" {
		return nil
	}
	_, code, _ := git(root, "cat-file", "-e", base+"^{commit}")
	revisions := head
	if code == 0 {
		revisions = base + ".." + head
	}
	log, _, err := git(root, "log", "--format=%H%x00%B%x01", revisions)
	if err != nil {
		return nil
	}
	var hits []string
	for _, entry := range strings.Split(log, "\x01") {
		entry = strings.TrimSpace(entry)
		commit, message, _ := strings.Cut(entry, "\x00")
		if commit == "" {
			continue
		}
		folded := fold.String(message)
		for _, word := range words {
			if strings.Contains(folded, word) {
				hits = append(hits, "commit "+commit[:12])
				break
			}
		}
	}
	return hits
}

// Run is the check: its exit code and what it prints, the words and the
// range taken from the environment by the caller.
func Run(wordsText, root, base, head string, stdout io.Writer) int {
	words := WordsFrom(wordsText)
	if len(words) == 0 {
		fmt.Fprintln(stdout, "::notice::NAME_GUARD_WORDS is not set, so no names were checked.")
		return 0
	}
	if root == "" {
		root = "."
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	hits := append(FileHits(root, words), MessageHits(root, words, base, head)...)
	for _, hit := range hits {
		fmt.Fprintf(stdout, "::error::A guarded name appears at %s\n", hit)
	}
	fmt.Fprintf(stdout, "%d guarded names, %d found.\n", len(words), len(hits))
	if len(hits) > 0 {
		return 1
	}
	return 0
}

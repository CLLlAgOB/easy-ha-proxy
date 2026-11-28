// Package contract holds the repository's contract tests: the templates,
// systemd units, panel pages, shell entry points and CI workflows the
// gateway is built from, checked against the regressions they once caused.
// They replace the Python suite that lived in .tests/; nothing here runs on
// a gateway, and every test only reads the checkout.
package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// repoRoot is the checkout these tests read.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

// read is the text of a file of the checkout, relative to its root, with
// universal newlines as Python's read_text gives them.
func read(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\r", "\n")
}

// cyrillic is the Cyrillic block the English-source checks look for.
var cyrillic = regexp.MustCompile(`[\x{0400}-\x{04FF}]`)

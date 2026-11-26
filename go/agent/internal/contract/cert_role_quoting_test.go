package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// The cert role runs as root; nothing from the site configuration reaches a
// shell unquoted. websites.yml is written by the panel, and its names, alt
// names and certificate paths were once placed into root shell scripts and
// certbot's argument line as they were: a name like x$(id) ran a command,
// and x --deploy-hook ... gave certbot a hook. Every value now goes through
// quote.

// certPrequoted are the expressions built by templates/_san_flags.j2, which
// quotes every name itself.
var certPrequoted = map[string]bool{"{{ san_flags }}": true}

var certCommandTask = regexp.MustCompile(`^(\s*)(?:ansible\.builtin\.)?(shell|command|raw):\s*(.*)$`)
var certInterpolation = regexp.MustCompile(`\{\{[^}]*\}\}`)

// certLeadingSpace is len(line) - len(line.lstrip()), counted in runes.
func certLeadingSpace(line string) int {
	n := 0
	for _, r := range line {
		if !unicode.IsSpace(r) {
			break
		}
		n++
	}
	return n
}

type certBlock struct {
	line int    // 1-based line of the task key
	text string // the task value plus its continuation lines
}

// certCommandBlocks yields every shell/command/raw task block of a YAML
// file: the task line plus every following blank or deeper-indented line.
func certCommandBlocks(t *testing.T, rel string) []certBlock {
	t.Helper()
	lines := strings.Split(read(t, rel), "\n")
	var blocks []certBlock
	i := 0
	for i < len(lines) {
		m := certCommandTask.FindStringSubmatch(lines[i])
		if m == nil {
			i++
			continue
		}
		indent := certLeadingSpace(lines[i])
		start := i + 1
		block := []string{m[3]}
		i++
		for i < len(lines) && (strings.TrimSpace(lines[i]) == "" || certLeadingSpace(lines[i]) > indent) {
			block = append(block, lines[i])
			i++
		}
		blocks = append(blocks, certBlock{line: start, text: strings.Join(block, "\n")})
	}
	return blocks
}

func TestEveryInterpolationInACommandIsQuoted(t *testing.T) {
	root := repoRoot(t)
	roleDir := filepath.Join(root, "ansible", "roles", "cert")
	var files []string
	err := filepath.WalkDir(roleDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var unquoted []string
	for _, path := range files {
		rel, _ := filepath.Rel(root, path)
		for _, block := range certCommandBlocks(t, filepath.ToSlash(rel)) {
			for _, expression := range certInterpolation.FindAllString(block.text, -1) {
				if !strings.Contains(expression, "quote") && !certPrequoted[expression] {
					unquoted = append(unquoted, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), block.line, expression))
				}
			}
		}
	}
	if len(unquoted) != 0 {
		t.Errorf("unquoted interpolations in cert role commands:\n%s", strings.Join(unquoted, "\n"))
	}
}

func TestTheSanFlagsQuoteEachName(t *testing.T) {
	template := read(t, "ansible/roles/cert/templates/_san_flags.j2")
	mustContain(t, template, "map('quote')", "_san_flags.j2")
}

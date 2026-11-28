package updateplan

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestTheCommandPrintsThePlanAndExitsZeroForUnknownComponents(t *testing.T) {
	payload := M{"schema_version": 1, "generated_at": "2026-07-19T12:00:00Z", "source_channel": "github",
		"image_channel": "latest", "components": []any{M{"id": "all", "state": "unknown", "summary": "<&>"}}}
	saved := buildPlan
	defer func() { buildPlan = saved }()
	var got Options
	buildPlan = func(o Options) (M, error) { got = o; return payload, nil }
	var stdout, stderr strings.Builder
	code := RunCLI([]string{"--format", "json", "--haproxy-status", "--image-channel", "alpha", "--source-channel", "local",
		"--branch", "alpha"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	var printed M
	if err := json.Unmarshal([]byte(stdout.String()), &printed); err != nil {
		t.Fatal(err)
	}
	if mustJSON(printed) != mustJSON(payload) || !strings.Contains(stdout.String(), "<&>") {
		t.Fatalf("printed %s", stdout.String())
	}
	if !got.IncludeHAProxy || got.ImageChannel != "alpha" || got.SourceChannel != "local" || got.Branch != "alpha" {
		t.Fatalf("options %+v", got)
	}
}

func TestBadArgumentsExitTwoWithTheReasonLast(t *testing.T) {
	saved := buildPlan
	defer func() { buildPlan = saved }()
	buildPlan = func(Options) (M, error) { return nil, errors.New("branch contains unsupported characters") }
	for _, args := range [][]string{{"--branch", "a..b"}, {"--branch", ""}, {"--image-channel", "beta"},
		{"--source-channel", "ftp"}, {"--format", "yaml"}, {"extra"}, {"--unknown"}, {}} {
		var stdout, stderr strings.Builder
		if code := RunCLI(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("%q: code %d stdout %q", args, code, stdout.String())
		}
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		if !strings.Contains(lines[len(lines)-1], "error: ") {
			t.Fatalf("%q: %q", args, stderr.String())
		}
	}
}

func TestBuildingRefusesUnsupportedChannelsAndBranches(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "config")
	for _, metadata := range []string{"source_channel: ftp\n", "image_channel: beta\n", "branch: a..b\n"} {
		writeFile(t, filepath.Join(config, "metadata.yml"), metadata)
		_, err := BuildUpdatePlan(Options{SourceDir: root, ConfigDir: config, Runner: newFakeRunner(unexpected),
			Getenv: func(string) string { return "" }})
		if err == nil {
			t.Fatalf("%q accepted", metadata)
		}
	}
}

func TestTheBranchAndRepositoryComeFromTheEnvironmentAfterTheMetadata(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	var asked []string
	runner := newFakeRunner(func(argv []string) CommandResult {
		if hasPrefix(argv, "git", "ls-remote") {
			asked = append(asked, argv[4], argv[5])
			return failed(1, "offline")
		}
		if hasSuffix(argv, "remote", "get-url", "origin") {
			return failed(1, "no origin")
		}
		return gitHandler(argv)
	})
	env := map[string]string{"EASY_HA_PROXY_BRANCH": "alpha", "EASY_HA_PROXY_REPOSITORY": "https://example.test/fork.git"}
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, ""),
		Getenv: func(name string) string { return env[name] }})
	if plan["branch"] != "alpha" || !reflect.DeepEqual(asked, []string{"https://example.test/fork.git", "refs/heads/alpha"}) {
		t.Fatalf("branch %v asked %v", plan["branch"], asked)
	}
}

// Every sentence the checker can show has a Russian translation: the page
// translates a component's summary in the browser, and a sentence with no
// catalogue entry fell back to word-by-word substitution.

func constantString(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, okLeft := constantString(e.X)
		right, okRight := constantString(e.Y)
		return left + right, okLeft && okRight
	case *ast.ParenExpr:
		return constantString(e.X)
	}
	return "", false
}

func checkerSummaries(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	found := map[string]bool{}
	// The summary argument of each constructor.
	position := map[string]int{"component": 2, "result": 1, "block": 2}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			name, isIdent := call.Fun.(*ast.Ident)
			if !isIdent {
				return true
			}
			if index, known := position[name.Name]; known && len(call.Args) > index {
				if text, constant := constantString(call.Args[index]); constant {
					found[text] = true
				}
			}
			return true
		})
	}
	out := []string{}
	for text := range found {
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

func TestEveryCheckerSummaryIsTranslated(t *testing.T) {
	summaries := checkerSummaries(t)
	if len(summaries) <= 30 {
		t.Fatalf("only %d summaries found", len(summaries))
	}
	messages := russianMessages(t)
	missing := []string{}
	for _, text := range summaries {
		if _, found := messages[text]; !found {
			missing = append(missing, text)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("update checker summaries with no Russian:\n%s", strings.Join(missing, "\n"))
	}
	sentence := "One or more managed Docker image versions could not be checked; the stack cannot be updated partially."
	if !strings.HasPrefix(messages[sentence], "Не удалось проверить") {
		t.Fatalf("%q -> %q", sentence, messages[sentence])
	}
}

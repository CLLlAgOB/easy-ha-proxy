// Package updateplan builds a read-only, machine-readable easy-ha-proxy
// update plan.
//
// The checker does not mutate APT state, fetch Git objects into the managed
// checkout, or pull Docker images. The update broker runs it ("easy-ha-proxy-
// agent update-plan") and signs the plan it prints; applying a plan is held
// to what it reviewed.
package updateplan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

const (
	schemaVersion = 1

	DefaultSourceDir       = "/opt/easy-ha-proxy/source"
	DefaultConfigDir       = "/etc/easy-ha-proxy"
	DefaultAutheliaCompose = "/opt/authelia/docker-compose.yml"
	DefaultAdminCompose    = "/opt/haproxy-admin/docker-compose.yml"
	defaultAdminImage      = "clllagob/haproxy-admin-ui:latest"
	defaultRepository      = "https://github.com/CLLlAgOB/easy-ha-proxy.git"
	defaultBranch          = "main"

	gitTimeout      = 20 * time.Second
	aptTimeout      = 45 * time.Second
	composeTimeout  = 15 * time.Second
	registryTimeout = 30 * time.Second
	// The changelog: optional, so it gives up early.
	cloneTimeout = 60 * time.Second
	// The candidate source: without it the plan cannot say what the complete
	// update installs, so it gets longer. A gateway with a slow route to
	// GitHub took more than a minute for a full clone.
	candidateTimeout = 180 * time.Second

	// "What's new": the commit subjects between the installed and the
	// candidate revision, read from a history-only clone.
	changelogDepth        = 200
	changelogLimit        = 40
	changelogSubjectChars = 160

	sourceRevisionMarker = ".easy-ha-proxy-source-revision"
	// How many locally changed files a blocked source names.
	maxChangedFiles = 20
)

var (
	validStates         = map[string]bool{"available": true, "current": true, "unknown": true, "blocked": true}
	validSourceChannels = map[string]bool{"github": true, "local": true}
	validImageChannels  = map[string]bool{"latest": true, "alpha": true}

	controlRe       = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	digestRe        = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	digestFullRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionRe      = regexp.MustCompile(`[0-9a-f]{40,64}`)
	revisionFullRe  = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	branchRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	uriUserinfoRe   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
	secretQueryRe   = regexp.MustCompile(`(?i)([?&](?:access_?token|api_?key|key|password|passwd|secret|token)=)[^&#\s]+`)
	scalarKeyRe     = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	webTreeRe       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerIDRe   = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	shortImageIDRe  = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	aptInstLineRe   = regexp.MustCompile(`^Inst\s+(?P<name>\S+)(?:\s+\[(?P<installed>[^\]]*)\])?\s+\((?P<version>\S+)(?:\s|\))`)
	releaseTagRe    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)((?:-[a-z]+)?)$`)
	haproxyBranchRe = regexp.MustCompile(`^(?:\d+:)?(\d+\.\d+)\.`)
)

// CommandResult is a bounded subprocess result; probe failures never raise.
type CommandResult struct {
	Returncode int
	Stdout     string
	Stderr     string
	Error      string // "", "not-found", "timeout", "os-error"
}

// Runner runs one fixed argv without a shell.
type Runner interface {
	Run(argv []string, timeout time.Duration) CommandResult
}

// SubprocessRunner runs commands with a deterministic locale and hard timeouts.
type SubprocessRunner struct{}

func (SubprocessRunner) Run(argv []string, timeout time.Duration) CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "GIT_TERMINAL_PROMPT=0", "DEBIAN_FRONTEND=noninteractive")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return CommandResult{124, stdout.String(), stderr.String(), "timeout"}
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return CommandResult{exit.ExitCode(), stdout.String(), stderr.String(), ""}
		}
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return CommandResult{127, "", err.Error(), "not-found"}
		}
		return CommandResult{126, "", err.Error(), "os-error"}
	}
	return CommandResult{0, stdout.String(), stderr.String(), ""}
}

// M is a JSON object of the plan.
type M = map[string]any

func component(id, state, summary string, current, available any, details M) M {
	if !validStates[state] {
		panic("unsupported update state: " + state)
	}
	if details == nil {
		details = M{}
	}
	return M{
		"id": id, "state": state, "actionable": state == "available", "summary": summary,
		"current_version": current, "available_version": available,
		// Stable aliases used by the host broker when signing a checked plan.
		"installed": current, "available": available, "candidate": available,
		"details": details,
	}
}

// details is a component's details object (created when missing).
func details(c M) M {
	if d, ok := c["details"].(M); ok {
		return d
	}
	d := M{}
	c["details"] = d
	return d
}

func merged(base M, more M) M {
	out := M{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// truthyStr is Python's `str(value or "")`.
func truthyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if !x {
			return ""
		}
		return "True"
	case int:
		if x == 0 {
			return ""
		}
	case int64:
		if x == 0 {
			return ""
		}
	case float64:
		if x == 0 {
			return ""
		}
	}
	return pyStr(v)
}

// pyStr renders scalars the way Python's str() does for YAML values.
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// toPlain turns loaded YAML into plain Go values.
func toPlain(v any) any {
	switch x := v.(type) {
	case *pyyaml.Map:
		out := M{}
		x.Each(func(key, value any) { out[pyStr(key)] = toPlain(value) })
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = toPlain(item)
		}
		return out
	default:
		return v
	}
}

// readMapping reads a YAML mapping; an error message (not an error) when it
// cannot, and an empty mapping for a missing or empty file.
func readMapping(path string) (M, string) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return M{}, ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return M{}, fmt.Sprintf("Could not read %s: %v", path, err)
	}
	loaded, err := pyyaml.Load(raw)
	if err != nil {
		return M{}, fmt.Sprintf("Could not parse %s: %v", path, err)
	}
	if loaded == nil {
		return M{}, ""
	}
	m, ok := toPlain(loaded).(M)
	if !ok {
		return M{}, "Expected a YAML mapping in " + path
	}
	return m, ""
}

// parseScalarYAML reads top-level "key: value" scalars without a YAML parser.
func parseScalarYAML(text string) map[string]string {
	values := map[string]string{}
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "" || raw[0] == ' ' || raw[0] == '\t' || strings.HasPrefix(strings.TrimLeft(raw, " \t"), "#") {
			continue
		}
		key, value, ok := strings.Cut(raw, ":")
		if !ok || !scalarKeyRe.MatchString(key) {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) >= 1 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"') {
			if len(value) >= 2 {
				value = value[1 : len(value)-1]
			} else {
				value = ""
			}
		} else {
			value = strings.TrimSpace(strings.SplitN(value, " #", 2)[0])
		}
		values[key] = value
	}
	return values
}

func redact(value string) string {
	value = uriUserinfoRe.ReplaceAllString(value, "${1}***@")
	return secretQueryRe.ReplaceAllString(value, "${1}***")
}

func shortError(r CommandResult) string {
	switch r.Error {
	case "timeout":
		return "probe timed out"
	case "not-found":
		return "required command is not installed"
	}
	text := strings.TrimSpace(r.Stderr)
	if text == "" {
		text = strings.TrimSpace(r.Stdout)
	}
	if text == "" {
		return fmt.Sprintf("command exited with %d", r.Returncode)
	}
	first := strings.SplitN(text, "\n", 2)[0]
	return truncRunes(redact(strings.TrimRight(first, "\r")), 240)
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func validBranch(branch string) bool {
	return branchRe.MatchString(branch) && !strings.Contains(branch, "..") && !strings.HasSuffix(branch, "/") &&
		!strings.Contains(branch, "//")
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func badRef(s string) bool {
	return s == "" || strings.ContainsAny(s, "\r\n\x00")
}

func strList(items []string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}

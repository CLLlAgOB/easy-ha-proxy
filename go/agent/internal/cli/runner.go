package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// AgentBinaryDefault is the installed host agent path.
	AgentBinaryDefault = "/usr/local/sbin/easy-ha-proxy-agent"
	// StagedAgentDefault is where an agent fetched for one run is staged so the
	// native stage still sees the change against AgentBinaryDefault.
	StagedAgentDefault = "/var/lib/easy-ha-proxy/native-staging/bootstrap/easy-ha-proxy-agent"
	// UpdateSourceRefreshedEnv guards against re-execing more than once.
	UpdateSourceRefreshedEnv = "EASY_HA_PROXY_UPDATE_SOURCE_REFRESHED"
	// ProgressEnv enables EHP-PROGRESS phase markers for updated.
	ProgressEnv = "EASY_HA_PROXY_PROGRESS"
)

var (
	agentBinary           = AgentBinaryDefault
	stagedAgent           = StagedAgentDefault
	sourceRevisionRe      = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	maintenanceRevRe      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	lookPath              = exec.LookPath
	runSubprocessFn       = defaultRunSubprocess
	runCommandFn          = defaultRunCommand
	fetchRunnerFn         = defaultFetchRunner
	bootstrapAgentFn      = defaultBootstrapAgent
	agentRunsPlaybookFn   = defaultAgentRunsPlaybook
	runPlaybookFn         = defaultRunPlaybook
	updateManagedSourceFn = defaultUpdateManagedSource
	reexecAfterSourceFn   = defaultReexecAfterSourceUpdate
	syncRuntimeDepsFn     = defaultSyncRuntimeDependencies
	changesScopeFn        = defaultChangesScope
	recordAppliedSourceFn = defaultRecordAppliedSource
	gitRevisionFn         = defaultGitRevision
	execveFn              = syscall.Exec
)

type subprocessResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Err      error
}

// CommandExitError wraps a subprocess non-zero exit code.
type CommandExitError struct {
	Command  []string
	ExitCode int
}

func (e *CommandExitError) Error() string {
	return fmt.Sprintf("command failed with exit code %d.", e.ExitCode)
}

func defaultRunSubprocess(name string, args ...string) subprocessResult {
	return runSubprocessWithTimeout(0, name, args...)
}

func runSubprocessWithTimeout(timeout time.Duration, name string, args ...string) subprocessResult {
	var cmd *exec.Cmd
	var cancel context.CancelFunc
	if timeout > 0 {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, name, args...)
	} else {
		cmd = exec.Command(name, args...)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return subprocessResult{ExitCode: ee.ExitCode(), Stdout: outBuf.String(), Stderr: errBuf.String()}
		}
		return subprocessResult{ExitCode: 1, Stdout: outBuf.String(), Stderr: errBuf.String(), Err: err}
	}
	return subprocessResult{ExitCode: 0, Stdout: outBuf.String(), Stderr: errBuf.String()}
}

func runSubprocess(name string, args ...string) subprocessResult {
	return runSubprocessFn(name, args...)
}

func defaultRunCommand(out io.Writer, command []string, env []string) error {
	fmt.Fprintf(out, "\n+ %s\n", strings.Join(command, " "))
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	if env != nil {
		cmd.Env = env
	}
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code := ee.ExitCode()
			if code == 0 {
				code = 1
			}
			return &CommandExitError{Command: command, ExitCode: code}
		}
		return err
	}
	return nil
}

func runCommand(out io.Writer, command []string, env []string) error {
	return runCommandFn(out, command, env)
}

// AgentRunsPlaybook reports whether the binary at agent supports "apply playbook".
func AgentRunsPlaybook(agent string) bool {
	return agentRunsPlaybookFn(agent)
}

func defaultAgentRunsPlaybook(agent string) bool {
	if !isRegularFile(agent) {
		return false
	}
	res := runSubprocess(agent, "apply", "playbook", "--supported", "--tags", "never")
	return res.Err == nil && (res.ExitCode == 0 || res.ExitCode == 3)
}

// FetchRunner downloads and stages the agent binary built for the current source revision.
func FetchRunner(out io.Writer, directory string) (string, error) {
	return fetchRunnerFn(out, directory)
}

func sourceTreeRevision(src string) string {
	if _, err := os.Stat(filepath.Join(src, ".git")); err == nil {
		res := runSubprocess("git", "-c", "safe.directory="+src, "-C", src, "rev-parse", "HEAD")
		revision := strings.TrimSpace(res.Stdout)
		if res.Err == nil && res.ExitCode == 0 && sourceRevisionRe.MatchString(revision) {
			return revision
		}
	}
	if raw, err := os.ReadFile(filepath.Join(src, ".easy-ha-proxy-source-revision")); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "revision="); ok && sourceRevisionRe.MatchString(strings.TrimSpace(value)) {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func defaultFetchRunner(out io.Writer, directory string) (string, error) {
	revision := sourceTreeRevision(SourceDir())
	varsFile := filepath.Join(directory, "vars.yml")
	variables := map[string]any{}
	if isRegularFile(varsFile) {
		loaded, err := LoadYAMLMapping(varsFile)
		if err != nil {
			return "", err
		}
		variables = mapToGoMap(loaded)
	}
	reference := ImageReference(variables, revision)
	sourceDesc := reference
	if sourceDesc == "" {
		sourceDesc = "the configured native bundle"
	}
	binary, err := BundleAgent(variables, "")
	if err == nil && binary == nil && reference != "" {
		var verify func(string) error
		if verify, err = nativeSignatureVerifier(variables); err == nil {
			binary, err = dockerAgent(reference, revision, verify)
			if err == nil && binary == nil {
				binary, err = fetchAgent(reference, revision, "", verify)
			}
		}
	}
	if err == nil && binary == nil {
		err = bootstrapErrorf("no source of the native binaries is configured")
	}
	if err == nil {
		err = InstallAgent(binary, stagedAgent)
	}
	if err != nil {
		return "", installerErrorf("Could not get the installer agent from %s: %v. CI publishes it for each commit of main and alpha a few minutes after the commit.", sourceDesc, err)
	}
	if !AgentRunsPlaybook(stagedAgent) {
		return "", installerErrorf("The agent from %s cannot run the installer; it is older than this source.", sourceDesc)
	}
	built := "of this channel"
	if revision != "" {
		prefix := revision
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		built = "built from " + prefix
	}
	fmt.Fprintf(out, "Fetched the installer agent %s (%s).\n", built, sourceDesc)
	return stagedAgent, nil
}

func agentArguments(directory string, extraVars map[string]any) []string {
	args := []string{"--source", SourceDir(), "--config", directory}
	if len(extraVars) > 0 {
		keys := make([]string, 0, len(extraVars))
		for k := range extraVars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "--extra", fmt.Sprintf("%s=%s", k, formatExtraVarValue(extraVars[k])))
		}
	}
	return args
}

func formatExtraVarValue(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return fmt.Sprintf("%g", x)
	default:
		return fmt.Sprint(v)
	}
}

// BootstrapAgent runs the installed agent's native part before the playbook so
// an update upgrades the agent binary first.
func BootstrapAgent(out io.Writer, directory string, extraVars map[string]any) error {
	return bootstrapAgentFn(out, directory, extraVars)
}

func defaultBootstrapAgent(out io.Writer, directory string, extraVars map[string]any) error {
	if !isRegularFile(agentBinary) {
		return nil
	}
	probe := runSubprocess(agentBinary, "apply", "parts")
	if probe.Err != nil || probe.ExitCode != 0 || !strings.Contains(probe.Stdout, `"native"`) {
		return nil
	}
	cmd := append([]string{agentBinary, "apply", "run", "--part", "native"}, agentArguments(directory, extraVars)...)
	return runCommand(out, cmd, nil)
}

// AgentPlaybookCommand builds the exact argv for "apply playbook".
func AgentPlaybookCommand(agent, tags string, checkMode bool, directory string, extraVars map[string]any, skipTags string) []string {
	cmd := append([]string{agent, "apply", "playbook", "--tags", tags}, agentArguments(directory, extraVars)...)
	if skipTags != "" {
		cmd = append(cmd, "--skip-tags", skipTags)
	}
	if checkMode {
		cmd = append(cmd, "--check")
	}
	return cmd
}

// PlaybookOptions configures a single RunPlaybook invocation.
type PlaybookOptions struct {
	CheckMode bool
	Directory string
	ExtraVars map[string]any
	SkipTags  string
}

// RunPlaybook executes the host agent playbook for tags.
func RunPlaybook(ctx *Context, tags string, opts PlaybookOptions) error {
	return runPlaybookFn(ctx, tags, opts)
}

func defaultRunPlaybook(ctx *Context, tags string, opts PlaybookOptions) error {
	effectiveExtra := map[string]any{}
	for k, v := range opts.ExtraVars {
		effectiveExtra[k] = v
	}
	tagList := splitTags(tags)
	if !opts.CheckMode && containsString(tagList, "status") {
		if _, ok := effectiveExtra["status_check_fail_on_error"]; !ok {
			effectiveExtra["status_check_fail_on_error"] = "true"
		}
	}
	target := opts.Directory
	if target == "" {
		target = ConfigDir()
	}
	if err := RequireConfiguration(target); err != nil {
		return err
	}
	if !opts.CheckMode && containsString(tagList, "ha-adm-native") {
		if err := BootstrapAgent(ctx.Stdout, target, effectiveExtra); err != nil {
			return err
		}
	}
	agent := agentBinary
	if !AgentRunsPlaybook(agentBinary) {
		var err error
		agent, err = FetchRunner(ctx.Stdout, target)
		if err != nil {
			return err
		}
	}
	if err := runCommand(ctx.Stdout, AgentPlaybookCommand(agent, tags, opts.CheckMode, target, effectiveExtra, opts.SkipTags), nil); err != nil {
		return err
	}
	if !opts.CheckMode && containsString(tagList, "upgrade") {
		if _, err := OfferPendingReboot(ctx, false); err != nil {
			return err
		}
	}
	return nil
}

// SyncRuntimeDependencies removes what the Python installer left: its
// virtual environment, once nothing runs from it, and the Ansible scratch
// directory.
func SyncRuntimeDependencies(out io.Writer) error {
	return syncRuntimeDepsFn(out)
}

// procRoot is /proc; the tests point it at a fake one.
var procRoot = "/proc"

// runsFrom says whether a running process executes from dir: its command
// line names a program there, or it has a file from there mapped. The update
// broker of a release before 1.2.0 runs from the Python environment while it
// applies the update that replaces it.
func runsFrom(dir string) bool {
	prefix := strings.TrimRight(dir, "/") + "/"
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if raw, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cmdline")); err == nil {
			for _, arg := range strings.Split(string(raw), "\x00") {
				if strings.HasPrefix(arg, prefix) {
					return true
				}
			}
		}
		if raw, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "maps")); err == nil && strings.Contains(string(raw), prefix) {
			return true
		}
	}
	return false
}

func defaultSyncRuntimeDependencies(out io.Writer) error {
	home := InstallHome()
	venv := filepath.Join(home, "venv")
	if fileExists(venv) {
		if runsFrom(venv) {
			fmt.Fprintf(out, "The Python environment %s is still in use; a later update removes it.\n", venv)
		} else if err := os.RemoveAll(venv); err != nil {
			return err
		} else {
			fmt.Fprintf(out, "Removed the Python environment the installer no longer needs: %s\n", venv)
		}
	}
	_ = os.RemoveAll(filepath.Join(home, "tmp", "ansible"))
	return nil
}

// EnsureSourceExecutables restores 0755 mode on managed shell entrypoints.
func EnsureSourceExecutables(directory string) {
	root := directory
	if root == "" {
		root = SourceDir()
	}
	for _, rel := range []string{
		"install.sh",
		"install-local.sh",
		"install-remote.sh",
		"easy-ha-proxy-helper.sh",
		"installer/easy-ha-proxy",
	} {
		p := filepath.Join(root, rel)
		if isRegularFile(p) {
			_ = os.Chmod(p, 0o755)
		}
	}
}

// NormalizeSourceRevision validates a full lowercase Git object ID.
func NormalizeSourceRevision(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	rev := strings.ToLower(strings.TrimSpace(value))
	if !sourceRevisionRe.MatchString(rev) {
		return "", installerErrorf("Expected source revision must be a full Git object ID.")
	}
	return rev, nil
}

// GitRevision resolves ref in directory to a full lowercase Git commit ID.
func GitRevision(directory, ref string) (string, error) {
	return gitRevisionFn(directory, ref)
}

func defaultGitRevision(directory, ref string) (string, error) {
	res := runSubprocess("git", "-C", directory, "rev-parse", "--verify", ref)
	rev := strings.ToLower(strings.TrimSpace(res.Stdout))
	if res.Err != nil || res.ExitCode != 0 || !sourceRevisionRe.MatchString(rev) {
		detail := strings.TrimSpace(res.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(res.Stdout)
		}
		suffix := ""
		if detail != "" {
			suffix = ": " + strings.SplitN(detail, "\n", 2)[0]
		}
		return "", installerErrorf("Could not resolve fetched source revision%s", suffix)
	}
	return rev, nil
}

// UpdateManagedSource fetches the configured Git branch into /opt/easy-ha-proxy/source.
func UpdateManagedSource(out io.Writer, expectedRevision string) (bool, error) {
	return updateManagedSourceFn(out, expectedRevision)
}

func defaultUpdateManagedSource(out io.Writer, expectedRevision string) (bool, error) {
	expected, err := NormalizeSourceRevision(expectedRevision)
	if err != nil {
		return false, err
	}
	managedSource := resolvePath(filepath.Join(InstallHome(), "source"))
	currentSource := resolvePath(SourceDir())
	if currentSource != managedSource {
		fmt.Fprintln(out, "Source update skipped: this is not the installer-managed source path.")
		return false, nil
	}
	branch := strings.TrimSpace(os.Getenv("EASY_HA_PROXY_BRANCH"))
	if branch == "" {
		branch = strings.TrimSpace(strVal(LoadMetadata("").Value("branch")))
	}
	if branch == "" {
		branch = "main"
	}
	if !ValidGitBranch(branch) {
		return false, installerErrorf("Invalid git branch recorded in metadata: %q", branch)
	}
	if isDir(filepath.Join(currentSource, ".git")) {
		if err := runCommand(out, []string{"git", "-C", currentSource, "fetch", "--depth=1", "origin", branch}, nil); err != nil {
			return false, err
		}
		fetched, err := GitRevision(currentSource, "FETCH_HEAD")
		if err != nil {
			return false, err
		}
		if expected != "" && fetched != expected {
			return false, installerErrorf("The fetched source revision changed after the update check; run the check again before applying.")
		}
		if err := runCommand(out, []string{"git", "-C", currentSource, "reset", "--hard", fetched}, nil); err != nil {
			return false, err
		}
		EnsureSourceExecutables(currentSource)
		return true, nil
	}

	metadata := LoadMetadata("")
	repository := strings.TrimSpace(os.Getenv("EASY_HA_PROXY_REPOSITORY"))
	if repository == "" {
		repository = strings.TrimSpace(strVal(metadata.Value("repository")))
	}
	if repository == "" {
		repository = DefaultRepository
	}
	home := InstallHome()
	if err := os.MkdirAll(home, 0o755); err != nil {
		return false, err
	}
	stagingRoot, err := os.MkdirTemp(home, ".source-update.")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(stagingRoot)
	checkout := filepath.Join(stagingRoot, "source")
	backup := filepath.Join(home, "source.before-update."+time.Now().UTC().Format("20060102T150405Z"))

	fmt.Fprintf(out, "The installed source is a staged bundle; cloning %s (%s) atomically.\n", repository, branch)
	if err := runCommand(out, []string{"git", "clone", "--depth=1", "--branch", branch, repository, checkout}, nil); err != nil {
		return false, err
	}
	for _, required := range []string{"installer/easy-ha-proxy", "installer/agent-fetch.sh", "ansible/easy-ha-proxy.yml"} {
		if !isRegularFile(filepath.Join(checkout, required)) {
			return false, installerErrorf("Downloaded source is incomplete: %s", required)
		}
	}
	fetched, err := GitRevision(checkout, "HEAD")
	if err != nil {
		return false, err
	}
	if expected != "" && fetched != expected {
		return false, installerErrorf("The downloaded source revision changed after the update check; run the check again before applying.")
	}
	if err := os.Rename(currentSource, backup); err != nil {
		return false, err
	}
	if err := os.Rename(checkout, currentSource); err != nil {
		_ = os.Rename(backup, currentSource)
		return false, err
	}
	EnsureSourceExecutables(currentSource)
	fmt.Fprintf(out, "Previous source backup: %s\n", backup)
	return true, nil
}

// ReexecAfterSourceUpdate restarts the refreshed installer entrypoint once,
// keeping the maintenance lock descriptor open across exec.
func ReexecAfterSourceUpdate(out io.Writer, origArgs []string) error {
	return reexecAfterSourceFn(out, origArgs)
}

func defaultReexecAfterSourceUpdate(out io.Writer, origArgs []string) error {
	entrypoint := filepath.Join(SourceDir(), "installer/easy-ha-proxy")
	if !isRegularFile(entrypoint) {
		return installerErrorf("Refreshed installer entrypoint is missing: %s", entrypoint)
	}
	env := append(os.Environ(), UpdateSourceRefreshedEnv+"=1")
	if maintenanceLockFD >= 0 {
		// Clear FD_CLOEXEC so the refreshed installer inherits the flock.
		_, _ = unix.FcntlInt(uintptr(maintenanceLockFD), unix.F_SETFD, 0)
	}
	fmt.Fprintln(out, "Restarting the updater with the refreshed installer source.")
	argv := append([]string{entrypoint}, origArgs...)
	if err := execveFn(entrypoint, argv, env); err != nil {
		return installerErrorf("Could not restart the refreshed installer: %v", err)
	}
	return installerErrorf("Could not restart the refreshed installer.")
}

// ProgressPhase emits a progress marker when updated requests progress reporting.
func ProgressPhase(out io.Writer, name string) {
	if os.Getenv(ProgressEnv) == "1" {
		fmt.Fprintf(out, "EHP-PROGRESS phase=%s\n", name)
	}
}

func scopeUnavailable() map[string]any {
	return map[string]any{
		"ready":    false,
		"reason":   "scope-unavailable",
		"full":     true,
		"tags":     []string{},
		"steps":    []string{},
		"changed":  0,
		"unmapped": []string{},
		"paths":    []string{},
	}
}

func runUpdateScope(agent, action, directory string, extra ...string) (subprocessResult, bool) {
	if !isRegularFile(agent) {
		return subprocessResult{}, false
	}
	args := append([]string{"update-scope", action, "--config", directory, "--source", SourceDir()}, extra...)
	res := runSubprocess(agent, args...)
	if res.Err != nil {
		return subprocessResult{}, false
	}
	return res, true
}

func agentUpdateScope(out io.Writer, action, directory string, extra ...string) (subprocessResult, bool) {
	res, ok := runUpdateScope(agentBinary, action, directory, extra...)
	unsupported := ok && res.ExitCode == 2 && !strings.Contains(res.Stderr, "update-scope")
	if ok && !unsupported {
		return res, true
	}
	staged, err := FetchRunner(out, directory)
	if err != nil {
		return res, ok
	}
	if stagedRes, stagedOK := runUpdateScope(staged, action, directory, extra...); stagedOK {
		return stagedRes, true
	}
	return res, ok
}

// ChangesScope asks the host agent what tags the current source diff requires.
func ChangesScope(out io.Writer, directory string) map[string]any {
	return changesScopeFn(out, directory)
}

func defaultChangesScope(out io.Writer, directory string) map[string]any {
	if directory == "" {
		directory = ConfigDir()
	}
	res, ok := agentUpdateScope(out, "plan", directory)
	if !ok || res.ExitCode != 0 {
		return scopeUnavailable()
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &parsed); err != nil || parsed == nil {
		return scopeUnavailable()
	}
	return parsed
}

// DescribeChangesScope prints a human-readable summary of the computed scope.
func DescribeChangesScope(out io.Writer, scope map[string]any) {
	reason := strVal(scope["reason"])
	if reason == "scope-unavailable" {
		fmt.Fprintln(out, "The installed host agent could not work out the changed files: running the full stack.")
		return
	}
	if reason == "no-applied-record" {
		fmt.Fprintln(out, "No record of a complete update yet, so the changed files cannot be worked out: running the full stack. Later updates can be narrower.")
		return
	}
	changed := intFromAny(scope["changed"])
	if truthy(scope["full"]) {
		unmapped := stringSliceFromAny(scope["unmapped"])
		if len(unmapped) > 0 {
			fmt.Fprintf(out, "%d changed file(s); some need the full stack: %s\n", changed, strings.Join(unmapped, ", "))
		} else {
			fmt.Fprintf(out, "%d changed file(s); some need the full stack.\n", changed)
		}
		return
	}
	steps := stringSliceFromAny(scope["steps"])
	stepText := "none -- nothing on the host changes"
	if len(steps) > 0 {
		stepText = strings.Join(steps, ", ")
	}
	fmt.Fprintf(out, "%d changed file(s). Steps to run: %s.\n", changed, stepText)
}

// RecordAppliedSource records the just-applied source tree via "update-scope record".
func RecordAppliedSource(out io.Writer, directory string) {
	recordAppliedSourceFn(out, directory)
}

func defaultRecordAppliedSource(out io.Writer, directory string) {
	if directory == "" {
		directory = ConfigDir()
	}
	revision, err := GitRevision(SourceDir(), "HEAD")
	if err != nil {
		revision = ""
	}
	res, ok := agentUpdateScope(out, "record", directory, "--revision", revision)
	if !ok {
		fmt.Fprintln(out, "Warning: could not record the applied source (the host agent is unavailable).")
		return
	}
	if res.ExitCode != 0 {
		detail := strings.TrimSpace(res.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(res.Stdout)
		}
		reason := fmt.Sprintf("exit status %d", res.ExitCode)
		if detail != "" {
			lines := strings.Split(detail, "\n")
			reason = lines[len(lines)-1]
		}
		fmt.Fprintf(out, "Warning: could not record the applied source (%s).\n", reason)
	}
}

// UpdateTagsForArgs resolves the playbook tag string for plan or update.
func UpdateTagsForArgs(out io.Writer, component string, uiOnly bool, checkMode bool) (string, error) {
	if component == "" {
		component = "all"
	}
	if uiOnly {
		if component != "all" {
			return "", installerErrorf("--ui-only cannot be combined with --component")
		}
		component = "ui"
	}
	if component == ChangesComponent {
		scope := ChangesScope(out, "")
		DescribeChangesScope(out, scope)
		if truthy(scope["full"]) {
			return UpdateTags, nil
		}
		tags := stringSliceFromAny(scope["tags"])
		if len(tags) == 0 {
			return "status", nil
		}
		return strings.Join(tags, ","), nil
	}
	tags, ok := UpdateComponentTags[component]
	if !ok {
		mode := "update"
		if checkMode {
			mode = "plan"
		}
		return "", installerErrorf("Unsupported %s component: %s", mode, component)
	}
	return tags, nil
}

// PlanArgs holds arguments for "easy-ha-proxy plan".
type PlanArgs struct {
	UIOnly    bool
	Component string
}

// CommandPlan runs check-mode planning for the requested component.
func CommandPlan(ctx *Context, args PlanArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	directory := ConfigDir()
	component := args.Component
	if component == "" {
		component = "all"
	}
	if args.UIOnly {
		component = "ui"
	}
	managedPending := ManagedConfigurationIsPending(directory)
	tags, err := UpdateTagsForArgs(ctx.Stdout, args.Component, args.UIOnly, true)
	if err != nil {
		return err
	}
	var extraVars map[string]any
	if managedPending && component == "all" {
		extraVars = map[string]any{"haproxy_admin_sync_managed_config": "true"}
	}
	if err := RunPlaybook(ctx, tags, PlaybookOptions{CheckMode: true, ExtraVars: extraVars}); err != nil {
		return err
	}
	if managedPending && component != "all" {
		fmt.Fprintln(ctx.Stdout, "Managed configuration is still pending and was not included in this targeted plan. Run 'easy-ha-proxy plan --component all'.")
	}
	return nil
}

// UpdateArgs holds arguments for "easy-ha-proxy update".
type UpdateArgs struct {
	UIOnly                 bool
	AutomaticOS            bool
	RuntimeMaintenance     string
	MaintenanceRevision    string
	MaintenanceUntil       float64
	HasMaintenanceUntil    bool
	Component              string
	NoFetch                bool
	SourceChannel          string
	ImageChannel           string
	ExpectedSourceRevision string
	NoFullFallback         bool
	OrigArgs               []string
}

// CommandUpdate refreshes source (if needed), syncs runtime config, and applies the stack.
func CommandUpdate(ctx *Context, args UpdateArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	component := args.Component
	if component == "" {
		component = "all"
	}
	if args.UIOnly {
		if component != "all" {
			return installerErrorf("--ui-only cannot be combined with --component")
		}
		component = "ui"
	}
	if args.AutomaticOS && component != "os" {
		return installerErrorf("Automatic OS upgrade guards require the os component.")
	}
	runtimeRev := args.RuntimeMaintenance
	windowRev := runtimeRev
	if windowRev == "" {
		windowRev = args.MaintenanceRevision
	}
	if windowRev != "" || args.HasMaintenanceUntil {
		if !args.AutomaticOS || !maintenanceRevRe.MatchString(windowRev) || !args.HasMaintenanceUntil ||
			!(args.MaintenanceUntil > 0 && !math.IsInf(args.MaintenanceUntil, 0) && !math.IsNaN(args.MaintenanceUntil)) {
			return installerErrorf("Runtime maintenance requires automatic OS mode and a valid window lease.")
		}
	}
	expectedRev, err := NormalizeSourceRevision(args.ExpectedSourceRevision)
	if err != nil {
		return err
	}
	sourceChannel := args.SourceChannel
	if sourceChannel == "" {
		configured := strings.TrimSpace(strVal(LoadMetadata("").Value("source_channel")))
		if args.NoFetch && (configured == "github" || configured == "local") {
			sourceChannel = configured
		} else {
			sourceChannel = "github"
		}
	}
	fetchSource := sourceChannel == "github" && !args.NoFetch
	refreshSource := fetchSource && SourceUpdateComponents[component]
	sourceWasRefreshed := os.Getenv(UpdateSourceRefreshedEnv) == "1"
	_ = os.Unsetenv(UpdateSourceRefreshedEnv)

	if expectedRev != "" && sourceChannel != "github" {
		return installerErrorf("An expected source revision can only be used with the GitHub source channel.")
	}
	if expectedRev != "" && !SourceUpdateComponents[component] {
		return installerErrorf("An expected source revision is only valid for a source update component.")
	}

	if refreshSource && !sourceWasRefreshed {
		ProgressPhase(ctx.Stdout, "source")
		if component == "daemons" || component == "services" || component == ChangesComponent {
			fmt.Fprintln(ctx.Stdout, "Updating managed source before the targeted host-service update.")
		}
		updated, err := UpdateManagedSource(ctx.Stdout, expectedRev)
		if err != nil {
			return err
		}
		if updated {
			return ReexecAfterSourceUpdate(ctx.Stdout, args.OrigArgs)
		}
	}
	if sourceWasRefreshed && expectedRev != "" {
		activeRev, err := GitRevision(SourceDir(), "HEAD")
		if err != nil {
			return err
		}
		if activeRev != expectedRev {
			return installerErrorf("The active source does not match the revision approved by the update plan.")
		}
	}

	directory := ConfigDir()
	ProgressPhase(ctx.Stdout, "prepare")
	if err := EnsureSecuritySecrets(ctx.Stdout, directory); err != nil {
		return err
	}
	persistSource := ""
	if !args.NoFetch || args.SourceChannel != "" {
		persistSource = sourceChannel
	}
	if err := PersistDeploymentChannels(ctx.Stdout, ChannelOptions{
		SourceChannel: persistSource,
		ImageChannel:  args.ImageChannel,
		Directory:     directory,
	}); err != nil {
		return err
	}
	managedPending := ManagedConfigurationIsPending(directory)
	if !managedPending {
		if _, err := SyncRuntimeHAProxyConfigToManaged(ctx.Stdout, directory, ""); err != nil {
			return err
		}
		if _, err := SyncRuntimeAutheliaRulesToManaged(ctx.Stdout, directory, ""); err != nil {
			return err
		}
	}
	changesTags := ""
	if component == ChangesComponent {
		scope := ChangesScope(ctx.Stdout, directory)
		DescribeChangesScope(ctx.Stdout, scope)
		if (managedPending || truthy(scope["full"])) && args.NoFullFallback {
			return installerErrorf("These changes need the full stack, which this update was not approved for. Check for updates again.")
		}
		if managedPending {
			fmt.Fprintln(ctx.Stdout, "Managed configuration is pending: running the full stack.")
			component = "all"
		} else if truthy(scope["full"]) {
			component = "all"
		} else {
			tagsList := stringSliceFromAny(scope["tags"])
			if len(tagsList) == 0 {
				changesTags = "status"
			} else {
				changesTags = strings.Join(tagsList, ",")
			}
		}
	}
	if component == "all" {
		switch {
		case sourceWasRefreshed:
			fmt.Fprintln(ctx.Stdout, "Continuing with the refreshed GitHub source.")
		case fetchSource:
			fmt.Fprintln(ctx.Stdout, "Using the current source because managed source refresh was skipped.")
		default:
			fmt.Fprintln(ctx.Stdout, "Using the currently installed local source; GitHub fetch skipped.")
		}
		if err := SyncRuntimeDependencies(ctx.Stdout); err != nil {
			return err
		}
	} else if (component == "daemons" || component == "services") && refreshSource {
		if err := SyncRuntimeDependencies(ctx.Stdout); err != nil {
			return err
		}
	} else if component != "all" && fetchSource {
		fmt.Fprintln(ctx.Stdout, "Source fetch skipped for targeted component update.")
	}

	ProgressPhase(ctx.Stdout, "playbook")
	var tags string
	if changesTags != "" {
		tags = changesTags
	} else if component == "all" {
		tags = UpdateTags
	} else {
		tags, err = UpdateTagsForArgs(ctx.Stdout, component, false, false)
		if err != nil {
			return err
		}
	}

	extraVars := map[string]any{}
	if managedPending && component == "all" {
		extraVars["haproxy_admin_sync_managed_config"] = "true"
	}
	if args.AutomaticOS {
		extraVars["easy_ha_proxy_automatic_os_upgrade"] = true
	}
	if runtimeRev != "" {
		extraVars["easy_ha_proxy_runtime_maintenance_revision"] = runtimeRev
	}
	if windowRev != "" {
		extraVars["easy_ha_proxy_maintenance_revision"] = windowRev
		extraVars["easy_ha_proxy_runtime_maintenance_until"] = args.MaintenanceUntil
	}
	if len(extraVars) == 0 {
		extraVars = nil
	}
	if err := RunPlaybook(ctx, tags, PlaybookOptions{ExtraVars: extraVars}); err != nil {
		return err
	}
	if component == "all" || changesTags != "" {
		RecordAppliedSource(ctx.Stdout, directory)
	}
	if managedPending && component != "all" {
		fmt.Fprintln(ctx.Stdout, "Managed configuration remains pending because a targeted update cannot safely apply the complete stack. Run 'easy-ha-proxy update --component all'.")
	} else {
		if err := MarkInstallationComplete(directory); err != nil {
			return err
		}
	}
	return nil
}

// SetChannelsArgs holds arguments for "easy-ha-proxy set-channels".
type SetChannelsArgs struct {
	ReleaseChannel string
	SourceChannel  string
	Branch         string
	ImageChannel   string
}

// CommandSetChannels persists or displays the deployment channels.
func CommandSetChannels(ctx *Context, args SetChannelsArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if args.ReleaseChannel != "" || args.SourceChannel != "" || args.ImageChannel != "" || args.Branch != "" {
		if err := HoldMaintenanceLock(""); err != nil {
			return err
		}
		if err := PersistDeploymentChannels(ctx.Stdout, ChannelOptions{
			ReleaseChannel: args.ReleaseChannel,
			SourceChannel:  args.SourceChannel,
			ImageChannel:   args.ImageChannel,
			Branch:         args.Branch,
		}); err != nil {
			return err
		}
	}
	metadata := LoadMetadata("")
	source := strVal(metadata.Value("source_channel"))
	if source == "" {
		source = "github"
	}
	branch := strVal(metadata.Value("branch"))
	if branch == "" {
		branch = "main"
	}
	image := strVal(metadata.Value("image_channel"))
	if image == "" {
		image = "latest"
	}
	fmt.Fprintf(ctx.Stdout, "release_channel=%s\n", ReleaseChannelFromSettings(source, branch, image))
	fmt.Fprintf(ctx.Stdout, "source_channel=%s\n", source)
	fmt.Fprintf(ctx.Stdout, "branch=%s\n", branch)
	fmt.Fprintf(ctx.Stdout, "image_channel=%s\n", image)
	return nil
}

// CommandStatus runs the status playbook tag.
func CommandStatus(ctx *Context) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	return RunPlaybook(ctx, "status", PlaybookOptions{})
}

// CommandReboot schedules a pending OS reboot.
func CommandReboot(ctx *Context, assumeYes bool) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	if RebootScheduleIsActive() {
		fmt.Fprintln(ctx.Stdout, T("A reboot is already scheduled; the current session will close."))
		fmt.Fprintln(ctx.Stdout, "EASY_HA_PROXY_REBOOT_SCHEDULED=1")
		return nil
	}
	if !RebootRequired() {
		fmt.Fprintln(ctx.Stdout, T("No reboot is currently required."))
		return nil
	}
	_, err := OfferPendingReboot(ctx, assumeYes)
	return err
}

// LanguageArgs holds arguments for "easy-ha-proxy language".
type LanguageArgs struct {
	Language string
	Apply    bool
}

// CommandLanguage persists and optionally applies the stack language.
func CommandLanguage(ctx *Context, args LanguageArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	directory := ConfigDir()
	varsPath := filepath.Join(directory, "vars.yml")
	autPath := filepath.Join(directory, "authelia.yml")
	metaPath := filepath.Join(directory, "metadata.yml")
	for _, p := range []string{varsPath, autPath, metaPath} {
		if !isRegularFile(p) {
			return installerErrorf("Managed configuration file is missing: %s", p)
		}
	}
	metadata, err := LoadYAMLMapping(metaPath)
	if err != nil {
		return err
	}
	current := strings.ToLower(strVal(metadata.Value("installer_language")))
	if current == "" {
		current = "en"
	}
	language := args.Language
	if language == "" {
		fmt.Fprintf(ctx.Stdout, "Current language / Текущий язык: %s\n", current)
		fmt.Fprintln(ctx.Stdout, "  1) English\n  2) Русский")
		choice, err := ctx.readLine("Language / Язык [1]: ")
		if err != nil {
			return err
		}
		choice = strings.ToLower(strings.TrimSpace(choice))
		switch choice {
		case "2", "ru", "rus", "рус", "русский":
			language = "ru"
		default:
			language = "en"
		}
	}
	variables, err := LoadYAMLMapping(varsPath)
	if err != nil {
		return err
	}
	authelia, err := LoadYAMLMapping(autPath)
	if err != nil {
		return err
	}
	if _, err := BackupConfiguration(ctx.Stdout, directory); err != nil {
		return err
	}
	variables.Set("haproxy_admin_default_language", language)
	authelia.Set("authelia_notification_language", language)
	rootDomain := strVal(variables.Value("root_domain"))
	if rootDomain == "" {
		rootDomain = "Authelia"
	}
	if language == "ru" {
		authelia.Set("mail_subject", fmt.Sprintf("[%s] Уведомление безопасности", rootDomain))
	} else {
		authelia.Set("mail_subject", fmt.Sprintf("[%s] Security notification", rootDomain))
	}
	metadata.Set("installer_language", language)
	metadata.Set("language_updated_at", time.Now().UTC().Format(time.RFC3339Nano))

	if err := WriteYAML(varsPath, variables, 0o600); err != nil {
		return err
	}
	if err := WriteYAML(autPath, authelia, 0o600); err != nil {
		return err
	}
	if err := WriteYAML(metaPath, metadata, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(ctx.Stdout, "Language saved: %s. This setting controls the assistant, the default web UI language, and Authelia notification templates.\n", language)
	if args.Apply {
		if err := RunPlaybook(ctx, LanguageTags, PlaybookOptions{
			Directory: directory,
			ExtraVars: map[string]any{"haproxy_admin_force_recreate": "true"},
		}); err != nil {
			return err
		}
		fmt.Fprintln(ctx.Stdout, "Language applied to the complete stack.")
	} else {
		fmt.Fprintf(ctx.Stdout, "Run 'easy-ha-proxy language --language %s --apply' to apply it.\n", language)
	}
	return nil
}

// AgentKnows probes whether the binary at agent supports subcommand command.
func AgentKnows(agent, command string) bool {
	if !isRegularFile(agent) {
		return false
	}
	res := runSubprocess(agent, command)
	if res.Err != nil {
		return false
	}
	return strings.Contains(res.Stderr, "easy-ha-proxy-agent "+command)
}

// FullBackupCommand returns the argv prefix for "full-backup".
func FullBackupCommand(out io.Writer) ([]string, error) {
	agent := agentBinary
	if !AgentKnows(agentBinary, "full-backup") {
		var err error
		agent, err = FetchRunner(out, ConfigDir())
		if err != nil {
			return nil, err
		}
	}
	return []string{agent, "full-backup"}, nil
}

// BackupFullArgs holds arguments for "easy-ha-proxy backup-full".
type BackupFullArgs struct {
	OutputDir  string
	IncludeSSH *bool
	NoQuiesce  bool
}

// CommandBackupFull invokes "easy-ha-proxy-agent full-backup backup".
func CommandBackupFull(ctx *Context, args BackupFullArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	base, err := FullBackupCommand(ctx.Stdout)
	if err != nil {
		return err
	}
	cmd := append(base, "backup")
	if args.OutputDir != "" {
		cmd = append(cmd, "--output-dir", args.OutputDir)
	}
	includeSSH := false
	if args.IncludeSSH == nil {
		includeSSH, err = ctx.promptBool("Include SSH host/private/authorized keys in the encrypted backup", false)
		if err != nil {
			return err
		}
	} else {
		includeSSH = *args.IncludeSSH
	}
	if includeSSH {
		cmd = append(cmd, "--include-ssh")
	}
	if args.NoQuiesce {
		cmd = append(cmd, "--no-quiesce")
	}
	return runCommand(ctx.Stdout, cmd, nil)
}

// RestoreFullArgs holds arguments for "easy-ha-proxy restore-full".
type RestoreFullArgs struct {
	Archive     string
	Mode        string
	RestoreSSH  bool
	SkipSSH     bool
	AllowLegacy bool
	Apply       bool
}

// CommandRestoreFull invokes "easy-ha-proxy-agent full-backup restore".
func CommandRestoreFull(ctx *Context, args RestoreFullArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	base, err := FullBackupCommand(ctx.Stdout)
	if err != nil {
		return err
	}
	mode := args.Mode
	if mode == "" {
		mode = "auto"
	}
	cmd := append(base, "restore", args.Archive, "--mode", mode, "--replace-managed")
	if args.RestoreSSH {
		cmd = append(cmd, "--restore-ssh")
	}
	if args.SkipSSH {
		cmd = append(cmd, "--skip-ssh")
	}
	if args.AllowLegacy {
		cmd = append(cmd, "--allow-legacy-v1")
	}
	if args.Apply {
		cmd = append(cmd, "--apply")
	}
	return runCommand(ctx.Stdout, cmd, nil)
}

// ApplyRestoredArgs holds arguments for "easy-ha-proxy apply-restored".
type ApplyRestoredArgs struct {
	Offline bool
	Scope   string
}

// CommandApplyRestored reconciles a host after a backup restore.
func CommandApplyRestored(ctx *Context, args ApplyRestoredArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	directory := ConfigDir()
	scope := args.Scope
	if scope == "" {
		scope = "full"
	}
	if err := EnsureSecuritySecrets(ctx.Stdout, directory); err != nil {
		return err
	}
	skipTags := ""
	if args.Offline {
		skipTags = RestoreSkipTags
	}
	if scope == "config" {
		extraVars := map[string]any{"haproxy_admin_sync_managed_config": "true"}
		if args.Offline {
			extraVars["easy_ha_proxy_offline_restore"] = "true"
		}
		if err := RunPlaybook(ctx, RestoreConfigTags, PlaybookOptions{
			Directory: directory,
			ExtraVars: extraVars,
			SkipTags:  skipTags,
		}); err != nil {
			return err
		}
		fmt.Fprintln(ctx.Stdout, "\nRestored site configuration reconciled successfully.")
		return nil
	}
	if args.Offline {
		if err := OfflineRestoreImagePreflight(directory, "", nil); err != nil {
			return err
		}
	}
	if _, err := SyncRuntimeAutheliaRulesToManaged(ctx.Stdout, directory, ""); err != nil {
		return err
	}
	extraVars := map[string]any{
		"authelia_force_restart":            "true",
		"haproxy_admin_force_recreate":      "true",
		"haproxy_admin_sync_managed_config": "true",
	}
	if args.Offline {
		extraVars["easy_ha_proxy_offline_restore"] = "true"
	}
	if err := RunPlaybook(ctx, RestoreTags, PlaybookOptions{
		Directory: directory,
		ExtraVars: extraVars,
		SkipTags:  skipTags,
	}); err != nil {
		return err
	}
	fmt.Fprintln(ctx.Stdout, "\nRestored easy-ha-proxy installation reconciled successfully.")
	return nil
}

func splitTags(tags string) []string {
	var out []string
	for _, t := range strings.Split(tags, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}

func stringSliceFromAny(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if item != nil {
				out = append(out, fmt.Sprint(item))
			}
		}
		return out
	default:
		return nil
	}
}

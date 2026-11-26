package fullbackup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type restoreOptions struct {
	archive         string
	mode            string
	scope           string
	restoreSSH      bool
	skipSSH         bool
	apply           bool
	replaceManaged  bool
	passphraseStdin bool
	yes             bool
}

type keyFile struct {
	lines    []string
	uid, gid int
}

// readRegularNoFollow reads a regular file without following a link; ok
// false when it is missing, a link or not regular.
func readRegularNoFollow(p string) (string, *syscall.Stat_t, bool) {
	if isSymlink(p) {
		return "", nil, false
	}
	f, err := os.OpenFile(p, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return "", nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return "", nil, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", nil, false
	}
	return string(raw), fi.Sys().(*syscall.Stat_t), true
}

func nonEmptyLines(text string) []string {
	var lines []string
	for _, line := range splitLines(text) {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func currentAuthorizedKeys() map[string]keyFile {
	saved := map[string]keyFile{}
	candidates := []string{rootAuthorizedKeys}
	more, _ := filepath.Glob(authorizedKeysGlob)
	candidates = append(candidates, more...)
	for _, p := range candidates {
		text, st, ok := readRegularNoFollow(p)
		if !ok {
			continue
		}
		saved[p] = keyFile{nonEmptyLines(text), int(st.Uid), int(st.Gid)}
	}
	return saved
}

// mergeAuthorizedKeys keeps the keys that could log in before the restore
// beside the restored ones.
var mergeAuthorizedKeys = func(saved map[string]keyFile) error {
	for _, p := range sortedKeyFiles(saved) {
		old := saved[p]
		if isSymlink(p) || isSymlink(filepath.Dir(p)) {
			return backupErrorf("Refusing to merge symlinked authorized_keys: %s", p)
		}
		var restored []string
		if text, _, ok := readRegularNoFollow(p); ok {
			restored = nonEmptyLines(text)
		}
		seen := map[string]bool{}
		var merged []string
		for _, line := range append(restored, old.lines...) {
			if !seen[line] {
				seen[line] = true
				merged = append(merged, line)
			}
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(p), ".authorized_keys.*.tmp")
		if err != nil {
			return err
		}
		err = func() error {
			if _, err := tmp.WriteString(strings.Join(merged, "\n") + "\n"); err != nil {
				return err
			}
			if err := tmp.Chmod(0o600); err != nil {
				return err
			}
			if err := tmp.Chown(old.uid, old.gid); err != nil {
				return err
			}
			return tmp.Sync()
		}()
		closeErr := tmp.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), p)
		}
		if err != nil {
			_ = os.Remove(tmp.Name())
			return err
		}
	}
	return nil
}

func sortedKeyFiles(saved map[string]keyFile) []string {
	set := map[string]bool{}
	for p := range saved {
		set[p] = true
	}
	return sortedKeys(set)
}

// disableRestoredRuntimeFirewallState keeps but disables the restored
// iptables-persistent snapshots: on Docker hosts they hold the source
// machine's DOCKER chains, bridges and subnets, and restored on a new host
// they can wipe its NAT chains.
var disableRestoredRuntimeFirewallState = func() ([]string, error) {
	var disabled []string
	if !lexists(iptablesDir) {
		return nil, nil
	}
	timestamp := utcStamp()
	for _, name := range []string{"rules.v4", "rules.v6"} {
		source := filepath.Join(iptablesDir, name)
		if !lexists(source) {
			continue
		}
		target := filepath.Join(iptablesDir, name+".restored-disabled."+timestamp)
		for suffix := 1; lexists(target); suffix++ {
			target = filepath.Join(iptablesDir, fmt.Sprintf("%s.restored-disabled.%s.%d", name, timestamp, suffix))
		}
		if err := os.Rename(source, target); err != nil {
			return disabled, err
		}
		disabled = append(disabled, target)
		fmt.Printf("Disabled restored runtime firewall state: %s -> %s\n", source, target)
	}
	return disabled, nil
}

// createPreRestoreBackup is a short-lived root-only snapshot of what a
// restore replaces. Unlike exported archives it keeps runtime state, so a
// failed restore can be reversed exactly; "" when nothing exists.
var createPreRestoreBackup = func(paths []string) (string, error) {
	var existing []string
	for _, p := range paths {
		if lexists(p) {
			existing = append(existing, p)
		}
	}
	if len(existing) == 0 {
		return "", nil
	}
	destination := filepath.Join(DefaultBackupRoot, fmt.Sprintf("pre-restore-%s-%d", utcStampMicro(), os.Getpid()))
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return "", err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return "", err
	}
	archive := filepath.Join(destination, "previous-state.tar.gz")
	if _, err := createPayload(archive, existing, relativePaths(effectiveRestorePreservedPaths())); err != nil {
		return "", err
	}
	return archive, nil
}

var cleanupPreRestoreBackup = func(archive string) {
	if archive == "" {
		return
	}
	_ = os.Remove(archive)
	_ = os.Remove(filepath.Dir(archive))
}

// managedPathsApparentUsage is apparent bytes, members and filesystems,
// links not followed, for a conservative capacity check. Paths that vanish
// are harmless (services rotate files); any other error aborts before
// anything stops.
var managedPathsApparentUsage = func(paths []string) (int64, int64, map[uint64]bool, error) {
	var bytes, members int64
	devices := map[uint64]bool{}
	preserved := effectiveRestorePreservedPaths()
	type identity struct{ dev, ino uint64 }
	seen := map[identity]bool{}
	var visit func(string) error
	visit = func(value string) error {
		if pathIsPreserved(value, preserved) {
			return nil
		}
		fi, err := os.Lstat(value)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return backupErrorf("Cannot inspect managed path before restore: %s: %v", value, err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		id := identity{uint64(st.Dev), uint64(st.Ino)}
		if seen[id] {
			return nil
		}
		seen[id] = true
		devices[id.dev] = true
		members++
		if fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
			if fi.Size() > 0 {
				bytes += fi.Size()
			}
		}
		if !fi.IsDir() {
			return nil
		}
		entries, err := os.ReadDir(value)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return backupErrorf("Cannot inspect managed directory before restore: %s: %v", value, err)
		}
		for _, entry := range entries {
			if err := visit(filepath.Join(value, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	unique := map[string]bool{}
	for _, p := range paths {
		unique[p] = true
	}
	for _, p := range sortedKeys(unique) {
		if err := visit(p); err != nil {
			return 0, 0, nil, err
		}
	}
	return bytes, members, devices, nil
}

// preflightRestoreSpace verifies room for the extraction and for an
// automatic rollback copy.
var preflightRestoreSpace = func(manifest map[string]any, rollbackPaths []string, replaceManaged, restoreSSH bool) error {
	payloadBytes, ok := integer(manifest["payload_expanded_bytes"])
	if !ok {
		return backupErrorf("Backup inspection did not report core expanded size.")
	}
	sshBytes, sshOK := integer(manifest["ssh_payload_expanded_bytes"])
	if restoreSSH && !sshOK {
		return backupErrorf("Backup inspection did not report SSH expanded size.")
	}
	candidate := payloadBytes
	if restoreSSH {
		candidate += sshBytes
	}
	current, members, devices, err := managedPathsApparentUsage(rollbackPaths)
	if err != nil {
		return err
	}
	var rollbackBytes int64
	if members > 0 {
		rollbackBytes = current + members*limit.rollbackPerMember + limit.rollbackBase
	}
	rootPath, err := existingAncestor(apparentRoot)
	if err != nil {
		return err
	}
	backupPath, err := existingAncestor(DefaultBackupRoot)
	if err != nil {
		return err
	}
	rootDevice, err := deviceOf(rootPath)
	if err != nil {
		return err
	}
	backupDevice, err := deviceOf(backupPath)
	if err != nil {
		return err
	}
	rootUsage, err := diskUsage(rootPath)
	if err != nil {
		return err
	}
	backupUsage, err := diskUsage(backupPath)
	if err != nil {
		return err
	}
	// Exact replacement can reclaim the current managed bytes before the
	// extraction, but only when every path lives on the root filesystem.
	var reclaimable int64
	if replaceManaged && len(devices) == 1 && devices[rootDevice] {
		reclaimable = current
	}
	growth := candidate - reclaimable
	if growth < 0 {
		growth = 0
	}
	if rootDevice == backupDevice {
		if required := rollbackBytes + growth + limit.restoreMinFree; rootUsage.free < required {
			return backupErrorf("Not enough free space for restore and automatic rollback on %s: need %s, have %s.",
				rootPath, formatBytes(required), formatBytes(rootUsage.free))
		}
		return nil
	}
	if required := growth + limit.restoreMinFree; rootUsage.free < required {
		return backupErrorf("Not enough free space for restore on %s: need %s, have %s.", rootPath,
			formatBytes(required), formatBytes(rootUsage.free))
	}
	if rollbackBytes > 0 {
		if required := rollbackBytes + limit.restoreMinFree; backupUsage.free < required {
			return backupErrorf("Not enough free space for the automatic rollback archive on %s: need %s, have %s.",
				backupPath, formatBytes(required), formatBytes(backupUsage.free))
		}
	}
	return nil
}

var normalizeRestoredConfigPermissions = func() error {
	config := managedConfigDir()
	if isSymlink(config) || !isDir(config) {
		return nil
	}
	if err := os.Chmod(config, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(config)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(config, entry.Name())
		if isSymlink(child) || !isFile(child) {
			continue
		}
		if err := os.Chmod(child, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// restoreStage runs one restore stage and keeps its name in the error.
var restoreStage = func(name string, argv []string, env []string, capture bool) error {
	_, err := run(argv, runOptions{check: true, capture: capture, env: env})
	var failed *CommandError
	if errors.As(err, &failed) {
		detail := ""
		if capture {
			output := strings.TrimSpace(failed.Stderr)
			if output == "" {
				output = strings.TrimSpace(failed.Stdout)
			}
			if output != "" {
				if len(output) > 2000 {
					output = output[len(output)-2000:]
				}
				detail = ": " + output
			}
		}
		return backupErrorf("%s failed with exit code %d%s", name, failed.Code, detail)
	}
	return err
}

func restoreControlPlaneSource() string {
	configured := os.Getenv("EASY_HA_PROXY_SOURCE_DIR")
	if configured == "" {
		configured = managedSource
	}
	if resolved, err := filepath.EvalSymlinks(configured); err == nil {
		configured = resolved
	}
	abs, _ := filepath.Abs(configured)
	return abs
}

// preflightRestoreControlPlane verifies the installed offline restore
// controller before anything is changed.
var preflightRestoreControlPlane = func() error {
	source := restoreControlPlaneSource()
	var missing []string
	for _, rel := range []string{"install.sh", "install-local.sh", "install-remote.sh", "easy-ha-proxy-helper.sh",
		"installer/easy-ha-proxy", "installer/agent-fetch.sh", "ansible/easy-ha-proxy.yml"} {
		if p := filepath.Join(source, rel); !isFile(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return backupErrorf("Restore control-plane preflight failed: missing trusted source files: %s", strings.Join(missing, ", "))
	}
	agent := os.Getenv("EASY_HA_PROXY_AGENT")
	if agent == "" {
		agent = "/usr/local/sbin/easy-ha-proxy-agent"
	}
	if !executable(agent) {
		return backupErrorf("Restore control-plane preflight failed: missing prepared executables: %s", agent)
	}
	// The installed agent runs the playbook that reconciles the restored
	// host; one older than "apply playbook" would have to be fetched, and a
	// restore must not depend on the network.
	return restoreStage("Restore control-plane installer check",
		[]string{agent, "apply", "playbook", "--supported", "--tags", "never"}, nil, true)
}

// recoverySourceArchivePath is a collision-safe diagnostic path beside the
// managed source.
func recoverySourceArchivePath(managed, timestamp string, pid int) (string, error) {
	if timestamp == "" {
		timestamp = utcStampMicro()
	}
	base := filepath.Join(filepath.Dir(managed), fmt.Sprintf("source.from-backup.%s.%d", timestamp, pid))
	for counter := 0; counter < 10_000; counter++ {
		candidate := base
		if counter > 0 {
			candidate = fmt.Sprintf("%s.%d", base, counter)
		}
		if !lexists(candidate) {
			return candidate, nil
		}
	}
	return "", backupErrorf("Cannot allocate a diagnostic source archive path beside %s.", managed)
}

// activateRecoverySource puts the controller's recovery source back over the
// source the archive brought: the host keeps its software, the archive gives
// its data.
var activateRecoverySource = func() (string, error) {
	managed := managedSource
	configured := os.Getenv("EASY_HA_PROXY_SOURCE_DIR")
	if configured == "" {
		return managed, nil
	}
	recovery, _ := filepath.Abs(configured)
	if resolved, err := filepath.EvalSymlinks(recovery); err == nil {
		recovery = resolved
	}
	managedResolved := managed
	if resolved, err := filepath.EvalSymlinks(managed); err == nil {
		managedResolved = resolved
	}
	if recovery == managedResolved {
		return managed, nil
	}
	var missing []string
	for _, rel := range []string{"install-local.sh", "installer/easy-ha-proxy", "installer/agent-fetch.sh", "ansible/easy-ha-proxy.yml"} {
		if p := filepath.Join(recovery, rel); !isFile(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return "", backupErrorf("Recovery source is incomplete: %s", strings.Join(missing, ", "))
	}
	if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
		return "", err
	}
	staged := filepath.Join(filepath.Dir(managed), fmt.Sprintf(".source.restore.next.%d", os.Getpid()))
	archived, err := recoverySourceArchivePath(managed, "", os.Getpid())
	if err != nil {
		return "", err
	}
	if lexists(staged) {
		return "", backupErrorf("Recovery source staging path already exists: %s", staged)
	}
	if err := copyTreeKeepingLinks(recovery, staged); err != nil {
		return "", err
	}
	if _, err := run([]string{"chown", "-R", "root:root", staged}, runOptions{check: true}); err != nil {
		return "", err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return "", err
	}
	moved := false
	if lexists(managed) {
		if err := os.Rename(managed, archived); err != nil {
			_ = os.RemoveAll(staged)
			return "", err
		}
		moved = true
	}
	if err := os.Rename(staged, managed); err != nil {
		_ = os.RemoveAll(staged)
		if moved && lexists(archived) && !lexists(managed) {
			_ = os.Rename(archived, managed)
		}
		return "", err
	}
	os.Setenv("EASY_HA_PROXY_SOURCE_DIR", managed)
	fmt.Printf("Recovery source activated: %s\n", managed)
	if moved {
		fmt.Printf("Source restored from backup preserved at: %s\n", archived)
	}
	return managed, nil
}

var reconcileRestoredHost = func(prepareEntrypoints bool) error {
	source, err := activateRecoverySource()
	if err != nil {
		return err
	}
	if prepareEntrypoints {
		installer := filepath.Join(source, "install-local.sh")
		if !isFile(installer) {
			return backupErrorf("Restored source does not contain install-local.sh.")
		}
		env := append(os.Environ(), "EASY_HA_PROXY_USE_EXISTING_SOURCE=true")
		if err := restoreStage("Offline restore entrypoint preparation",
			[]string{"bash", installer, "--prepare-only", "--skip-bootstrap-dependencies"}, env, false); err != nil {
			return err
		}
	}
	command := []string{"/usr/local/bin/easy-ha-proxy", "apply-restored"}
	if os.Getenv(offlineRestoreEnv) == "1" {
		command = append(command, "--offline")
	}
	return restoreStage("Restored host reconciliation", command, nil, false)
}

var reconcileRestoredConfiguration = func() error {
	command := []string{"/usr/local/bin/easy-ha-proxy", "apply-restored", "--scope", "config"}
	if os.Getenv(offlineRestoreEnv) == "1" {
		command = append(command, "--offline")
	}
	return restoreStage("Restored site configuration reconciliation", command, nil, false)
}

// removeManagedState deletes the current managed state by the code-owned
// paths, never the manifest's.
var removeManagedState = func(includeSSH bool) error { return removePaths(managedStatePaths(includeSSH)) }

// restorePreviousState puts the pre-restore snapshot back exactly after a
// failed candidate.
var restorePreviousState = func(rollback string, restoreSSH, apply bool) error {
	if err := validateRollbackPayload(rollback, restoreSSH); err != nil {
		return err
	}
	if err := removeManagedState(restoreSSH); err != nil {
		return err
	}
	if err := extractPayload(rollback, nil); err != nil {
		return err
	}
	_, _ = run([]string{"systemctl", "try-restart", "rsyslog.service"}, runOptions{})
	if err := normalizeRestoredConfigPermissions(); err != nil {
		return err
	}
	if apply {
		// The candidate already validated the installed controller and
		// prepared the entrypoints; preparing again could turn one
		// environmental failure into a false rollback failure.
		return reconcileRestoredHost(false)
	}
	return nil
}

func restoreConfigScope(o restoreOptions, manifest map[string]any, payload string) error {
	fmt.Println("\nConfiguration restore plan (sites and certificates only):")
	fmt.Printf("  archive host: %s\n", manifestText(manifest, "hostname"))
	fmt.Printf("  created:      %s\n", manifestText(manifest, "created_at"))
	fmt.Printf("  paths:        %s\n", strings.Join(configScopePaths, ", "))
	fmt.Println("  untouched:    managed source, systemd units, secrets, Authelia, SSH")
	if !o.yes && strings.TrimSpace(input("Type RESTORE to continue: ")) != "RESTORE" {
		return backupErrorf("Restore cancelled.")
	}
	members, err := configScopeMembers(payload)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return backupErrorf("The archive contains no site or certificate payload for a configuration-scope restore.")
	}
	if o.apply {
		if err := preflightRestoreControlPlane(); err != nil {
			return err
		}
	}
	// Which of the fixed roots existed is part of the previous state too: a
	// root the failed attempt created used to survive a rollback.
	var rollbackPaths []string
	for _, p := range configScopePaths {
		if lexists(p) {
			rollbackPaths = append(rollbackPaths, p)
		}
	}
	rollback, err := createPreRestoreBackup(rollbackPaths)
	if err != nil {
		return err
	}
	if rollback != "" {
		fmt.Printf("Pre-restore rollback archive: %s\n", rollback)
	}
	stop := catchInterrupt()
	restoreErr := func() error {
		defer stop()
		if err := extractPayload(payload, members); err != nil {
			return err
		}
		if err := checkInterrupt(); err != nil {
			return err
		}
		if err := normalizeRestoredConfigPermissions(); err != nil {
			return err
		}
		if o.apply {
			if err := reconcileRestoredConfiguration(); err != nil {
				return err
			}
		}
		return checkInterrupt()
	}()
	if restoreErr == nil {
		cleanupPreRestoreBackup(rollback)
		fmt.Println("\nSite configuration and certificates restored successfully.")
		if o.apply {
			fmt.Println("The restored configuration was applied successfully.")
		} else {
			fmt.Println("Run 'sudo easy-ha-proxy apply-restored --scope config' to apply it.")
		}
		return nil
	}
	if rollback == "" {
		// None of the roots existed: the previous state is their absence.
		if err := removePaths(configScopePaths); err != nil {
			return backupErrorf("Configuration restore failed, and removing what it had written also failed: %v. Restore error: %v",
				err, restoreErr)
		}
		return backupErrorf("Configuration restore failed; none of its paths existed before, and what it had written was "+
			"removed again. Restore error: %v", restoreErr)
	}
	rollbackErr := func() error {
		if err := validateRollbackPayload(rollback, false); err != nil {
			return err
		}
		// Every fixed root: the archive brings back the ones that existed.
		if err := removePaths(configScopePaths); err != nil {
			return err
		}
		if err := extractPayload(rollback, nil); err != nil {
			return err
		}
		if err := normalizeRestoredConfigPermissions(); err != nil {
			return err
		}
		if o.apply {
			return reconcileRestoredConfiguration()
		}
		return nil
	}()
	if rollbackErr != nil {
		return backupErrorf("Configuration restore failed and automatic rollback also failed. Restore error: %v. "+
			"Rollback archive: %s. Rollback error: %v", restoreErr, rollback, rollbackErr)
	}
	cleanupPreRestoreBackup(rollback)
	return backupErrorf("Configuration restore failed; the previous configuration was restored automatically. Restore error: %v",
		restoreErr)
}

func manifestText(manifest map[string]any, key string) string {
	if value, ok := manifest[key]; ok && value != nil {
		return fmt.Sprint(value)
	}
	return "unknown"
}

func restoreBackup(o restoreOptions) error {
	if err := requireRoot(); err != nil {
		return err
	}
	archive := resolveArchive(o.archive)
	if err := verifyEncryptedArchive(archive); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "easy-ha-proxy-restore.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	opened, err := openBackupArchive(archive, work, o.passphraseStdin)
	if err != nil {
		return err
	}
	manifest := opened.manifest
	installed := isFile(filepath.Join(managedConfigDir(), "metadata.yml"))
	mode := o.mode
	if mode == "auto" {
		mode = "fresh"
		if installed {
			mode = "overlay"
		}
	}
	if mode == "fresh" && installed {
		return backupErrorf("Fresh restore refuses to overwrite an installed server.")
	}
	if mode == "overlay" && !installed {
		return backupErrorf("Overlay restore requires an existing managed installation.")
	}
	if o.scope == "config" {
		if !installed {
			return backupErrorf("Configuration-scope restore requires an installed server.")
		}
		if o.restoreSSH {
			return backupErrorf("SSH keys are not part of a configuration-scope restore.")
		}
		return restoreConfigScope(o, manifest, opened.payload)
	}
	restoreSSH := false
	if opened.sshPayload != "" && !o.skipSSH {
		restoreSSH = o.restoreSSH
		if !restoreSSH {
			answer := strings.ToLower(strings.TrimSpace(input("Restore archived SSH host/private/authorized keys? [y/N]: ")))
			restoreSSH = answer == "y" || answer == "yes" || answer == "д" || answer == "да"
		}
	}
	fmt.Println("\nFull restore plan:")
	fmt.Printf("  archive host: %s\n", manifestText(manifest, "hostname"))
	fmt.Printf("  created:      %s\n", manifestText(manifest, "created_at"))
	fmt.Printf("  mode:         %s\n", mode)
	managedText := "overlay"
	if o.replaceManaged {
		managedText = "replace exactly"
	}
	fmt.Printf("  managed state: %s\n", managedText)
	sshText := "keep current"
	if restoreSSH {
		sshText = "restore"
	}
	fmt.Printf("  SSH keys:     %s\n", sshText)
	if !o.yes && strings.TrimSpace(input("Type RESTORE to continue: ")) != "RESTORE" {
		return backupErrorf("Restore cancelled.")
	}
	if o.apply {
		// A web restore runs inside the hardened backup broker, where APT
		// cannot switch to the _apt uid: the installed Python and agent are
		// verified before services stop, a snapshot is taken or a path is
		// replaced, so the destructive phase stays offline.
		if err := preflightRestoreControlPlane(); err != nil {
			return err
		}
	}
	savedKeys := map[string]keyFile{}
	if restoreSSH {
		savedKeys = currentAuthorizedKeys()
	}
	// The rollback set comes from the code-owned allowlist and its capacity
	// is verified before any service stops or file changes.
	rollbackPaths := managedStatePaths(restoreSSH)
	if err := preflightRestoreSpace(manifest, rollbackPaths, o.replaceManaged, restoreSSH); err != nil {
		return err
	}
	q := newQuiesce(true, true)
	if err := q.enter(); err != nil {
		return err
	}
	rollback, err := func() (string, error) {
		defer q.exit()
		// Everything managed now, from the trusted allowlist: the archive's
		// manifest never authorizes what is read, removed or restored here.
		rollback, err := createPreRestoreBackup(rollbackPaths)
		if err != nil {
			return "", err
		}
		if rollback != "" {
			fmt.Printf("Pre-restore rollback archive: %s\n", rollback)
		}
		stop := catchInterrupt()
		restoreErr := func() error {
			defer stop()
			if o.replaceManaged {
				if err := removePaths(rollbackPaths); err != nil {
					return err
				}
			}
			if err := extractPayload(opened.payload, nil); err != nil {
				return err
			}
			if _, err := installRestoredMetrics(); err != nil {
				return err
			}
			// The extraction replaced /var/log/haproxy.log; rsyslog writes to
			// the old inode until restarted.
			_, _ = run([]string{"systemctl", "try-restart", "rsyslog.service"}, runOptions{})
			if _, err := disableRestoredRuntimeFirewallState(); err != nil {
				return err
			}
			if restoreSSH {
				if err := extractPayload(opened.sshPayload, nil); err != nil {
					return err
				}
				if err := mergeAuthorizedKeys(savedKeys); err != nil {
					return err
				}
			}
			if err := normalizeRestoredConfigPermissions(); err != nil {
				return err
			}
			if err := checkInterrupt(); err != nil {
				return err
			}
			if o.apply {
				// Reconciliation ends with a status check that expects the
				// quiesced timers to be active again.
				q.resumeUnits()
				if err := reconcileRestoredHost(true); err != nil {
					return err
				}
			}
			return checkInterrupt()
		}()
		if restoreErr == nil {
			return rollback, nil
		}
		if rollback == "" {
			return "", backupErrorf("Restore failed and no previous managed state was available for automatic rollback: %v", restoreErr)
		}
		q.resumeUnits()
		if err := restorePreviousState(rollback, restoreSSH, o.apply && installed); err != nil {
			return "", backupErrorf("Restore failed and automatic rollback also failed. Restore error: %v. Rollback archive: %s. "+
				"Rollback error: %v", restoreErr, rollback, err)
		}
		cleanupPreRestoreBackup(rollback)
		return "", backupErrorf("Restore failed; the previous managed state was restored automatically. Restore error: %v", restoreErr)
	}()
	if err != nil {
		return err
	}
	cleanupPreRestoreBackup(rollback)
	fmt.Println("\nFiles restored successfully.")
	if o.apply {
		fmt.Println("The restored host was reconciled successfully.")
	} else {
		fmt.Println("Run 'sudo easy-ha-proxy apply-restored' to reconcile the restored host.")
	}
	return nil
}

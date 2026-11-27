package fullbackup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// catchInterrupt turns Ctrl+C into an error while a restore changes the
// host, so it still rolls back; outside that window Ctrl+C ends the run.
func catchInterrupt() func() {
	interrupted.Store(false)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			interrupted.Store(true)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(signals)
		close(done)
	}
}

// fqdn is socket.getfqdn(): the first name of this host's address that has
// a dot, else the host name.
func fqdn() string {
	host, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return host
	}
	names, err := net.LookupAddr(addrs[0])
	if err != nil || len(names) == 0 {
		return host
	}
	for _, name := range names {
		if name = strings.TrimSuffix(name, "."); strings.Contains(name, ".") {
			return name
		}
	}
	return strings.TrimSuffix(names[0], ".")
}

func machine() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Machine[:])
}

// marshalPython is JSON without HTML escaping (Python's ensure_ascii=False).
func marshalPython(v any, indent bool) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func writeJSON(p string, data map[string]any) error {
	text, err := marshalPython(data, true)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(text+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

// compactManifestJSON is the manifest on one line with sorted keys, as the
// brokers parse it from the output.
func compactManifestJSON(manifest map[string]any) string {
	text, _ := marshalPython(manifest, false)
	return text
}

type backupOptions struct {
	outputDir       string
	includeSSH      bool
	quiesce         bool
	passphraseStdin bool
}

func utcStamp() string { return time.Now().UTC().Format("20060102T150405Z") }

func utcStampMicro() string {
	now := time.Now().UTC()
	return now.Format("20060102T150405") + fmt.Sprintf("%06dZ", now.Nanosecond()/1000)
}

func createBackup(o backupOptions) (string, error) {
	if err := requireRoot(); err != nil {
		return "", err
	}
	if !which("openssl") || !which("tar") {
		return "", backupErrorf("openssl and tar are required.")
	}
	timestamp := utcStamp()
	root := o.outputDir
	if root == "" {
		root = DefaultBackupRoot
	}
	backupDir := filepath.Join(root, "full-"+timestamp)
	if err := os.MkdirAll(filepath.Dir(backupDir), 0o755); err != nil {
		return "", err
	}
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		return "", err
	}
	encrypted := filepath.Join(backupDir, "easy-ha-proxy-full-"+timestamp+".tar.gz.enc")
	core := existingPaths(corePaths, coreGlobs)
	var ssh []string
	if o.includeSSH {
		ssh = sshPaths()
	}
	if !isFile(filepath.Join(managedConfigDir(), "metadata.yml")) {
		return "", backupErrorf("A managed easy-ha-proxy installation was not found.")
	}
	password, err := readPassphrase(true, o.passphraseStdin)
	if err != nil {
		return "", err
	}
	work, err := os.MkdirTemp("", "easy-ha-proxy-backup.")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	required, err := configuredPositiveLimit("EASY_HA_PROXY_BACKUP_MIN_TMP_FREE_BYTES", 64<<20)
	if err != nil {
		return "", err
	}
	free, err := diskUsage(work)
	if err != nil {
		return "", err
	}
	if free.free < required {
		return "", backupErrorf("Not enough temporary disk space to stage the backup: need %s, have %s.",
			formatBytes(required), formatBytes(free.free))
	}
	payload := filepath.Join(work, "payload.tar.gz")
	sshPayload := filepath.Join(work, "ssh.tar.gz")
	// Under /var/lib/easy-ha-proxy, so the archive picks it up from there.
	metrics := snapshotMetrics(metricsDatabase, metricsSnapshot)
	if metrics["included"] != true {
		fmt.Printf("Monitoring history is not included: %v.\n", metrics["reason"])
	}
	var warnings []string
	err = func() error {
		defer discardMetricsSnapshot(metricsSnapshot)
		q := newQuiesce(o.quiesce, false)
		if err := q.enter(); err != nil {
			return err
		}
		defer q.exit()
		w, err := createPayload(payload, core, backupExcludes)
		if err != nil {
			return err
		}
		warnings = w
		if o.includeSSH && len(ssh) > 0 {
			w, err := createPayload(sshPayload, ssh, backupExcludes)
			if err != nil {
				return err
			}
			warnings = append(warnings, w...)
		}
		return nil
	}()
	if err != nil {
		return "", err
	}
	payloadExpanded, err := validatePayload(payload, false)
	if err != nil {
		return "", err
	}
	var sshExpanded, sshSHA any
	if lexists(sshPayload) {
		size, err := validatePayload(sshPayload, true)
		if err != nil {
			return "", err
		}
		sshExpanded = size
		sum, err := sha256File(sshPayload)
		if err != nil {
			return "", err
		}
		sshSHA = sum
	}
	payloadSHA, err := sha256File(payload)
	if err != nil {
		return "", err
	}
	if warnings == nil {
		warnings = []string{}
	}
	sshList := ssh
	if sshList == nil {
		sshList = []string{}
	}
	manifest := map[string]any{
		"format":           "easy-ha-proxy-full-backup",
		"format_version":   FormatVersion,
		"created_at":       timestamp,
		"hostname":         fqdn(),
		"machine":          machine(),
		"core_paths":       core,
		"runtime_excludes": backupExcludes,
		"ssh_included":     o.includeSSH && len(ssh) > 0,
		"ssh_paths":        sshList,
		"quiesced":         o.quiesce,
		"metrics":          metrics,
		"metrics_included": metrics["included"] == true,
		"payload_sha256":   payloadSHA,
		// Kept so a restore can see which files tar caught mid-write.
		"ssh_payload_sha256":         sshSHA,
		"payload_expanded_bytes":     payloadExpanded,
		"ssh_payload_expanded_bytes": sshExpanded,
		"payload_warnings":           warnings,
	}
	if err := writeJSON(filepath.Join(work, "manifest.json"), manifest); err != nil {
		return "", err
	}
	state := "=== OS ===\n" + commandOutput("uname", "-a") +
		"\n=== PACKAGES ===\n" + commandOutput("dpkg-query", "-W") +
		"\n=== SYSTEMD ===\n" + commandOutput("systemctl", "list-unit-files", "--no-pager") +
		"\n=== DOCKER ===\n" + commandOutput("docker", "ps", "-a", "--no-trunc") +
		"\n=== IMAGES ===\n" + commandOutput("docker", "image", "ls", "--digests", "--no-trunc")
	if err := os.WriteFile(filepath.Join(work, "system-state.txt"), []byte(state), 0o644); err != nil {
		return "", err
	}
	bundle := filepath.Join(work, "bundle.tar.gz")
	names := []string{"manifest.json", "system-state.txt", "payload.tar.gz"}
	if lexists(sshPayload) {
		names = append(names, "ssh.tar.gz")
	}
	if _, err := run(append([]string{"tar", "-czf", bundle, "-C", work}, names...), runOptions{check: true}); err != nil {
		return "", err
	}
	if err := encryptBackup(bundle, encrypted, password); err != nil {
		return "", err
	}
	checksum, err := sha256File(encrypted)
	if err != nil {
		return "", err
	}
	sidecar := encrypted + ".sha256"
	if err := os.WriteFile(sidecar, []byte(checksum+"  "+filepath.Base(encrypted)+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(sidecar, 0o600); err != nil {
		return "", err
	}
	sshText := "no"
	if manifest["ssh_included"] == true {
		sshText = "yes"
	}
	fmt.Printf("\nFull encrypted backup created: %s\n", encrypted)
	fmt.Printf("Checksum: %s\n", sidecar)
	fmt.Printf("SSH keys included: %s\n", sshText)
	fmt.Printf("EASY_HA_PROXY_FULL_BACKUP_FILE=%s\n", encrypted)
	fmt.Printf("EASY_HA_PROXY_BACKUP_MANIFEST_JSON=%s\n", compactManifestJSON(manifest))
	return encrypted, nil
}

// verifyEncryptedArchive checks the checksum sidecar when there is one.
func verifyEncryptedArchive(archive string) error {
	if !isFile(archive) {
		return backupErrorf("Backup file not found: %s", archive)
	}
	sidecar := archive + ".sha256"
	if !isFile(sidecar) {
		return nil
	}
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return backupErrorf("Encrypted backup checksum file is empty.")
	}
	expected := strings.ToLower(fields[0])
	if !isHex64(expected) {
		return backupErrorf("Encrypted backup checksum file is invalid.")
	}
	actual, err := sha256File(archive)
	if err != nil {
		return err
	}
	if expected != actual {
		return backupErrorf("Encrypted backup checksum verification failed.")
	}
	return nil
}

// integer is a JSON number written as an integer (Python's int, not float
// or bool).
func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseInt(string(n), 10, 64)
	return value, err == nil
}

func nonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func validatedManifest(raw any) (map[string]any, error) {
	source, ok := raw.(map[string]any)
	if !ok {
		return nil, backupErrorf("Full-backup manifest must be a JSON object.")
	}
	manifest := map[string]any{}
	for k, v := range source {
		manifest[k] = v
	}
	version, isNumber := manifest["format_version"].(json.Number)
	versionValue, _ := strconv.ParseFloat(string(version), 64)
	if manifest["format"] != "easy-ha-proxy-full-backup" || !isNumber || versionValue != FormatVersion {
		return nil, backupErrorf("Unsupported full-backup format.")
	}
	for _, field := range []string{"created_at", "hostname", "machine"} {
		if !nonEmptyString(manifest[field]) {
			return nil, backupErrorf("Full-backup manifest field is invalid: %s", field)
		}
	}
	lists := map[string][]string{}
	for _, field := range []string{"core_paths", "ssh_paths"} {
		values, ok := manifest[field].([]any)
		if !ok {
			return nil, backupErrorf("Full-backup manifest field is invalid: %s", field)
		}
		for _, value := range values {
			s, ok := value.(string)
			if !ok || !strings.HasPrefix(s, "/") || hasDotDot(s) {
				return nil, backupErrorf("Full-backup manifest field is invalid: %s", field)
			}
			lists[field] = append(lists[field], s)
		}
	}
	if len(lists["core_paths"]) == 0 {
		return nil, backupErrorf("Full-backup manifest field is invalid: core_paths")
	}
	for _, value := range lists["core_paths"] {
		if !manifestCorePathAllowed(value) {
			return nil, backupErrorf("Full-backup manifest contains unmanaged core_paths.")
		}
	}
	for _, value := range lists["ssh_paths"] {
		if !manifestSSHPathAllowed(value) {
			return nil, backupErrorf("Full-backup manifest contains disallowed ssh_paths.")
		}
	}
	sshIncluded, ok := manifest["ssh_included"].(bool)
	if !ok {
		return nil, backupErrorf("Full-backup manifest field is invalid: ssh_included")
	}
	if _, ok := manifest["quiesced"].(bool); !ok {
		return nil, backupErrorf("Full-backup manifest field is invalid: quiesced")
	}
	if s, ok := manifest["payload_sha256"].(string); !ok || !isHex64(s) {
		return nil, backupErrorf("Full-backup manifest field is invalid: payload_sha256")
	}
	sshSHA := manifest["ssh_payload_sha256"]
	if sshSHA != nil {
		if s, ok := sshSHA.(string); !ok || !isHex64(s) {
			return nil, backupErrorf("Full-backup manifest field is invalid: ssh_payload_sha256")
		}
	}
	if sshIncluded != (sshSHA != nil && sshSHA != "") {
		return nil, backupErrorf("Full-backup manifest SSH metadata is inconsistent.")
	}
	if sshIncluded != (len(lists["ssh_paths"]) > 0) {
		return nil, backupErrorf("Full-backup manifest SSH path metadata is inconsistent.")
	}
	if value, set := manifest["payload_expanded_bytes"]; set && value != nil {
		if n, ok := integer(value); !ok || n < 0 || n > limit.coreBytes {
			return nil, backupErrorf("Full-backup manifest field is invalid: payload_expanded_bytes")
		}
	}
	sshExpanded, sshExpandedSet := manifest["ssh_payload_expanded_bytes"]
	if sshExpandedSet && sshExpanded != nil {
		if n, ok := integer(sshExpanded); !ok || n < 0 || n > limit.sshBytes {
			return nil, backupErrorf("Full-backup manifest field is invalid: ssh_payload_expanded_bytes")
		}
	}
	if !sshIncluded && sshExpandedSet && sshExpanded != nil {
		return nil, backupErrorf("Full-backup manifest SSH expanded-size metadata is inconsistent.")
	}
	if value, set := manifest["runtime_excludes"]; set && value != nil {
		list, ok := value.([]any)
		if !ok {
			return nil, backupErrorf("Full-backup manifest field is invalid: runtime_excludes")
		}
		for _, item := range list {
			if _, ok := item.(string); !ok {
				return nil, backupErrorf("Full-backup manifest field is invalid: runtime_excludes")
			}
		}
	}
	return manifest, nil
}

type openedArchive struct {
	manifest   map[string]any
	payload    string
	sshPayload string
}

// validateBackupArchive decrypts and fully validates an archive without
// changing the host.
var validateBackupArchive = func(archive, password, work string, checksumVerified, allowLegacy bool) (*openedArchive, error) {
	if !checksumVerified {
		if err := verifyEncryptedArchive(archive); err != nil {
			return nil, err
		}
	}
	bundle := filepath.Join(work, "bundle.tar.gz")
	if err := decryptBackup(archive, bundle, password, allowLegacy); err != nil {
		return nil, err
	}
	if err := extractBundle(bundle, work); err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(work, "manifest.json")
	if isSymlink(manifestPath) || !isFile(manifestPath) {
		return nil, backupErrorf("Full-backup manifest is missing or is not a regular file.")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var loaded any
	if err := decoder.Decode(&loaded); err != nil {
		return nil, backupErrorf("Full-backup manifest is not valid JSON: %v", err)
	}
	manifest, err := validatedManifest(loaded)
	if err != nil {
		return nil, err
	}
	payload := filepath.Join(work, "payload.tar.gz")
	if isSymlink(payload) || !isFile(payload) {
		return nil, backupErrorf("Core payload is missing or is not a regular file.")
	}
	if sum, err := sha256File(payload); err != nil {
		return nil, err
	} else if sum != strings.ToLower(manifest["payload_sha256"].(string)) {
		return nil, backupErrorf("Core payload checksum verification failed.")
	}
	expanded, err := validatePayload(payload, false)
	if err != nil {
		return nil, err
	}
	if declared, set := manifest["payload_expanded_bytes"]; set && declared != nil {
		if n, _ := integer(declared); n != expanded {
			return nil, backupErrorf("Core payload expanded-size verification failed.")
		}
	}
	// Version 1 archives made before the size metadata stay readable: the
	// measured sizes let every restore path run the same space preflight.
	manifest["payload_expanded_bytes"] = json.Number(strconv.FormatInt(expanded, 10))
	opened := &openedArchive{manifest: manifest, payload: payload}
	sshPath := filepath.Join(work, "ssh.tar.gz")
	switch {
	case manifest["ssh_included"] == true:
		if isSymlink(sshPath) || !isFile(sshPath) {
			return nil, backupErrorf("SSH payload is missing or is not a regular file.")
		}
		if sum, err := sha256File(sshPath); err != nil {
			return nil, err
		} else if sum != strings.ToLower(manifest["ssh_payload_sha256"].(string)) {
			return nil, backupErrorf("SSH payload checksum verification failed.")
		}
		sshExpanded, err := validatePayload(sshPath, true)
		if err != nil {
			return nil, err
		}
		if declared, set := manifest["ssh_payload_expanded_bytes"]; set && declared != nil {
			if n, _ := integer(declared); n != sshExpanded {
				return nil, backupErrorf("SSH payload expanded-size verification failed.")
			}
		}
		manifest["ssh_payload_expanded_bytes"] = json.Number(strconv.FormatInt(sshExpanded, 10))
		opened.sshPayload = sshPath
	case lexists(sshPath):
		return nil, backupErrorf("Unexpected SSH payload is present in the backup.")
	default:
		manifest["ssh_payload_expanded_bytes"] = nil
	}
	return opened, nil
}

// openBackupArchive asks for the passphrase and opens the archive with it.
// A person at a terminal is asked again when the passphrase does not open
// it; anything else wrong with the archive still ends the run.
var openBackupArchive = func(archive, work string, fromStdin, allowLegacy bool) (*openedArchive, error) {
	retry := passphraseIsTyped(fromStdin)
	for {
		password, err := readPassphrase(false, fromStdin)
		if err != nil {
			return nil, err
		}
		opened, err := validateBackupArchive(archive, password, work, true, allowLegacy)
		if err == nil {
			return opened, nil
		}
		if !isWrongPassphrase(err) || !retry {
			return nil, err
		}
		_ = os.Remove(filepath.Join(work, "bundle.tar.gz"))
		fmt.Fprintln(term.stderr, "That passphrase does not open this backup (or the file is damaged). Try again, or press Ctrl+C to stop.")
	}
}

func resolveArchive(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

func inspectBackup(archive string, passphraseStdin, allowLegacy bool) (map[string]any, error) {
	archive = resolveArchive(archive)
	if err := verifyEncryptedArchive(archive); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "easy-ha-proxy-inspect.")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	opened, err := openBackupArchive(archive, work, passphraseStdin, allowLegacy)
	if err != nil {
		return nil, err
	}
	fmt.Printf("EASY_HA_PROXY_BACKUP_MANIFEST_JSON=%s\n", compactManifestJSON(opened.manifest))
	return opened.manifest, nil
}

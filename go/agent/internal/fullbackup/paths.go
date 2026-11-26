// Package fullbackup is the encrypted full backup and disaster recovery of
// easy-ha-proxy: "easy-ha-proxy-agent full-backup backup|inspect|restore".
//
// The archive format is the one installer/full_backup.py wrote, so archives
// of either remain readable by the other: an OpenSSL AES-256-CBC stream
// behind an "EHP2" HMAC header, holding a tar.gz of manifest.json,
// system-state.txt, payload.tar.gz and an optional ssh.tar.gz.
package fullbackup

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	FormatVersion     = 1
	offlineRestoreEnv = "EASY_HA_PROXY_OFFLINE_RESTORE"
	metricsUnit       = "easy-ha-proxy-metricsd.service"
	// Free space kept beyond the snapshot itself, so a backup never fills
	// the disk the gateway logs to.
	metricsSnapshotReserve = 512 * 1024 * 1024
)

// The host paths; variables so the tests can point them at a scratch tree.
var (
	DefaultBackupRoot = "/var/backups/easy-ha-proxy"

	corePaths = []string{
		"/etc/easy-ha-proxy",
		"/opt/easy-ha-proxy/source",
		"/etc/haproxy",
		"/etc/letsencrypt",
		"/etc/iptables/haproxy_ban.rules",
		"/etc/msmtprc",
		"/etc/apparmor.d/local/usr.sbin.rsyslogd",
		"/etc/logrotate.d/authelia",
		"/etc/sysctl.d/99-authelia-redis.conf",
		"/etc/systemd/journald.conf.d/80-retention.conf",
		"/opt/authelia",
		"/opt/haproxy-admin",
		"/var/lib/haproxy",
		// Who changed what, the security engine's findings and -- as a
		// snapshot, see metricsSnapshot -- the monitoring history. The live
		// metrics database under the same root is excluded below.
		"/var/lib/easy-ha-proxy",
		"/var/log/haproxy",
		"/var/log/haproxy.log",
		"/var/log/letsencrypt",
		"/usr/local/bin/update-geoip.sh",
		// The former Python GeoIP updater (now the agent's update-geoip):
		// kept, as /usr/local/sbin/haproxy-* and authelia-* below match the
		// former Python daemons, because restore authorizes an archive's
		// paths by these lists and archives taken before still carry them.
		"/usr/local/lib/easy-ha-proxy/update_geoip.py",
	}
	coreGlobs = []string{
		"/etc/systemd/system/haproxy*",
		"/etc/systemd/system/authelia*",
		"/etc/systemd/system/iptables-haproxy*",
		"/etc/systemd/system/update-admin-rt*",
		"/etc/systemd/system/journal-vacuum*",
		"/etc/systemd/system/easy-ha-proxy-geoip-update*",
		"/usr/local/sbin/haproxy-*",
		"/usr/local/sbin/authelia-*",
		"/etc/rsyslog.d/*haproxy*",
	}
	// corePaths mixes directory trees and single files. The directory
	// semantics are explicit so an archive cannot turn a managed file path
	// such as /etc/msmtprc into an authorization for arbitrary descendants.
	coreDirectoryPaths = map[string]bool{
		"/etc/easy-ha-proxy": true, "/opt/easy-ha-proxy/source": true, "/etc/haproxy": true,
		"/etc/letsencrypt": true, "/opt/authelia": true, "/opt/haproxy-admin": true,
		"/var/lib/easy-ha-proxy": true, "/var/lib/haproxy": true, "/var/log/haproxy": true,
		"/var/log/letsencrypt": true,
	}

	// Runtime material that must not survive inside disaster-recovery
	// archives, or that is no help in rebuilding the machine.
	backupExcludes = []string{
		// Short-lived password-reset links and one-time codes.
		"opt/authelia/notification.log",
		"var/lib/easy-ha-proxy/authelia-notification-state.json",
		"var/lib/easy-ha-proxy/authelia-notifications",
		// The live metrics database is written every few seconds, so a copy
		// taken by tar can be torn between the database and its write-ahead
		// log; the history travels as a consistent snapshot instead.
		"var/lib/easy-ha-proxy/metrics",
		// Finished archives live under the archived tree: without these
		// every backup swallowed all its predecessors and roughly doubled.
		"var/lib/easy-ha-proxy/backup-web/backups",
		"var/lib/easy-ha-proxy/backup-web/uploads",
		"var/lib/easy-ha-proxy/update-web",
		// The request log: every visitor's address, path and user agent over
		// a few days. It rebuilds itself, and an archive often sent off the
		// host is no place for it.
		"var/lib/easy-ha-proxy/requests",
	}

	// The monitoring history: SQLite's online backup copies it consistently
	// while the collector keeps writing. The snapshot lives under an
	// archived root only while the archive is written; a restore moves it
	// into place.
	metricsDatabase = "/var/lib/easy-ha-proxy/metrics/metrics.db"
	metricsSnapshot = "/var/lib/easy-ha-proxy/monitoring-history/metrics.db"

	sshGlobs = []string{"/etc/ssh/ssh_host_*", "/root/.ssh", "/home/*/.ssh"}

	quiesceUnits = []string{
		// The security engine and the alert engine write their SQLite
		// databases all the time: a copy of one taken a moment after the
		// other restores as a torn file. Stopped, each closes its database
		// cleanly; started again, the security engine carries on from its
		// place in the access log.
		"easy-ha-proxy-guardd.service",
		"easy-ha-proxy-alertd.service",
		"easy-ha-proxy-geoip-update.timer",
		"easy-ha-proxy-geoip-update.service",
		"haproxy-certd.service",
		"haproxy-controld.service",
		"haproxy-healthd.service",
		"authelia-configd.service",
		"authelia-usersd.service",
		"authelia-bansd.service",
		"snap.certbot.renew.timer",
		"certbot.timer",
	}
	quiesceContainers = []string{"haproxy-admin", "authelia", "authelia-redis", "mail_relay"}

	// Configuration-scope restore: only sites, their runtime settings and
	// certificates. The managed source, systemd units, secrets, Authelia
	// state and SSH identity are left untouched, so even a backup taken on
	// an older revision cannot downgrade host services.
	configScopePaths = []string{"/etc/haproxy", "/etc/letsencrypt", "/opt/haproxy-admin/config"}

	outerRequired = []string{"manifest.json", "payload.tar.gz", "system-state.txt"}
	outerOptional = []string{"ssh.tar.gz"}

	authorizedKeysGlob = "/home/*/.ssh/authorized_keys"
	rootAuthorizedKeys = "/root/.ssh/authorized_keys"
	iptablesDir        = "/etc/iptables"
	managedSource      = "/opt/easy-ha-proxy/source"
	apparentRoot       = "/"
)

// Limits on what an archive may expand to.
type limits struct {
	outerMembers, outerBytes int64
	coreMembers, coreBytes   int64
	sshMembers, sshBytes     int64
	restoreMinFree           int64
	rollbackBase             int64
	rollbackPerMember        int64
}

var limit = limits{
	outerMembers: 8, outerBytes: 8 << 30,
	coreMembers: 250_000, coreBytes: 64 << 30,
	sshMembers: 10_000, sshBytes: 1 << 30,
	restoreMinFree: 512 << 20,
	rollbackBase:   16 << 20, rollbackPerMember: 4096,
}

// configuredPositiveLimit reads an override from the environment.
func configuredPositiveLimit(name string, fallback int64) (int64, error) {
	raw, set := os.LookupEnv(name)
	if !set {
		return fallback, nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0, backupErrorf("%s must be a positive integer.", name)
	}
	return value, nil
}

// loadLimits applies the environment overrides.
func loadLimits() error {
	for _, l := range []struct {
		name  string
		value *int64
	}{
		{"EASY_HA_PROXY_BACKUP_MAX_OUTER_MEMBERS", &limit.outerMembers},
		{"EASY_HA_PROXY_BACKUP_MAX_OUTER_BYTES", &limit.outerBytes},
		{"EASY_HA_PROXY_BACKUP_MAX_CORE_MEMBERS", &limit.coreMembers},
		{"EASY_HA_PROXY_BACKUP_MAX_CORE_BYTES", &limit.coreBytes},
		{"EASY_HA_PROXY_BACKUP_MAX_SSH_MEMBERS", &limit.sshMembers},
		{"EASY_HA_PROXY_BACKUP_MAX_SSH_BYTES", &limit.sshBytes},
		{"EASY_HA_PROXY_RESTORE_MIN_FREE_BYTES", &limit.restoreMinFree},
	} {
		value, err := configuredPositiveLimit(l.name, *l.value)
		if err != nil {
			return err
		}
		*l.value = value
	}
	return nil
}

func managedConfigDir() string {
	if dir := os.Getenv("EASY_HA_PROXY_CONFIG_DIR"); dir != "" {
		return dir
	}
	return "/etc/easy-ha-proxy"
}

func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func isSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// existingPaths is every listed path and glob match that exists, sorted.
func existingPaths(paths, patterns []string) []string {
	found := map[string]bool{}
	for _, value := range paths {
		if lexists(value) {
			found[value] = true
		}
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, value := range matches {
			if lexists(value) {
				found[value] = true
			}
		}
	}
	return sortedKeys(found)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pyNormpath is Python's posixpath.normpath, two leading slashes included.
func pyNormpath(p string) string {
	if p == "" {
		return "."
	}
	initial := 0
	if strings.HasPrefix(p, "/") {
		initial = 1
		if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
			initial = 2
		}
	}
	var comps []string
	for _, comp := range strings.Split(p, "/") {
		if comp == "" || comp == "." {
			continue
		}
		if comp != ".." || (initial == 0 && len(comps) == 0) || (len(comps) > 0 && comps[len(comps)-1] == "..") {
			comps = append(comps, comp)
		} else if len(comps) > 0 {
			comps = comps[:len(comps)-1]
		}
	}
	out := strings.Repeat("/", initial) + strings.Join(comps, "/")
	if out == "" {
		return "."
	}
	return out
}

// pyDirname is posixpath.dirname.
func pyDirname(p string) string {
	i := strings.LastIndex(p, "/") + 1
	head := p[:i]
	if head != "" && head != strings.Repeat("/", len(head)) {
		head = strings.TrimRight(head, "/")
	}
	return head
}

// pyJoin is posixpath.join of two parts.
func pyJoin(a, b string) string {
	if strings.HasPrefix(b, "/") {
		return b
	}
	if a == "" || strings.HasSuffix(a, "/") {
		return a + b
	}
	return a + "/" + b
}

// pathParts is PurePosixPath(p).parts: "/" first for an absolute path, no
// empty or "." parts.
func pathParts(p string) []string {
	var parts []string
	if strings.HasPrefix(p, "/") {
		parts = append(parts, "/")
	}
	for _, part := range strings.Split(p, "/") {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	return parts
}

func hasDotDot(p string) bool {
	for _, part := range pathParts(p) {
		if part == ".." {
			return true
		}
	}
	return false
}

func normalizedAbsolutePath(value string) (string, bool) {
	if !strings.HasPrefix(value, "/") || hasDotDot(value) {
		return "", false
	}
	normalized := pyNormpath(value)
	if !strings.HasPrefix(normalized, "/") {
		return "", false
	}
	return normalized, true
}

// posixPatternMatches matches part for part, a "*" never crossing a "/".
func posixPatternMatches(p, pattern string) bool {
	candidate, expected := pathParts(p), pathParts(pattern)
	if len(candidate) != len(expected) {
		return false
	}
	for i := range candidate {
		if matched, err := path.Match(expected[i], candidate[i]); err != nil || !matched {
			return false
		}
	}
	return true
}

func isSameOrBelow(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimRight(root, "/")+"/")
}

func staticPatternPrefix(pattern string) string {
	var parts []string
	for _, part := range pathParts(pattern) {
		if strings.ContainsAny(part, "*?[") {
			break
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "/"
	}
	return joinParts(parts)
}

func joinParts(parts []string) string {
	if parts[0] == "/" {
		return "/" + strings.Join(parts[1:], "/")
	}
	return strings.Join(parts, "/")
}

// parents is PurePosixPath(p).parents: every ancestor up to "/".
func parents(p string) []string {
	parts := pathParts(p)
	var out []string
	for i := len(parts) - 1; i >= 1; i-- {
		out = append(out, joinParts(parts[:i]))
	}
	return out
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func manifestCorePathAllowed(p string) bool {
	normalized, ok := normalizedAbsolutePath(p)
	if !ok {
		return false
	}
	if contains(corePaths, normalized) {
		return true
	}
	for _, pattern := range coreGlobs {
		if posixPatternMatches(normalized, pattern) {
			return true
		}
	}
	return false
}

func corePayloadPathAllowed(p string) bool {
	normalized, ok := normalizedAbsolutePath(p)
	if !ok {
		return false
	}
	for root := range coreDirectoryPaths {
		if isSameOrBelow(normalized, root) {
			return true
		}
	}
	if contains(corePaths, normalized) {
		return true
	}
	for _, pattern := range coreGlobs {
		if posixPatternMatches(normalized, pattern) {
			return true
		}
		// A glob can select a managed directory such as haproxy.service.d;
		// tar then holds its children too: only descendants of the exact
		// glob match are authorized.
		for _, parent := range parents(normalized) {
			if posixPatternMatches(parent, pattern) {
				return true
			}
		}
	}
	return false
}

func coreAncestorDirectoryAllowed(p string) bool {
	normalized, ok := normalizedAbsolutePath(p)
	if !ok {
		return false
	}
	targets := append([]string(nil), corePaths...)
	for _, pattern := range coreGlobs {
		targets = append(targets, staticPatternPrefix(pattern))
	}
	for _, target := range targets {
		if target == normalized || strings.HasPrefix(target, strings.TrimRight(normalized, "/")+"/") {
			return true
		}
	}
	return false
}

func manifestSSHPathAllowed(p string) bool {
	normalized, ok := normalizedAbsolutePath(p)
	if !ok {
		return false
	}
	for _, pattern := range sshGlobs {
		if posixPatternMatches(normalized, pattern) {
			return true
		}
	}
	return false
}

func sshPayloadPathAllowed(p string) bool {
	normalized, ok := normalizedAbsolutePath(p)
	if !ok {
		return false
	}
	if posixPatternMatches(normalized, "/etc/ssh/ssh_host_*") || isSameOrBelow(normalized, "/root/.ssh") {
		return true
	}
	parts := pathParts(normalized)
	return len(parts) >= 4 && parts[1] == "home" && parts[3] == ".ssh"
}

func sshAncestorDirectoryAllowed(p string) bool {
	normalized, ok := normalizedAbsolutePath(p)
	if !ok {
		return false
	}
	switch normalized {
	case "/etc", "/etc/ssh", "/root", "/home":
		return true
	}
	parts := pathParts(normalized)
	return len(parts) == 3 && parts[1] == "home" && parts[2] != ""
}

// sshPaths is the SSH material a backup may carry, the key named by
// rdg_ssh_key in vars.yml included.
func sshPaths() []string {
	found := map[string]bool{}
	for _, p := range existingPaths(nil, sshGlobs) {
		found[p] = true
	}
	if raw, err := os.ReadFile(filepath.Join(managedConfigDir(), "vars.yml")); err == nil {
		for _, line := range splitLines(string(raw)) {
			if strings.HasPrefix(strings.TrimSpace(line), "rdg_ssh_key:") {
				_, value, _ := strings.Cut(line, ":")
				candidate := strings.Trim(strings.TrimSpace(value), "\"'")
				if manifestSSHPathAllowed(candidate) && isFile(candidate) {
					found[candidate] = true
				}
				break
			}
		}
	}
	return sortedKeys(found)
}

// managedStatePaths is only what the built-in allowlist authorizes.
var managedStatePaths = func(includeSSH bool) []string {
	found := map[string]bool{}
	for _, p := range existingPaths(corePaths, coreGlobs) {
		found[p] = true
	}
	if includeSSH {
		for _, p := range sshPaths() {
			found[p] = true
		}
	}
	return sortedKeys(found)
}

func relativePaths(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = strings.TrimLeft(p, "/")
	}
	return out
}

// splitLines is Python's str.splitlines for the usual line ends.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

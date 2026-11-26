// Package updatescope decides which playbook steps a source change needs.
//
// A full update runs every stage of the playbook -- certificates, the HAProxy
// package, AppArmor, GeoIP, Docker, Authelia, every daemon -- to deliver what
// is often one changed daemon and a template. This compares the source tree
// an update would install with the tree the last complete update applied,
// and maps each changed file to the stage that deploys it.
//
// The map is deliberately narrow and conservative. A file it does not know
// -- the playbook itself, a role's defaults, the Python requirements,
// anything new -- means "run the full stack", never "skip it". A file that
// deploys nothing (tests, documentation, the web application's source, which
// ships as a container image) needs no stage at all.
//
// The comparison is against a record of the last complete update, not
// against whatever was on disk before the download. An update that stopped
// half way, or a narrower update that refreshed the source without running
// every stage, therefore cannot make the next "changes only" run skip what
// it missed.
package updatescope

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	AppliedSourceFile = "applied-source.json"
	manifestSchema    = 1
	gitTimeout        = 20 * time.Second

	Full           = "full"
	StatusTag      = "status"
	maxListedPaths = 20
)

// Directories and files that are never part of the shipped source, even in
// a staged bundle that was not a Git checkout.
var (
	skippedDirs = map[string]bool{".git": true, "__pycache__": true, ".pytest_cache": true, ".mypy_cache": true, "node_modules": true}
	skipped     = []string{"*.pyc", "*.retry", ".easy-ha-proxy-source-revision", "ansible/cache/*", "ansible/tcp.yml",
		"ansible/authelia_users_initial.yml", "ansible/roles/cert/files/*.pem", "ansible/roles/haproxy-admin.zip"}
	revisionRe = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
)

const (
	admin    = "ansible/roles/haproxy-admin"
	haproxy  = "ansible/roles/haproxy"
	cert     = "ansible/roles/cert"
	authelia = "ansible/roles/authelia"
)

// goInstaller: the native stage installs the agent; the others are the
// stages a change to the agent's stage code (or to the template engine it
// renders with) can alter on a host.
var goInstaller = []string{"ha-adm-native", "ha-adm-daemons", "ha-adm-journald", "ha-adm-install", "ha-install", "apparmor",
	"geo", "ha-cfg", "ha-adm-cfg", "ha-adm-start", "docker", "authelia", "crt-install", "crt-notify", "crt-hooks"}

// Rule maps a source path pattern (fnmatch, "*" crossing "/") to the tags
// that deploy it; no tags means the file deploys nothing on the host.
type Rule struct {
	Pattern string
	Tags    []string
}

func tags(t ...string) []string { return t }

// Rules: the first match wins.
var Rules = []Rule{
	// Nothing to deploy.
	{".tests/*", nil},
	{".github/*", nil},
	{"LICENSES/*", nil},
	{"LICENSE", nil},
	// Read live by the update broker for the footer; nothing to deploy.
	{"VERSION", nil},
	{"*.md", nil},
	{"docs/*", nil},
	{".gitignore", nil},
	{".gitattributes", nil},
	// The web panel ships as a container image built from go/panel; the "web
	// application" update pulls it. Nothing on the host changes -- except for
	// the packages the host agent compiles too (the Jinja engine and the
	// Python-compatible YAML): a new agent, and the stages render with them.
	{"go/panel/shared/*", goInstaller},
	{"go/panel/*", nil},
	// Native Rust hot-path core and Go host agent. The sources do not deploy,
	// but CI publishes their binaries from them, and only the native stage
	// installs those binaries and restarts the daemons that run them.
	{"rust/guardd/*", tags("ha-adm-native")},
	// The installer agent's stages: a change there must reach those stages,
	// not only the new binary.
	{"go/agent/internal/apply/*", goInstaller},
	{"go/agent/*", tags("ha-adm-native")},
	// Install entry points and the menu helper run from the source directory
	// itself, and the refreshed source is already in place.
	{"install.sh", nil},
	{"install-local.sh", nil},
	{"install-remote.sh", nil},
	{"easy-ha-proxy-helper.sh", nil},
	// The installer runs from the refreshed source too -- except for its
	// Python dependencies, which only the full update reinstalls.
	{"installer/requirements.txt", tags(Full)},
	{"installer/*", nil},
	// Always run, and the OS packages have their own update.
	{"ansible/roles/healthcheck/*", nil},

	// Adaptive protection.
	{admin + "/files/scanner-signatures.json", tags("ha-adm-guardd")},
	{admin + "/templates/guardd.json.j2", tags("ha-adm-guardd")},
	{admin + "/templates/easy-ha-proxy-guardd.service.j2", tags("ha-adm-guardd")},
	// Metrics.
	{admin + "/templates/metricsd.json.j2", tags("ha-adm-metricsd")},
	{admin + "/templates/easy-ha-proxy-metricsd.service.j2", tags("ha-adm-metricsd")},
	// Alerts.
	{admin + "/templates/alertd.json.j2", tags("ha-adm-alertd")},
	{admin + "/templates/easy-ha-proxy-alertd.service.j2", tags("ha-adm-alertd")},
	// Health.
	{admin + "/templates/healthd.json.j2", tags("ha-adm-healthd")},
	{admin + "/templates/haproxy-healthd.service.j2", tags("ha-adm-healthd")},
	// Control.
	{admin + "/templates/haproxy-controld.service.j2", tags("ha-adm-controld")},
	// Backups.
	{admin + "/templates/easy-ha-proxy-backup.service.j2", tags("ha-adm-backupd")},
	{admin + "/templates/easy-ha-proxy-backup.timer.j2", tags("ha-adm-backupd")},
	{admin + "/templates/easy-ha-proxy-backupd.service.j2", tags("ha-adm-backupd")},
	{admin + "/templates/easy-ha-proxy-unit-failed@.service.j2", tags("ha-adm-backupd")},
	// The update broker.
	{admin + "/templates/easy-ha-proxy-updated.service.j2", tags("ha-adm-updated")},
	// Certificates: certd is only deployed by the install and daemons stages.
	{admin + "/templates/haproxy-certd.service.j2", tags("ha-adm-daemons")},
	{admin + "/templates/certbot-renew.service.conf.j2", tags("ha-adm-daemons")},
	// Journal retention.
	{admin + "/templates/journal-vacuum.service.j2", tags("ha-adm-journald")},
	{admin + "/templates/journal-vacuum.timer.j2", tags("ha-adm-journald")},
	// Firewall helpers and the admin host setup.
	{admin + "/files/haproxy_ban.rules", tags("ha-adm-install")},
	{admin + "/templates/iptables-haproxy-ban.service.j2", tags("ha-adm-install")},
	{admin + "/templates/iptables-haproxy-udp.service.j2", tags("ha-adm-install")},
	// The web application's Compose file, environment and start stage are
	// left to the full stack on purpose: starting it also pulls the image,
	// which would update the container without the digest review the "web
	// application" update does.

	// HAProxy. The web application renders the configuration from its own
	// copy of the template, which the admin settings stage refreshes.
	{haproxy + "/templates/haproxy.cfg.j2", tags("ha-cfg", "ha-adm-cfg")},
	{haproxy + "/templates/haproxy-state-dump.*", tags("ha-cfg")},
	{haproxy + "/files/default-favicon.ico", tags("ha-install")},
	{haproxy + "/templates/access_granted.http.j2", tags("ha-install")},
	{haproxy + "/templates/maintenance.http.j2", tags("ha-install")},
	{haproxy + "/templates/update-admin-rt.*", tags("ha-install")},
	// A default can change the rendered configuration and what install lays down.
	{haproxy + "/defaults/*", tags("ha-install", "ha-cfg")},

	// GeoIP: one stage owns the whole role.
	{"ansible/roles/geoip_acl/*", tags("geo")},
	// Docker: likewise.
	{"ansible/roles/docker/*", tags("docker")},

	// Certificate hooks and notifications. Issuance and renewal are not part
	// of any update, full or not.
	{cert + "/templates/905-haproxy-pems-reload.sh.j2", tags("crt-hooks")},
	{cert + "/templates/906-deliver-certificates.sh.j2", tags("crt-hooks")},
	{cert + "/templates/910-mail-notify.sh.j2", tags("crt-notify")},
	{cert + "/templates/mail-notify.json.j2", tags("crt-notify")},
	{cert + "/templates/_san_flags.j2", nil},

	// Authelia's host daemons. Its configuration and container are not
	// mapped: those go through the full stack.
	{authelia + "/templates/authelia-bans.sh.j2", tags("aut-daemons")},
	{authelia + "/templates/authelia-bansd.service.j2", tags("aut-daemons")},
	{authelia + "/templates/authelia-configd.service.j2", tags("aut-daemons")},
	{authelia + "/templates/authelia-usersd.service.j2", tags("aut-daemons")},
}

// TagLabels: what each step is called on the page and in the log.
var TagLabels = map[string]string{
	"ha-cfg":          "HAProxy configuration",
	"ha-install":      "HAProxy files",
	"apparmor":        "AppArmor profile",
	"geo":             "GeoIP",
	"docker":          "Docker",
	"crt-install":     "Certbot",
	"crt-hooks":       "Certificate hooks",
	"crt-notify":      "Certificate notifications",
	"ha-adm-guardd":   "Adaptive protection",
	"ha-adm-metricsd": "Metrics",
	"ha-adm-alertd":   "Alerts",
	"ha-adm-healthd":  "Health monitor",
	"ha-adm-controld": "HAProxy control service",
	"ha-adm-backupd":  "Backups",
	"ha-adm-updated":  "Update service",
	"ha-adm-daemons":  "Helper daemons",
	"ha-adm-native":   "Native host binaries",
	"ha-adm-journald": "Journal retention",
	"ha-adm-install":  "Admin host setup",
	"ha-adm-cfg":      "Web application's copy of the HAProxy template",
	"aut-daemons":     "Authelia helper daemons",
}

var (
	patternsMu sync.Mutex
	patterns   = map[string]*regexp.Regexp{}
)

// FnmatchCase is Python's fnmatch.fnmatchcase: "*" and "?" match any
// character, "/" included; [seq] and [!seq] are classes.
func FnmatchCase(name, pattern string) bool {
	patternsMu.Lock()
	re, ok := patterns[pattern]
	if !ok {
		re = regexp.MustCompile(translate(pattern))
		patterns[pattern] = re
	}
	patternsMu.Unlock()
	return re.MatchString(name)
}

func translate(pattern string) string {
	var b strings.Builder
	b.WriteString(`(?s)^`)
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		case '[':
			j := i + 1
			if j < len(pattern) && pattern[j] == '!' {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j >= len(pattern) {
				b.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : j]
			class = strings.ReplaceAll(class, `\`, `\\`)
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			} else if strings.HasPrefix(class, "^") {
				class = `\` + class
			}
			b.WriteString("[" + class + "]")
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	return b.String()
}

func isSkipped(relative string) bool {
	parts := strings.Split(relative, "/")
	for _, part := range parts[:len(parts)-1] {
		if skippedDirs[part] {
			return true
		}
	}
	for _, p := range skipped {
		if FnmatchCase(relative, p) {
			return true
		}
	}
	return false
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// trackedFiles lists what Git tracks; nil when the tree is not a usable checkout.
func trackedFiles(root string) []string {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-c", "safe.directory="+root, "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}
	if names == nil {
		names = []string{}
	}
	return names
}

func regularFile(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

// SourceManifest is {relative path: sha256} for the shipped files under
// root. In a Git checkout only tracked files count, so files the installation
// writes into its own source directory at run time never look like a change.
// A staged bundle has no Git; it is walked, minus the known run-time files.
func SourceManifest(root string) map[string]string {
	names := trackedFiles(root)
	if names == nil {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if rel, err := filepath.Rel(root, path); err == nil {
				names = append(names, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	manifest := map[string]string{}
	for _, relative := range names {
		if isSkipped(relative) {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		if !regularFile(path) {
			continue
		}
		if digest, err := fileDigest(path); err == nil {
			manifest[relative] = digest
		}
	}
	return manifest
}

// ChangedPaths are the paths the candidate adds or changes. A removed file
// deploys nothing by itself.
func ChangedPaths(applied, candidate map[string]string) []string {
	var out []string
	for path, digest := range candidate {
		if old, ok := applied[path]; !ok || old != digest {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// TagsForPath: the tags that deploy one path; an empty slice for nothing;
// nil with false when unknown.
func TagsForPath(relative string) ([]string, bool) {
	for _, rule := range Rules {
		if FnmatchCase(relative, rule.Pattern) {
			if rule.Tags == nil {
				return []string{}, true
			}
			return rule.Tags, true
		}
	}
	return nil, false
}

func head(paths []string) []string {
	if len(paths) > maxListedPaths {
		paths = paths[:maxListedPaths]
	}
	return append([]string{}, paths...)
}

// ScopeFor decides what a set of changed paths needs. "full" is true when
// any path is unknown or explicitly needs the whole stack ("tags" is then
// empty); otherwise "tags" lists the stages to run, with the status check
// when anything runs at all.
func ScopeFor(paths []string) map[string]any {
	seen := map[string]bool{}
	var changed []string
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			changed = append(changed, p)
		}
	}
	sort.Strings(changed)
	tagSet := map[string]bool{}
	unmapped, fullPaths := []string{}, []string{}
	for _, relative := range changed {
		found, known := TagsForPath(relative)
		switch {
		case !known:
			unmapped = append(unmapped, relative)
		case contains(found, Full):
			fullPaths = append(fullPaths, relative)
		default:
			for _, t := range found {
				tagSet[t] = true
			}
		}
	}
	needsFull := len(unmapped) > 0 || len(fullPaths) > 0
	ordered := []string{}
	if !needsFull {
		for t := range tagSet {
			ordered = append(ordered, t)
		}
		sort.Strings(ordered)
		if len(ordered) > 0 {
			ordered = append(ordered, StatusTag)
		}
	}
	steps := []string{}
	for _, t := range ordered {
		if t == StatusTag {
			continue
		}
		if label, ok := TagLabels[t]; ok {
			steps = append(steps, label)
		} else {
			steps = append(steps, t)
		}
	}
	if changed == nil {
		changed = []string{}
	}
	return map[string]any{
		"full":     needsFull,
		"tags":     ordered,
		"steps":    steps,
		"changed":  len(changed),
		"unmapped": head(append(unmapped, fullPaths...)),
		"paths":    head(changed),
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// Applied is the record of the last complete update.
type Applied struct {
	Revision   string
	Files      map[string]string
	RecordedAt string
}

// ReadApplied reads the record; nil when there is none or it is damaged.
func ReadApplied(configDir string) *Applied {
	raw, err := os.ReadFile(filepath.Join(configDir, AppliedSourceFile))
	if err != nil {
		return nil
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return nil
	}
	if schema, _ := data["schema"].(float64); schema != manifestSchema {
		return nil
	}
	files, ok := data["files"].(map[string]any)
	if !ok || len(files) == 0 {
		return nil
	}
	out := &Applied{Files: map[string]string{}}
	for name, digest := range files {
		if s, ok := digest.(string); ok {
			out.Files[name] = s
		}
	}
	out.Revision, _ = data["revision"].(string)
	out.RecordedAt, _ = data["recorded_at"].(string)
	return out
}

// WriteApplied records sourceRoot as the tree the last complete update applied.
func WriteApplied(configDir, sourceRoot, revision string) (string, error) {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", err
	}
	clean := strings.ToLower(strings.TrimSpace(revision))
	if !revisionRe.MatchString(clean) {
		clean = ""
	}
	payload := map[string]any{
		"schema":      manifestSchema,
		"revision":    clean,
		"recorded_at": time.Now().UTC().Format("2006-01-02T15:04:05") + "+00:00",
		"files":       SourceManifest(sourceRoot),
	}
	raw, err := json.Marshal(payload) // sorted keys, no spaces, as json.dump(sort_keys, separators)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(configDir, "."+AppliedSourceFile+".")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return "", err
	}
	target := filepath.Join(configDir, AppliedSourceFile)
	return target, os.Rename(tmp.Name(), target)
}

// PlanScope says what applying candidateRoot needs, for the update plan and the CLI.
func PlanScope(configDir, candidateRoot string) map[string]any {
	applied := ReadApplied(configDir)
	if applied == nil {
		return map[string]any{"ready": false, "reason": "no-applied-record", "full": true, "tags": []string{}, "steps": []string{},
			"changed": 0, "unmapped": []string{}, "paths": []string{}}
	}
	scope := ScopeFor(ChangedPaths(applied.Files, SourceManifest(candidateRoot)))
	full := scope["full"].(bool)
	scope["ready"] = !full
	scope["reason"] = ""
	if full {
		scope["reason"] = "unmapped-paths"
	}
	scope["applied_revision"] = applied.Revision
	return scope
}

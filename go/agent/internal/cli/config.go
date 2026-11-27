package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"golang.org/x/sys/unix"
)

const (
	Product                     = "easy-ha-proxy"
	DefaultHome                 = "/opt/easy-ha-proxy"
	DefaultConfigDir            = "/etc/easy-ha-proxy"
	DefaultRepository           = "https://github.com/CLLlAgOB/easy-ha-proxy.git"
	DefaultAdminImageRepository = "clllagob/haproxy-admin-ui"
	RuntimeConfigMaxBytes       = 2 * 1024 * 1024
	ChangesComponent            = "changes"
)

// InstallerError is an expected installer failure with a user-facing message.
type InstallerError struct {
	Msg string
}

func (e *InstallerError) Error() string { return e.Msg }

func installerErrorf(format string, args ...any) error {
	return &InstallerError{Msg: fmt.Sprintf(format, args...)}
}

// ReleaseChannels binds the single user-facing release channel name to git
// branch + Docker image tag (or local synced source).
var ReleaseChannels = map[string]map[string]string{
	"stable": {"source_channel": "github", "branch": "main", "image_channel": "latest"},
	"alpha":  {"source_channel": "github", "branch": "alpha", "image_channel": "alpha"},
	"local":  {"source_channel": "local"},
}

var (
	gitBranchRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,100}$`)
	country2Re  = regexp.MustCompile(`^[A-Za-z]{2}$`)
	country2Up  = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Tag bundles: which stages each kind of run applies.
const (
	InstallTags = "crt-install,crt-notify,crt-hooks,crt-renew,ha-install,apparmor,geo,ha-cfg,docker," +
		"ha-adm-native,aut-install,ha-adm-install,ha-adm-healthd,ha-adm-cfg,ha-adm-controld," +
		"ha-adm-backupd,ha-adm-updated,ha-adm-metricsd,ha-adm-guardd,ha-adm-alertd," +
		"ha-adm-journald,ha-adm-start,status"

	UpdateTags = "crt-install,crt-hooks,crt-notify,ha-install,apparmor,geo,ha-cfg,docker," +
		"ha-adm-native,aut-install,aut-update,ha-adm-install,ha-adm-healthd,ha-adm-cfg," +
		"ha-adm-controld,ha-adm-backupd,ha-adm-updated,ha-adm-metricsd,ha-adm-guardd," +
		"ha-adm-alertd,ha-adm-journald,ha-adm-update,ha-adm-start,status"

	UITags = "ha-cfg,ha-adm-native,aut-daemons,ha-adm-daemons,ha-adm-healthd,ha-adm-cfg," +
		"ha-adm-controld,ha-adm-backupd,ha-adm-updated,ha-adm-metricsd,ha-adm-guardd," +
		"ha-adm-alertd,ha-adm-update,ha-adm-start,status"

	DaemonTags = "ha-adm-native,aut-daemons,ha-adm-daemons,status"

	HostServiceTags = "crt-install,crt-hooks,crt-notify,ha-install,apparmor,geo,ha-cfg," +
		"ha-adm-native,ha-adm-install,ha-adm-healthd,ha-adm-backupd,ha-adm-updated," +
		"ha-adm-metricsd,ha-adm-guardd,ha-adm-alertd,ha-adm-journald,aut-install,status"

	ConfigureTags             = "crt-renew," + UpdateTags
	LanguageTags              = "aut-install,ha-adm-cfg,ha-adm-start,status"
	DomainMigrationTags       = "crt-hooks,crt-renew,ha-cfg,aut-cfg,ha-adm-cfg,ha-adm-start,status"
	InternalCADomainMigration = "crt-hooks,ha-cfg,aut-cfg,ha-adm-cfg,ha-adm-start,status"
	InternalCAInstallTags     = "crt-install,crt-notify,crt-hooks,ha-install,apparmor,geo,ha-cfg,docker,ha-adm-native,aut-install,ha-adm-install,ha-adm-healthd,ha-adm-cfg,ha-adm-controld,ha-adm-backupd,ha-adm-updated,ha-adm-metricsd,ha-adm-guardd,ha-adm-alertd,ha-adm-journald,ha-adm-start,status"
	RestoreTags               = InternalCAInstallTags
	RestoreConfigTags         = "ha-adm-cfg,ha-cfg,status"
	RestoreSkipTags           = "restore-network"
)

var (
	UpdateComponentTags = map[string]string{
		"all":                UpdateTags,
		ChangesComponent:     "",
		"ui":                 UITags,
		"daemons":            DaemonTags,
		"services":           HostServiceTags,
		"containers":         "aut-update,ha-adm-update,status",
		"admin-container":    "ha-adm-cfg,ha-adm-update,status",
		"authelia-container": "aut-update,status",
		"os":                 "upgrade,status",
	}

	SourceUpdateComponents = map[string]bool{
		"all":            true,
		"daemons":        true,
		"services":       true,
		ChangesComponent: true,
	}

	// RuntimeHAProxyVarKeys are the render settings the panel owns and the
	// sync carries from the container-writable runtime config into the managed
	// root config. Host-owned infrastructure keys (haproxy_socket,
	// haproxy_socket_group, root_domain, the native delivery settings) must
	// never be here: the runtime files are writable by the unprivileged panel
	// container, and a value like haproxy_socket flows into root-run shell
	// templates (haproxy-state-dump.sh, update-admin-rt.sh), so carrying it
	// would hand a compromised container command execution as root.
	RuntimeHAProxyVarKeys = map[string]bool{
		"admin_allowed_ips":    true,
		"admin_ips_enabled":    true,
		"admin_password":       true,
		"enable_geoip":         true,
		"enable_http80":        true,
		"export_prometheus":    true,
		"geoip_country_codes":  true,
		"geoip_mode":           true,
		"haproxy_nbthread":     true,
		"haproxy_nbthread_max": true,
		"localpeer":            true,
		"peers_bind":           true,
		"peers_enabled":        true,
		"peers_name":           true,
		"prometheus_port":      true,
		"site_defaults":        true,
	}

	ConfigurationFiles = []string{"inventory.ini", "vars.yml", "secrets.yml"}

	runtimeHAProxyConfigDir = "/opt/haproxy-admin/config"
	runtimeAutheliaConfig   = "/opt/authelia/configuration.yml"
	sourceDirOverride       = ""
	configDirOverride       = ""
	installHomeOverride     = ""
	requireRootFn           = defaultRequireRoot
	backupConfigurationFn   = defaultBackupConfiguration
	dockerContainerExistsFn = defaultDockerContainerExists
)

// ValidGitBranch checks whether branch is a safe plain git branch name.
func ValidGitBranch(branch string) bool {
	return gitBranchRe.MatchString(branch) &&
		!strings.HasPrefix(branch, "-") &&
		!strings.Contains(branch, "..") &&
		!strings.HasPrefix(branch, "/") &&
		!strings.HasSuffix(branch, "/") &&
		!strings.HasSuffix(branch, ".lock") &&
		!strings.Contains(branch, "//")
}

// InstalledBranch returns EASY_HA_PROXY_BRANCH if set and valid.
func InstalledBranch() string {
	branch := strings.TrimSpace(os.Getenv("EASY_HA_PROXY_BRANCH"))
	if branch != "" && ValidGitBranch(branch) {
		return branch
	}
	return ""
}

// ReleaseChannelFromSettings derives the user-facing release channel name.
func ReleaseChannelFromSettings(sourceChannel, branch, imageChannel string) string {
	_ = branch
	if sourceChannel == "" {
		sourceChannel = "github"
	}
	if sourceChannel == "local" {
		return "local"
	}
	if imageChannel == "alpha" {
		return "alpha"
	}
	return "stable"
}

// InstallHome returns the installer home directory (/opt/easy-ha-proxy).
func InstallHome() string {
	if installHomeOverride != "" {
		return installHomeOverride
	}
	if v := os.Getenv("EASY_HA_PROXY_HOME"); v != "" {
		return expandHome(v)
	}
	return DefaultHome
}

// SourceDir returns the managed source tree path.
func SourceDir() string {
	if sourceDirOverride != "" {
		return sourceDirOverride
	}
	if v := os.Getenv("EASY_HA_PROXY_SOURCE_DIR"); v != "" {
		return resolvePath(expandHome(v))
	}
	return resolvePath(filepath.Join(InstallHome(), "source"))
}

// ConfigDir returns the managed configuration directory (/etc/easy-ha-proxy).
func ConfigDir() string {
	if configDirOverride != "" {
		return configDirOverride
	}
	if v := os.Getenv("EASY_HA_PROXY_CONFIG_DIR"); v != "" {
		return expandHome(v)
	}
	return DefaultConfigDir
}

// InternalCAExportPath returns where the public internal CA cert is exported.
func InternalCAExportPath() string {
	if v := os.Getenv("EASY_HA_PROXY_CA_EXPORT"); v != "" {
		return expandHome(v)
	}
	return filepath.Join(InstallHome(), "internal-ca.crt")
}

// RequireRoot verifies root privileges.
func RequireRoot() error {
	return requireRootFn()
}

func defaultRequireRoot() error {
	if os.Geteuid() != 0 {
		return installerErrorf("Run this command as root (sudo easy-ha-proxy ...).")
	}
	return nil
}

// WriteYAML writes data as PyYAML-compatible YAML atomically with mode.
func WriteYAML(path string, data any, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o600
	}
	text, err := pyyaml.Dump(data, pyyaml.Options{AllowUnicode: true, SortKeys: false})
	if err != nil {
		return err
	}
	return WriteText(path, text, mode)
}

// WriteText writes text atomically to path with mode (replacing any symlink).
func WriteText(path string, text string, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o600
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// LoadYAMLMapping reads a YAML mapping file into a *pyyaml.Map.
func LoadYAMLMapping(path string) (*pyyaml.Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, installerErrorf("Cannot read YAML file %s: %v", path, err)
	}
	loaded, err := pyyaml.Load(raw)
	if err != nil {
		return nil, installerErrorf("Cannot read YAML file %s: %v", path, err)
	}
	m, ok := loaded.(*pyyaml.Map)
	if !ok || m == nil {
		return nil, installerErrorf("Expected a YAML mapping in %s.", path)
	}
	return m, nil
}

// LoadMetadata reads metadata.yml, returning an empty Map if missing or invalid.
func LoadMetadata(directory string) *pyyaml.Map {
	if directory == "" {
		directory = ConfigDir()
	}
	m, err := LoadYAMLMapping(filepath.Join(directory, "metadata.yml"))
	if err != nil {
		return pyyaml.NewMap()
	}
	return m
}

// MarkInstallationComplete marks metadata.yml as completely applied.
func MarkInstallationComplete(directory string) error {
	if directory == "" {
		directory = ConfigDir()
	}
	metaPath := filepath.Join(directory, "metadata.yml")
	metadata, err := LoadYAMLMapping(metaPath)
	if err != nil {
		return err
	}
	metadata.Set("installation_complete", true)
	metadata.Set("configuration_pending", false)
	metadata.Set("installation_completed_at", time.Now().UTC().Format(time.RFC3339Nano))
	return WriteYAML(metaPath, metadata, 0o600)
}

// IsTestMode reports whether metadata.yml has test_mode: true.
func IsTestMode(directory string) bool {
	return truthy(LoadMetadata(directory).Value("test_mode"))
}

// ConfiguredCertificateSource returns "internal" or "letsencrypt".
func ConfiguredCertificateSource(directory string) string {
	meta := LoadMetadata(directory)
	source := strings.ToLower(strings.TrimSpace(strVal(meta.Value("certificate_source"))))
	if source == "letsencrypt" || source == "internal" {
		return source
	}
	if truthy(meta.Value("test_mode")) {
		return "internal"
	}
	return "letsencrypt"
}

// UsesInternalCA reports whether the installation uses the internal CA.
func UsesInternalCA(directory string) bool {
	return ConfiguredCertificateSource(directory) == "internal"
}

// ManagedConfigurationIsPending reports whether installer-owned config awaits a full apply.
func ManagedConfigurationIsPending(directory string) bool {
	return truthy(LoadMetadata(directory).Value("configuration_pending"))
}

// BackupConfiguration snapshots top-level files of directory into directory/backups/<ts>.
func BackupConfiguration(out io.Writer, directory string) (string, error) {
	return backupConfigurationFn(out, directory)
}

func defaultBackupConfiguration(out io.Writer, directory string) (string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 {
		return "", nil
	}
	ts := time.Now().UTC().Format("20060102T150405.000000Z")
	ts = strings.ReplaceAll(ts, ".", "")
	dest := filepath.Join(directory, "backups", ts)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Name() == "backups" {
			continue
		}
		srcPath := filepath.Join(directory, entry.Name())
		info, err := os.Stat(srcPath)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := copyFilePreserve(srcPath, filepath.Join(dest, entry.Name()), info.Mode().Perm()); err != nil {
			return "", err
		}
	}
	fmt.Fprintf(out, "Configuration backup: %s\n", dest)
	return dest, nil
}

// RequireConfiguration checks that managed config files and playbook exist.
func RequireConfiguration(directory string) error {
	var missing []string
	for _, name := range ConfigurationFiles {
		p := filepath.Join(directory, name)
		if !fileExists(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return installerErrorf("Configuration is incomplete. Run easy-ha-proxy install first. Missing: %s", strings.Join(missing, ", "))
	}
	playbook := filepath.Join(SourceDir(), "ansible/easy-ha-proxy.yml")
	if !fileExists(playbook) {
		return installerErrorf("Playbook not found: %s", playbook)
	}
	return nil
}

// EnsureSecuritySecrets idempotently generates haproxy_admin_proxy_secret if missing.
func EnsureSecuritySecrets(out io.Writer, directory string) error {
	path := filepath.Join(directory, "secrets.yml")
	if !isRegularFile(path) {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return installerErrorf("Cannot migrate security secrets in %s: %v", path, err)
	}
	loaded, err := pyyaml.Load(raw)
	if err != nil {
		return installerErrorf("Cannot migrate security secrets in %s: %v", path, err)
	}
	var data *pyyaml.Map
	if loaded == nil {
		data = pyyaml.NewMap()
	} else {
		var ok bool
		data, ok = loaded.(*pyyaml.Map)
		if !ok {
			return installerErrorf("Expected a YAML mapping in %s.", path)
		}
	}
	if truthy(data.Value("haproxy_admin_proxy_secret")) {
		return nil
	}
	data.Set("haproxy_admin_proxy_secret", tokenURLSafe(48))
	if err := WriteYAML(path, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "Generated the missing internal proxy secret in %s.\n", path)
	return nil
}

// ChannelOptions specifies channel fields to persist.
type ChannelOptions struct {
	ReleaseChannel string
	SourceChannel  string
	ImageChannel   string
	Branch         string
	Directory      string
}

// PersistDeploymentChannels updates vars.yml and metadata.yml with explicit channel selections.
func PersistDeploymentChannels(out io.Writer, opts ChannelOptions) error {
	sourceChannel := opts.SourceChannel
	imageChannel := opts.ImageChannel
	branch := opts.Branch

	if opts.ReleaseChannel != "" {
		rc := strings.ToLower(strings.TrimSpace(opts.ReleaseChannel))
		mapping, ok := ReleaseChannels[rc]
		if !ok {
			return installerErrorf("Release channel must be stable, alpha or local.")
		}
		if sourceChannel == "" {
			sourceChannel = mapping["source_channel"]
		}
		if rc != "local" {
			if branch == "" {
				branch = mapping["branch"]
			}
			if imageChannel == "" {
				imageChannel = mapping["image_channel"]
			}
		}
	}

	directory := opts.Directory
	if directory == "" {
		directory = ConfigDir()
	}
	varsPath := filepath.Join(directory, "vars.yml")
	metaPath := filepath.Join(directory, "metadata.yml")
	variables, err := LoadYAMLMapping(varsPath)
	if err != nil {
		return err
	}
	metadata, err := LoadYAMLMapping(metaPath)
	if err != nil {
		return err
	}
	changed := false

	if branch != "" {
		branch = strings.TrimSpace(branch)
		if !ValidGitBranch(branch) {
			return installerErrorf("Invalid git branch name.")
		}
		if strVal(metadata.Value("branch")) != branch {
			metadata.Set("branch", branch)
			changed = true
		}
	}
	if sourceChannel != "" {
		sourceChannel = strings.ToLower(strings.TrimSpace(sourceChannel))
		if sourceChannel != "github" && sourceChannel != "local" {
			return installerErrorf("Source channel must be github or local.")
		}
		if strVal(metadata.Value("source_channel")) != sourceChannel {
			metadata.Set("source_channel", sourceChannel)
			changed = true
		}
	}
	if imageChannel != "" {
		imageChannel = strings.ToLower(strings.TrimSpace(imageChannel))
		if imageChannel != "latest" && imageChannel != "alpha" {
			return installerErrorf("Docker image channel must be latest or alpha.")
		}
		repo := os.Getenv("EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY")
		if repo == "" {
			repo = DefaultAdminImageRepository
		}
		image := repo + ":" + imageChannel
		if strVal(variables.Value("haproxy_admin_image")) != image {
			variables.Set("haproxy_admin_image", image)
			changed = true
		}
		if strVal(metadata.Value("image_channel")) != imageChannel {
			metadata.Set("image_channel", imageChannel)
			changed = true
		}
	}

	if !changed {
		return nil
	}
	if _, err := BackupConfiguration(out, directory); err != nil {
		return err
	}
	if err := WriteYAML(varsPath, variables, 0o600); err != nil {
		return err
	}
	return WriteYAML(metaPath, metadata, 0o600)
}

func loadBoundedRuntimeYAML(path string) (*pyyaml.Map, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, installerErrorf("Cannot safely open runtime YAML %s: %v", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, installerErrorf("Cannot read runtime YAML %s: %v", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, installerErrorf("Runtime YAML is not a regular file: %s", path)
	}
	if st.Size <= 0 || st.Size > RuntimeConfigMaxBytes {
		return nil, installerErrorf("Runtime YAML must be between 1 byte and 2 MiB: %s", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, RuntimeConfigMaxBytes+1))
	if err != nil {
		return nil, installerErrorf("Cannot read runtime YAML %s: %v", path, err)
	}
	if len(raw) > RuntimeConfigMaxBytes {
		return nil, installerErrorf("Runtime YAML exceeds 2 MiB: %s", path)
	}
	loaded, err := pyyaml.Load(raw)
	if err != nil {
		return nil, installerErrorf("Invalid runtime YAML %s: %v", path, err)
	}
	m, ok := loaded.(*pyyaml.Map)
	if !ok || m == nil {
		return nil, installerErrorf("Expected a YAML mapping in runtime file %s.", path)
	}
	return m, nil
}

func rejectUnsafeRuntimeScalars(v any, path string) error {
	switch x := v.(type) {
	case string:
		for _, r := range x {
			if r < 32 || r == 127 {
				return installerErrorf("Unsafe control character in runtime configuration: %s", path)
			}
		}
		return nil
	case *pyyaml.Map:
		var firstErr error
		x.Each(func(k, val any) {
			if firstErr != nil {
				return
			}
			ks, ok := k.(string)
			if !ok {
				firstErr = installerErrorf("Runtime mapping keys must be strings: %s", path)
				return
			}
			if err := rejectUnsafeRuntimeScalars(ks, path+".<key>"); err != nil {
				firstErr = err
				return
			}
			if err := rejectUnsafeRuntimeScalars(val, path+"."+ks); err != nil {
				firstErr = err
				return
			}
		})
		return firstErr
	case []any:
		for i, item := range x {
			if err := rejectUnsafeRuntimeScalars(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case nil, bool, int, int64, float64:
		return nil
	default:
		return installerErrorf("Unsupported YAML value in runtime configuration: %s", path)
	}
}

func validateRuntimeDocumentRoots(doc *pyyaml.Map, filename string, allowed map[string]bool) error {
	var unexpected []string
	doc.Each(func(k, _ any) {
		ks := fmt.Sprint(k)
		if !allowed[ks] {
			unexpected = append(unexpected, ks)
		}
	})
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return installerErrorf("Unsupported top-level key(s) in %s: %s. Preserve the file and upgrade with a version that explicitly supports this schema before applying changes.", filename, strings.Join(unexpected, ", "))
	}
	return nil
}

func loadRuntimeHAProxyDocuments(runtimeDir string) (*pyyaml.Map, *pyyaml.Map, *pyyaml.Map, bool, error) {
	paths := map[string]string{
		"vars.yml":     filepath.Join(runtimeDir, "vars.yml"),
		"websites.yml": filepath.Join(runtimeDir, "websites.yml"),
		"tcp.yml":      filepath.Join(runtimeDir, "tcp.yml"),
	}
	existCount := 0
	for _, p := range paths {
		if fileExists(p) {
			existCount++
		}
	}
	if existCount == 0 {
		return nil, nil, nil, false, nil
	}
	if existCount != len(paths) {
		return nil, nil, nil, false, installerErrorf("The HAProxy Admin runtime configuration is incomplete; expected vars.yml, websites.yml, and tcp.yml together.")
	}
	rv, err := loadBoundedRuntimeYAML(paths["vars.yml"])
	if err != nil {
		return nil, nil, nil, false, err
	}
	rw, err := loadBoundedRuntimeYAML(paths["websites.yml"])
	if err != nil {
		return nil, nil, nil, false, err
	}
	rt, err := loadBoundedRuntimeYAML(paths["tcp.yml"])
	if err != nil {
		return nil, nil, nil, false, err
	}
	for _, pair := range []struct {
		name string
		data *pyyaml.Map
	}{{"vars.yml", rv}, {"websites.yml", rw}, {"tcp.yml", rt}} {
		if err := rejectUnsafeRuntimeScalars(pair.data, pair.name); err != nil {
			return nil, nil, nil, false, err
		}
	}
	if err := validateRuntimeDocumentRoots(rw, "runtime websites.yml", map[string]bool{"sites": true}); err != nil {
		return nil, nil, nil, false, err
	}
	if err := validateRuntimeDocumentRoots(rt, "runtime tcp.yml", map[string]bool{"tcp_proxies": true, "tcp": true}); err != nil {
		return nil, nil, nil, false, err
	}
	_, hasProxies := rt.Get("tcp_proxies")
	_, hasLegacy := rt.Get("tcp")
	if hasProxies && hasLegacy {
		return nil, nil, nil, false, installerErrorf("Runtime tcp.yml cannot contain both tcp_proxies and the legacy tcp key.")
	}

	sitesRaw, hasSites := rw.Get("sites")
	var sites []any
	if !hasSites {
		sites = []any{}
	} else {
		var ok bool
		sites, ok = sitesRaw.([]any)
		if !ok || len(sites) > 500 {
			return nil, nil, nil, false, installerErrorf("Runtime websites.yml must contain at most 500 sites.")
		}
		for _, item := range sites {
			if _, ok := item.(*pyyaml.Map); !ok {
				return nil, nil, nil, false, installerErrorf("Runtime websites.yml must contain at most 500 sites.")
			}
		}
	}

	var tcpRaw any
	var hasTCPRaw bool
	if hasProxies {
		tcpRaw, hasTCPRaw = rt.Get("tcp_proxies")
	} else if hasLegacy {
		tcpRaw, hasTCPRaw = rt.Get("tcp")
	}
	if hasTCPRaw {
		tcpList, ok := tcpRaw.([]any)
		if !ok || len(tcpList) > 500 {
			return nil, nil, nil, false, installerErrorf("Runtime tcp.yml must contain at most 500 TCP proxies.")
		}
		for _, item := range tcpList {
			if _, ok := item.(*pyyaml.Map); !ok {
				return nil, nil, nil, false, installerErrorf("Runtime tcp.yml must contain at most 500 TCP proxies.")
			}
		}
	}

	if sd, ok := rv.Get("site_defaults"); ok {
		if _, isMap := sd.(*pyyaml.Map); !isMap {
			return nil, nil, nil, false, installerErrorf("Runtime vars.yml site_defaults must be a mapping.")
		}
	}

	runtimeGeoCountries := map[string]bool{}
	if ccRaw, ok := rv.Get("geoip_country_codes"); ok {
		ccList, isList := ccRaw.([]any)
		if !isList {
			return nil, nil, nil, false, installerErrorf("Runtime vars.yml geoip_country_codes must contain ISO alpha-2 codes.")
		}
		for _, item := range ccList {
			cs, isStr := item.(string)
			if !isStr || !country2Re.MatchString(cs) {
				return nil, nil, nil, false, installerErrorf("Runtime vars.yml geoip_country_codes must contain ISO alpha-2 codes.")
			}
			runtimeGeoCountries[strings.ToUpper(cs)] = true
		}
	}
	for idx, item := range sites {
		site := item.(*pyyaml.Map)
		scRaw, hasSC := site.Get("geo_countries")
		if !hasSC || scRaw == nil {
			continue
		}
		scList, isList := scRaw.([]any)
		if !isList {
			return nil, nil, nil, false, installerErrorf("Runtime websites.yml sites[%d].geo_countries must contain at most 249 uppercase ISO alpha-2 codes.", idx)
		}
		if len(scList) == 0 {
			continue
		}
		if len(scList) > 249 {
			return nil, nil, nil, false, installerErrorf("Runtime websites.yml sites[%d].geo_countries must contain at most 249 uppercase ISO alpha-2 codes.", idx)
		}
		unavailSet := map[string]bool{}
		for _, c := range scList {
			cs, isStr := c.(string)
			if !isStr || !country2Up.MatchString(strings.TrimSpace(cs)) {
				return nil, nil, nil, false, installerErrorf("Runtime websites.yml sites[%d].geo_countries must contain at most 249 uppercase ISO alpha-2 codes.", idx)
			}
			if !runtimeGeoCountries[cs] {
				unavailSet[cs] = true
			}
		}
		if len(unavailSet) > 0 {
			var unavail []string
			for c := range unavailSet {
				unavail = append(unavail, c)
			}
			sort.Strings(unavail)
			return nil, nil, nil, false, installerErrorf("Runtime websites.yml sites[%d] uses GeoIP countries not selected globally: %s", idx, strings.Join(unavail, ", "))
		}
	}
	return rv, rw, rt, true, nil
}

// SyncRuntimeHAProxyConfigToManaged copies UI-owned HAProxy settings/sites/TCP
// back into managed /etc/easy-ha-proxy before updates.
func SyncRuntimeHAProxyConfigToManaged(out io.Writer, directory, runtimeDir string) (bool, error) {
	if directory == "" {
		directory = ConfigDir()
	}
	if runtimeDir == "" {
		runtimeDir = runtimeHAProxyConfigDir
	}
	if ManagedConfigurationIsPending(directory) {
		return false, nil
	}
	rv, rw, rt, found, err := loadRuntimeHAProxyDocuments(runtimeDir)
	if err != nil || !found {
		return false, err
	}
	sites := []any{}
	if raw, ok := rw.Get("sites"); ok {
		if list, ok := raw.([]any); ok {
			sites = list
		}
	}
	tcpProxies := []any{}
	if raw, ok := rt.Get("tcp_proxies"); ok {
		if list, ok := raw.([]any); ok {
			tcpProxies = list
		}
	} else if raw, ok := rt.Get("tcp"); ok {
		if list, ok := raw.([]any); ok {
			tcpProxies = list
		}
	}

	managedVarsPath := filepath.Join(directory, "vars.yml")
	managedWebsitesPath := filepath.Join(directory, "websites.yml")
	managedTCPPath := filepath.Join(directory, "tcp.yml")

	managedVars, err := LoadYAMLMapping(managedVarsPath)
	if err != nil {
		return false, err
	}
	managedWebsites, err := LoadYAMLMapping(managedWebsitesPath)
	if err != nil {
		return false, err
	}
	managedTCP, err := LoadYAMLMapping(managedTCPPath)
	if err != nil {
		return false, err
	}
	if err := validateRuntimeDocumentRoots(managedWebsites, "managed websites.yml", map[string]bool{"sites": true}); err != nil {
		return false, err
	}
	if err := validateRuntimeDocumentRoots(managedTCP, "managed tcp.yml", map[string]bool{"tcp_proxies": true, "tcp": true}); err != nil {
		return false, err
	}
	_, hasManagedProxies := managedTCP.Get("tcp_proxies")
	_, hasManagedLegacy := managedTCP.Get("tcp")
	if hasManagedProxies && hasManagedLegacy {
		return false, installerErrorf("Managed tcp.yml cannot contain both tcp_proxies and the legacy tcp key.")
	}

	effectiveVars := pyyaml.DeepCopy(managedVars).(*pyyaml.Map)
	keys := make([]string, 0, len(RuntimeHAProxyVarKeys))
	for k := range RuntimeHAProxyVarKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if val, ok := rv.Get(key); ok {
			effectiveVars.Set(key, pyyaml.DeepCopy(val))
		} else {
			effectiveVars.Delete(key)
		}
	}
	effectiveWebsites := pyyaml.NewMap()
	effectiveWebsites.Set("sites", pyyaml.DeepCopy(sites))
	effectiveTCP := pyyaml.NewMap()
	effectiveTCP.Set("tcp_proxies", pyyaml.DeepCopy(tcpProxies))

	if yamlValuesEqual(effectiveVars, managedVars) &&
		yamlValuesEqual(effectiveWebsites, managedWebsites) &&
		yamlValuesEqual(effectiveTCP, managedTCP) {
		return false, nil
	}
	if _, err := BackupConfiguration(out, directory); err != nil {
		return false, err
	}
	if err := WriteYAML(managedVarsPath, effectiveVars, 0o600); err != nil {
		return false, err
	}
	if err := WriteYAML(managedWebsitesPath, effectiveWebsites, 0o600); err != nil {
		return false, err
	}
	if err := WriteYAML(managedTCPPath, effectiveTCP, 0o600); err != nil {
		return false, err
	}
	fmt.Fprintln(out, "Synchronized UI-owned HAProxy sites, TCP proxies, and render settings into the managed update source.")
	return true, nil
}

// SyncRuntimeAutheliaRulesToManaged persists Authelia access_control.rules
// edited in the panel into managed authelia.yml before rendering.
func SyncRuntimeAutheliaRulesToManaged(out io.Writer, directory, runtimeConfig string) (bool, error) {
	if directory == "" {
		directory = ConfigDir()
	}
	if runtimeConfig == "" {
		runtimeConfig = runtimeAutheliaConfig
	}
	if ManagedConfigurationIsPending(directory) {
		return false, nil
	}
	managedPath := filepath.Join(directory, "authelia.yml")
	if !isRegularFile(managedPath) || !isRegularFile(runtimeConfig) {
		return false, nil
	}
	runtimeDoc, err := loadBoundedRuntimeYAML(runtimeConfig)
	if err != nil {
		return false, nil
	}
	access, ok := runtimeDoc.Value("access_control").(*pyyaml.Map)
	if !ok || access == nil {
		return false, nil
	}
	rules, ok := access.Value("rules").([]any)
	if !ok {
		return false, nil
	}
	for _, r := range rules {
		if _, isMap := r.(*pyyaml.Map); !isMap {
			return false, nil
		}
	}
	managed, err := LoadYAMLMapping(managedPath)
	if err != nil {
		return false, err
	}
	current := managed.Value("authelia_access_control_rules")
	if yamlValuesEqual(rules, current) {
		return false, nil
	}
	if len(rules) == 0 && truthy(current) {
		return false, nil
	}
	if _, err := BackupConfiguration(out, directory); err != nil {
		return false, err
	}
	managed.Set("authelia_access_control_rules", pyyaml.DeepCopy(rules))
	if err := WriteYAML(managedPath, managed, 0o600); err != nil {
		return false, err
	}
	fmt.Fprintln(out, "Synchronized Authelia access rules edited in the panel into the managed update source.")
	return true, nil
}

// OfflineRestoreRequiredImages resolves all container/native images required by
// an offline reconciliation of controllerSource with directory's config.
func OfflineRestoreRequiredImages(directory, controllerSource string) (map[string]bool, error) {
	if directory == "" {
		directory = ConfigDir()
	}
	if controllerSource == "" {
		controllerSource = SourceDir()
	}
	variables, err := LoadYAMLMapping(filepath.Join(directory, "vars.yml"))
	if err != nil {
		return nil, err
	}
	authelia, err := LoadYAMLMapping(filepath.Join(directory, "authelia.yml"))
	if err != nil {
		return nil, err
	}
	adminDefaults, err := LoadYAMLMapping(filepath.Join(controllerSource, "ansible/roles/haproxy-admin/defaults/main.yml"))
	if err != nil {
		return nil, err
	}
	autheliaDefaults, err := LoadYAMLMapping(filepath.Join(controllerSource, "ansible/roles/authelia/defaults/main.yml"))
	if err != nil {
		return nil, err
	}

	templates := []struct {
		path string
		vars []string
	}{
		{
			filepath.Join(controllerSource, "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2"),
			[]string{"haproxy_admin_go_image"},
		},
		{
			filepath.Join(controllerSource, "ansible/roles/authelia/templates/docker-compose.yml.j2"),
			[]string{"authelia_redis_image", "mail_relay_image", "authelia_version"},
		},
	}
	for _, spec := range templates {
		raw, err := os.ReadFile(spec.path)
		if err != nil {
			return nil, installerErrorf("Offline restore preflight cannot read image template %s: %v", spec.path, err)
		}
		var imageLines []string
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "image:") {
				imageLines = append(imageLines, trimmed)
			}
		}
		bad := len(imageLines) != len(spec.vars)
		if !bad {
			for _, variable := range spec.vars {
				count := 0
				for _, line := range imageLines {
					if strings.Contains(line, variable) {
						count++
					}
				}
				if count != 1 {
					bad = true
					break
				}
			}
		}
		if bad {
			return nil, installerErrorf("Offline restore preflight does not recognize every image in the current recovery template: %s.", spec.path)
		}
	}

	effective := map[string]any{}
	overrides := map[string]bool{}
	for _, src := range []*pyyaml.Map{adminDefaults, autheliaDefaults} {
		src.Each(func(k, v any) { effective[fmt.Sprint(k)] = v })
	}
	for _, src := range []*pyyaml.Map{variables, authelia} {
		src.Each(func(k, v any) {
			ks := fmt.Sprint(k)
			effective[ks] = v
			overrides[ks] = true
		})
	}

	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.StrictUndefined = true
	env.Filters["bool"] = jinja.AnsibleBool
	env.Filters["regex_replace"] = func(_ *jinja.Environment, value any, args []any, _ *jinja.Map) (any, error) {
		if len(args) < 2 {
			return "", fmt.Errorf("regex_replace requires pattern and replacement")
		}
		re, err := regexp.Compile(fmt.Sprint(args[0]))
		if err != nil {
			return "", err
		}
		return re.ReplaceAllString(fmt.Sprint(value), fmt.Sprint(args[1])), nil
	}

	resolve := func(key string, fallback any) (any, error) {
		val, ok := effective[key]
		if !ok {
			val = fallback
		}
		if !overrides[key] {
			if s, isStr := val.(string); isStr && strings.Contains(s, "{{") {
				tmpl, err := env.FromString(key, s)
				if err != nil {
					return nil, err
				}
				rendered, err := env.RenderTemplate(tmpl, effective)
				if err != nil {
					return nil, err
				}
				val = rendered
			}
		}
		effective[key] = val
		return val, nil
	}
	enabled := func(key string, fallback bool) (bool, error) {
		val, err := resolve(key, fallback)
		if err != nil {
			return false, err
		}
		b, err := jinja.AnsibleBool(env, val, nil, nil)
		if err != nil {
			return false, err
		}
		out, _ := b.(bool)
		return out, nil
	}

	images := map[string]bool{}
	if _, err := resolve("haproxy_admin_image_channel", ""); err != nil {
		return nil, err
	}
	if useDocker, err := enabled("haproxy_admin_use_docker", true); err != nil {
		return nil, err
	} else if useDocker {
		v, err := resolve("haproxy_admin_go_image", "")
		if err != nil {
			return nil, err
		}
		images[strings.TrimSpace(strVal(v))] = true
	}

	localBundle, err := resolve("native_local_bundle_dir", "")
	if err != nil {
		return nil, err
	}
	releaseURL, err := resolve("native_release_base_url", "")
	if err != nil {
		return nil, err
	}
	if !truthy(localBundle) && !truthy(releaseURL) {
		refVal, err := resolve("native_release_image", "")
		if err != nil {
			return nil, err
		}
		reference := strings.TrimSpace(strVal(refVal))
		if pin, err := enabled("native_release_pin_revision", true); err != nil {
			return nil, err
		} else if pin {
			if rev := sourceTreeRevision(controllerSource); rev != "" {
				reference += "-" + rev[:12]
			}
		}
		images[reference] = true
	}

	if autEnabled, err := enabled("authelia_enabled", false); err != nil {
		return nil, err
	} else if autEnabled {
		images["authelia/authelia:"+strings.TrimSpace(strVal(effective["authelia_version"]))] = true
		if redisEnabled, err := enabled("authelia_session_redis_enabled", true); err != nil {
			return nil, err
		} else if redisEnabled {
			images[strings.TrimSpace(strVal(effective["authelia_redis_image"]))] = true
		}
		mailNotify, err := enabled("mail_notify_enabled", false)
		if err != nil {
			return nil, err
		}
		mailRelay, err := enabled("mail_relay_server", false)
		if err != nil {
			return nil, err
		}
		if mailNotify || mailRelay || dockerContainerExistsFn("mail_relay") {
			images[strings.TrimSpace(strVal(effective["mail_relay_image"]))] = true
		}
	}

	var invalid []string
	for img := range images {
		hasSpace := false
		for _, r := range img {
			if unicode.IsSpace(r) {
				hasSpace = true
				break
			}
		}
		if img == "" || len(img) > 512 || hasSpace {
			invalid = append(invalid, fmt.Sprintf("%q", img))
		}
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		return nil, installerErrorf("Offline restore preflight found invalid managed image references: %s", strings.Join(invalid, ", "))
	}
	return images, nil
}

func defaultDockerContainerExists(name string) bool {
	docker, err := lookPath("docker")
	if err != nil || docker == "" {
		return false
	}
	res := runSubprocess(docker, "inspect", name)
	return res.Err == nil && res.ExitCode == 0
}

// OfflineRestoreImagePreflight verifies that all required images exist locally in Docker.
func OfflineRestoreImagePreflight(directory, controllerSource string, requiredImages map[string]bool) error {
	docker, err := lookPath("docker")
	if err != nil || docker == "" {
		return installerErrorf("Offline restore preflight failed: Docker is not installed. Prepare the target with the normal installer before restoring.")
	}
	images := requiredImages
	if images == nil {
		var err error
		images, err = OfflineRestoreRequiredImages(directory, controllerSource)
		if err != nil {
			return err
		}
	}
	sorted := make([]string, 0, len(images))
	for img := range images {
		sorted = append(sorted, img)
	}
	sort.Strings(sorted)
	var missing []string
	for _, img := range sorted {
		res := runSubprocess(docker, "image", "inspect", img)
		if res.Err != nil {
			return installerErrorf("Offline restore preflight failed while inspecting %s: %v", img, res.Err)
		}
		if res.ExitCode != 0 {
			missing = append(missing, img)
		}
	}
	if len(missing) > 0 {
		return installerErrorf("Offline restore preflight failed: required Docker images are not available locally: %s. Run a normal managed install/update to cache them before restoring; the restore broker will not contact registries.", strings.Join(missing, ", "))
	}
	return nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isRegularFile(p string) bool {
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

func copyFilePreserve(src, dst string, mode os.FileMode) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, raw, mode); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func mapToGoMap(m *pyyaml.Map) map[string]any {
	out := map[string]any{}
	if m == nil {
		return out
	}
	m.Each(func(k, v any) {
		switch x := v.(type) {
		case *pyyaml.Map:
			out[fmt.Sprint(k)] = mapToGoMap(x)
		default:
			out[fmt.Sprint(k)] = v
		}
	})
	return out
}

func truthy(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	case *pyyaml.Map:
		return x != nil && x.Len() > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

// yamlValuesEqual compares two decoded YAML values semantically (like Python ==,
// independent of map key insertion order).
func yamlValuesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	switch x := a.(type) {
	case *pyyaml.Map:
		y, ok := b.(*pyyaml.Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		equal := true
		x.Each(func(k, v any) {
			if !equal {
				return
			}
			yv, found := y.Get(k)
			if !found || !yamlValuesEqual(v, yv) {
				equal = false
			}
		})
		return equal
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !yamlValuesEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case int:
		return yamlValuesEqual(int64(x), b)
	case int64:
		switch y := b.(type) {
		case int64:
			return x == y
		case int:
			return x == int64(y)
		case float64:
			return float64(x) == y
		}
		return false
	case float64:
		switch y := b.(type) {
		case float64:
			return x == y
		case int64:
			return x == float64(y)
		case int:
			return x == float64(y)
		}
		return false
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	default:
		ab, aerr := pyyaml.Dump(a, pyyaml.Options{SortKeys: true, AllowUnicode: true})
		bb, berr := pyyaml.Dump(b, pyyaml.Options{SortKeys: true, AllowUnicode: true})
		return aerr == nil && berr == nil && bytes.Equal([]byte(ab), []byte(bb))
	}
}

package cli

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// PreparationError is an expected error while converting a legacy snapshot.
type PreparationError struct {
	Msg string
}

func (e *PreparationError) Error() string { return e.Msg }

func prepErrorf(format string, args ...any) error {
	return &PreparationError{Msg: fmt.Sprintf(format, args...)}
}

func loadLegacyYAML(path string) (*pyyaml.Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, prepErrorf("Cannot read YAML %s: %v", path, err)
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, prepErrorf("Cannot read YAML %s: %v", path, err)
	}
	if v == nil {
		return pyyaml.NewMap(), nil
	}
	m, ok := v.(*pyyaml.Map)
	if !ok {
		return nil, prepErrorf("Expected a YAML mapping in %s", path)
	}
	return m, nil
}

func mapNested(data any, keys ...any) any {
	cur := data
	for _, key := range keys {
		switch k := key.(type) {
		case int:
			list, ok := cur.([]any)
			if !ok || k < 0 || k >= len(list) {
				return nil
			}
			cur = list[k]
		default:
			m, ok := cur.(*pyyaml.Map)
			if !ok || m == nil {
				return nil
			}
			v, found := m.Get(k)
			if !found {
				return nil
			}
			cur = v
		}
	}
	return cur
}

func mapOrEmpty(v any) *pyyaml.Map {
	if m, ok := v.(*pyyaml.Map); ok && m != nil {
		return m
	}
	return pyyaml.NewMap()
}

func setIfPresent(target *pyyaml.Map, key string, value any) {
	if value != nil {
		target.Set(key, value)
	}
}

func readEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, prepErrorf("Cannot read environment file %s: %v", path, err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		k, v, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(k)] = v
	}
	return values, nil
}

func writeLegacyYAML(path string, data *pyyaml.Map) error {
	text, err := pyyaml.Dump(data, pyyaml.Options{AllowUnicode: true, SortKeys: false})
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func tokenURLSafe(nBytes int) string {
	buf := make([]byte, nBytes)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// BuildLegacyAuthelia translates a live Authelia configuration.yml into the
// managed authelia.yml schema, preserving fallback values.
func BuildLegacyAuthelia(fallback, live, liveVars *pyyaml.Map) *pyyaml.Map {
	result := pyyaml.DeepCopy(fallback).(*pyyaml.Map)
	session := mapOrEmpty(live.Value("session"))
	cookie := mapOrEmpty(mapNested(live, "session", "cookies", 0))
	redis := mapOrEmpty(session.Value("redis"))
	authFile := mapOrEmpty(mapNested(live, "authentication_backend", "file"))
	regulation := mapOrEmpty(live.Value("regulation"))
	notifier := mapOrEmpty(live.Value("notifier"))
	notifierSMTP := mapOrEmpty(notifier.Value("smtp"))
	notifierFS := mapOrEmpty(notifier.Value("filesystem"))
	totp := mapOrEmpty(live.Value("totp"))
	access := mapOrEmpty(live.Value("access_control"))

	enabled := true
	if raw, ok := liveVars.Get("authelia_enabled"); ok {
		enabled = truthy(raw)
	}
	result.Set("authelia_enabled", enabled)
	result.Set("admin_authelia_enabled", enabled)
	setIfPresent(result, "aut_domain", liveVars.Value("aut_domain"))
	setIfPresent(result, "authelia_server_address", mapNested(live, "server", "address"))
	setIfPresent(result, "authelia_log_level", mapNested(live, "log", "level"))
	setIfPresent(result, "authelia_log_file_path", mapNested(live, "log", "file_path"))
	setIfPresent(result, "authelia_session_name", session.Value("name"))
	setIfPresent(result, "authelia_session_same_site", session.Value("same_site"))
	setIfPresent(result, "authelia_session_expiration", session.Value("expiration"))
	setIfPresent(result, "authelia_session_inactivity", session.Value("inactivity"))
	setIfPresent(result, "authelia_session_remember_me", session.Value("remember_me"))
	setIfPresent(result, "authelia_cookie_domain", cookie.Value("domain"))
	setIfPresent(result, "authelia_portal_url", cookie.Value("authelia_url"))
	setIfPresent(result, "authelia_default_redirection_url", cookie.Value("default_redirection_url"))

	result.Set("authelia_session_redis_enabled", redis.Len() > 0)
	setIfPresent(result, "authelia_session_redis_host", redis.Value("host"))
	setIfPresent(result, "authelia_session_redis_port", redis.Value("port"))
	setIfPresent(result, "authelia_session_redis_database", redis.Value("database_index"))
	setIfPresent(result, "authelia_session_redis_max_active", redis.Value("maximum_active_connections"))
	setIfPresent(result, "authelia_session_redis_max_idle", redis.Value("minimum_idle_connections"))
	setIfPresent(result, "authelia_session_redis_timeout", redis.Value("timeout"))

	setIfPresent(result, "authelia_storage_local_path", mapNested(live, "storage", "local", "path"))
	setIfPresent(result, "authelia_auth_refresh_interval", mapNested(live, "authentication_backend", "refresh_interval"))
	setIfPresent(result, "authelia_users_file_path", authFile.Value("path"))
	setIfPresent(result, "authelia_users_watch", authFile.Value("watch"))
	setIfPresent(result, "authelia_password_algorithm", mapNested(authFile, "password", "algorithm"))

	setIfPresent(result, "authelia_regulation_modes", regulation.Value("modes"))
	setIfPresent(result, "authelia_regulation_max_retries", regulation.Value("max_retries"))
	setIfPresent(result, "authelia_regulation_find_time", regulation.Value("find_time"))
	setIfPresent(result, "authelia_regulation_ban_time", regulation.Value("ban_time"))

	if _, hasFS := notifier.Get("filesystem"); hasFS {
		result.Set("authelia_notifier_type", "filesystem")
		setIfPresent(result, "authelia_notifier_filesystem_filename", notifierFS.Value("filename"))
	} else if _, hasSMTP := notifier.Get("smtp"); hasSMTP {
		result.Set("authelia_notifier_type", "smtp")
		result.Set("mail_relay_server", true)
		setIfPresent(result, "mail_smtp_timeout", notifierSMTP.Value("timeout"))
		setIfPresent(result, "mail_subject", notifierSMTP.Value("subject"))
		setIfPresent(result, "mail_smtp_disable_starttls", notifierSMTP.Value("disable_starttls"))
		setIfPresent(result, "mail_smtp_disable_require_tls", notifierSMTP.Value("disable_require_tls"))
		setIfPresent(result, "mail_smtp_tls_skip_verify", mapNested(notifierSMTP, "tls", "skip_verify"))
	}

	setIfPresent(result, "authelia_totp_issuer", totp.Value("issuer"))
	setIfPresent(result, "authelia_totp_period", totp.Value("period"))
	setIfPresent(result, "authelia_totp_skew", totp.Value("skew"))
	setIfPresent(result, "authelia_default_policy", access.Value("default_policy"))
	setIfPresent(result, "authelia_access_control_rules", access.Value("rules"))
	result.Set("authelia_users_mode", "selfservice")
	return result
}

// PrepareLegacyConfig builds a managed /etc/easy-ha-proxy config directory from
// a protected legacy snapshot.
func PrepareLegacyConfig(liveDir, controllerDir, outputDir string, stdout io.Writer) error {
	var err error
	if liveDir, err = filepath.Abs(liveDir); err != nil {
		return err
	}
	if resolved, rerr := filepath.EvalSymlinks(liveDir); rerr == nil {
		liveDir = resolved
	}
	if controllerDir, err = filepath.Abs(controllerDir); err != nil {
		return err
	}
	if resolved, rerr := filepath.EvalSymlinks(controllerDir); rerr == nil {
		controllerDir = resolved
	}
	if outputDir, err = filepath.Abs(outputDir); err != nil {
		return err
	}

	reqOrder := []struct {
		key  string
		path string
	}{
		{"live_vars", filepath.Join(liveDir, "opt/haproxy-admin/config/vars.yml")},
		{"live_sites", filepath.Join(liveDir, "opt/haproxy-admin/config/websites.yml")},
		{"live_tcp", filepath.Join(liveDir, "opt/haproxy-admin/config/tcp.yml")},
		{"live_authelia", filepath.Join(liveDir, "opt/authelia/configuration.yml")},
		{"live_users", filepath.Join(liveDir, "opt/authelia/users_database.yml")},
		{"live_env", filepath.Join(liveDir, "opt/authelia/.env")},
		{"controller_authelia", filepath.Join(controllerDir, "ansible/authelia.yml")},
	}
	reqPaths := map[string]string{}
	var missing []string
	for _, r := range reqOrder {
		reqPaths[r.key] = r.path
		if !isRegularFile(r.path) {
			missing = append(missing, r.path)
		}
	}
	if len(missing) > 0 {
		return prepErrorf("Required snapshot files are missing: %s", strings.Join(missing, ", "))
	}
	if _, err := os.Lstat(outputDir); err == nil {
		return prepErrorf("Output directory already exists: %s", outputDir)
	}

	liveVars, err := loadLegacyYAML(reqPaths["live_vars"])
	if err != nil {
		return err
	}
	liveSites, err := loadLegacyYAML(reqPaths["live_sites"])
	if err != nil {
		return err
	}
	liveTCP, err := loadLegacyYAML(reqPaths["live_tcp"])
	if err != nil {
		return err
	}
	liveAuthelia, err := loadLegacyYAML(reqPaths["live_authelia"])
	if err != nil {
		return err
	}
	liveUsers, err := loadLegacyYAML(reqPaths["live_users"])
	if err != nil {
		return err
	}
	fallbackAuthelia, err := loadLegacyYAML(reqPaths["controller_authelia"])
	if err != nil {
		return err
	}
	liveEnv, err := readEnvFile(reqPaths["live_env"])
	if err != nil {
		return err
	}

	users, ok := liveUsers.Value("users").(*pyyaml.Map)
	if !ok || users == nil || users.Len() == 0 {
		return prepErrorf("The live Authelia users database is empty or invalid.")
	}

	mailPass := liveEnv["MAIL_SMTP_PASSWORD"]
	if mailPass == "" {
		mailPass = liveEnv["SMTP_PASSWORD"]
	}
	if mailPass == "" {
		mailPass = strVal(mapNested(liveAuthelia, "notifier", "smtp", "password"))
	}
	secretsData := pyyaml.NewMap()
	secretsData.Set("authelia_session_secret", mapNested(liveAuthelia, "session", "secret"))
	secretsData.Set("authelia_jwt_secret", mapNested(liveAuthelia, "identity_validation", "reset_password", "jwt_secret"))
	secretsData.Set("authelia_storage_key", mapNested(liveAuthelia, "storage", "encryption_key"))
	secretsData.Set("mail_smtp_pass", mailPass)
	secretsData.Set("haproxy_admin_proxy_secret", tokenURLSafe(48))

	var missingSecrets []string
	for _, key := range []string{"authelia_session_secret", "authelia_jwt_secret", "authelia_storage_key"} {
		if !truthy(secretsData.Value(key)) {
			missingSecrets = append(missingSecrets, key)
		}
	}
	if len(missingSecrets) > 0 {
		return prepErrorf("Required live secrets are missing: %s", strings.Join(missingSecrets, ", "))
	}

	autheliaData := BuildLegacyAuthelia(fallbackAuthelia, liveAuthelia, liveVars)
	rootDomain := strVal(liveVars.Value("root_domain"))
	adminDomain := strVal(liveVars.Value("admin_domain"))
	autheliaDomain := strVal(liveVars.Value("aut_domain"))
	if autheliaDomain == "" {
		autheliaDomain = strVal(autheliaData.Value("aut_domain"))
	}
	if rootDomain == "" || adminDomain == "" || autheliaDomain == "" {
		return prepErrorf("Cannot determine root/admin/Authelia domains.")
	}

	metadata := pyyaml.NewMap()
	metadata.Set("product", Product)
	metadata.Set("configured_at", time.Now().UTC().Format(time.RFC3339Nano))
	metadata.Set("repository", DefaultRepository)
	metadata.Set("test_mode", false)
	metadata.Set("test_server_ip", "")
	metadata.Set("admin_domain", adminDomain)
	metadata.Set("authelia_domain", autheliaDomain)
	metadata.Set("migration_source", liveDir)
	metadata.Set("migration_mode", "legacy_snapshot")

	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp(parent, "."+filepath.Base(outputDir)+".tmp-*")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	usersInitial := pyyaml.NewMap()
	usersInitial.Set("authelia_users", users)
	files := []struct {
		name string
		data *pyyaml.Map
	}{
		{"vars.yml", liveVars},
		{"authelia.yml", autheliaData},
		{"authelia_users_initial.yml", usersInitial},
		{"websites.yml", liveSites},
		{"tcp.yml", liveTCP},
		{"secrets.yml", secretsData},
		{"metadata.yml", metadata},
	}
	for _, f := range files {
		if err := writeLegacyYAML(filepath.Join(tmpDir, f.name), f.data); err != nil {
			return err
		}
	}
	invPath := filepath.Join(tmpDir, "inventory.ini")
	invText := "[easy_ha_proxy]\nlocalhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n"
	if err := os.WriteFile(invPath, []byte(invText), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(invPath, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpDir, outputDir); err != nil {
		return err
	}
	cleanup = false

	siteCount := 0
	if list, ok := liveSites.Value("sites").([]any); ok {
		siteCount = len(list)
	}
	tcpCount := 0
	if raw, ok := liveTCP.Get("tcp_proxies"); ok {
		if list, ok := raw.([]any); ok {
			tcpCount = len(list)
		}
	} else if raw, ok := liveTCP.Get("tcp"); ok {
		if list, ok := raw.([]any); ok {
			tcpCount = len(list)
		}
	}

	fmt.Fprintf(stdout, "Prepared config: %s\n", outputDir)
	fmt.Fprintf(stdout, "Sites preserved: %d\n", siteCount)
	fmt.Fprintf(stdout, "TCP proxies preserved: %d\n", tcpCount)
	fmt.Fprintf(stdout, "Authelia users preserved: %d\n", users.Len())
	fmt.Fprintln(stdout, "Secrets copied from the protected live snapshot; values were not printed.")
	fmt.Fprintln(stdout, "No files were uploaded to the server and no services were changed.")
	return nil
}

// RunPrepareLegacyCLI implements "easy-ha-proxy-agent prepare-legacy-config".
func RunPrepareLegacyCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("prepare-legacy-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	liveDir := fs.String("live-dir", "", "path to legacy snapshot live/ directory")
	controllerDir := fs.String("controller-dir", "", "path to controller source directory")
	outputDir := fs.String("output-dir", "", "destination directory for prepared config")
	if err := fs.Parse(args); err != nil {
		// --help is a successful probe: install.sh runs `prepare-legacy-config
		// --help` to decide whether the installed agent can prepare a legacy
		// snapshot, and a non-zero exit makes it re-fetch the agent every time.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *liveDir == "" || *controllerDir == "" || *outputDir == "" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent prepare-legacy-config --live-dir DIR --controller-dir DIR --output-dir DIR")
		return 2
	}
	if err := PrepareLegacyConfig(*liveDir, *controllerDir, *outputDir, stdout); err != nil {
		fmt.Fprintf(stderr, "ERROR: %v\n", err)
		return 2
	}
	return 0
}

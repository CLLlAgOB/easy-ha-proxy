package certd

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

type pkixAttr = pkix.AttributeTypeAndValue

func (d *Daemon) dnsProfilePath(name string) (string, error) {
	if !dnsProfileRe.MatchString(name) {
		return "", vErr("invalid DNS provider profile name")
	}
	return filepath.Join(d.Opts.DNSCredentialsDir, name+".ini"), nil
}

func propagationSeconds(v any) int {
	seconds := dnsPropagationDefault
	if v != nil {
		if n, ok := pyIntLoose(v); ok {
			seconds = int(n)
		}
	}
	if seconds < dnsPropagationMin {
		seconds = dnsPropagationMin
	}
	if seconds > dnsPropagationMax {
		seconds = dnsPropagationMax
	}
	return seconds
}

// pyIntLoose is int(value) for JSON values.
func pyIntLoose(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
	}
	return 0, false
}

func certbotTimeout(profile string, propagation any) time.Duration {
	if profile == "" {
		return certbotTimeoutSeconds * time.Second
	}
	return time.Duration(certbotTimeoutSeconds+propagationSeconds(propagation)) * time.Second
}

func (d *Daemon) installedDNSPlugins() map[string]bool {
	found := map[string]bool{}
	res, err := runBounded([]string{d.Opts.CertbotBin, "plugins", "--non-interactive"}, certbotQuickTimeoutSeconds*time.Second, nil)
	if err != nil {
		return found
	}
	for _, line := range strings.Split(string(res.stdout), "\n") {
		entry := strings.TrimSpace(line)
		if strings.HasPrefix(entry, "* ") {
			found[strings.TrimSpace(entry[2:])] = true
		}
	}
	return found
}

func (d *Daemon) listDNSProviders() map[string]any {
	available := d.listedDNSPlugins()
	profiles := []any{}
	if isDir(d.Opts.DNSCredentialsDir) {
		for _, path := range globSorted(filepath.Join(d.Opts.DNSCredentialsDir, "*.ini")) {
			name := stem(path)
			if !dnsProfileRe.MatchString(name) {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			provider := ""
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "# provider:") {
					provider = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					break
				}
			}
			fi, err := os.Stat(path)
			if err != nil {
				continue
			}
			profiles = append(profiles, map[string]any{
				"name": name, "provider": provider,
				"plugin_available": available[dnsProviders[provider].Plugin] && dnsProviders[provider].Plugin != "",
				"updated_ts":       fi.ModTime().Unix(),
			})
		}
	}
	providers := map[string]any{}
	for _, name := range dnsProviderOrder {
		spec := dnsProviders[name]
		providers[name] = map[string]any{"plugin": spec.Plugin, "snap": spec.Snap, "keys": spec.Keys,
			"available": available[spec.Plugin]}
	}
	return map[string]any{"profiles": profiles, "providers": providers}
}

type storedProfile struct {
	Provider string
	Values   map[string]string
	Order    []string
}

func readDNSProfile(path string) storedProfile {
	out := storedProfile{Values: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range splitPyLines(string(raw)) {
		if strings.HasPrefix(line, "# provider:") {
			out.Provider = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.Contains(line, " = ") && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, " = ", 2)
			key := strings.TrimSpace(parts[0])
			if _, seen := out.Values[key]; !seen {
				out.Order = append(out.Order, key)
			}
			out.Values[key] = parts[1]
		}
	}
	return out
}

// splitPyLines is str.splitlines() for the separators that matter here.
func splitPyLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func (d *Daemon) dnsBindingPath(lineage string) (string, error) {
	if lineage == "" || lineage == "." || lineage == ".." || filepath.Base(lineage) != lineage || strings.Contains(lineage, "/") {
		return "", vErr("invalid Certbot lineage name")
	}
	return filepath.Join(d.Opts.LetsEncryptRoot, "easy-ha-proxy-dns", lineage+".json"), nil
}

func renewalAuthenticator(conf string) (string, error) {
	raw, err := os.ReadFile(conf)
	if err != nil {
		return "", err
	}
	if m := authenticRe.FindSubmatch(raw); m != nil {
		return string(m[1]), nil
	}
	return "", nil
}

func (d *Daemon) dnsProfileLineages(profile string) ([]string, error) {
	used := []string{}
	for _, path := range globSorted(filepath.Join(d.Opts.LetsEncryptRoot, "easy-ha-proxy-dns", "*.json")) {
		name := stem(path)
		conf := filepath.Join(d.Opts.LetsEncryptRoot, "renewal", name+".conf")
		if !isFile(conf) {
			continue
		}
		auth, err := renewalAuthenticator(conf)
		if err != nil {
			return nil, vErr("cannot read DNS renewal binding for %s", name)
		}
		if auth != "dns-route53" {
			continue
		}
		raw, err := os.ReadFile(path)
		var binding map[string]any
		if err != nil || json.Unmarshal(raw, &binding) != nil || binding == nil {
			return nil, vErr("cannot read DNS renewal binding for %s", name)
		}
		if binding["profile"] == profile {
			used = append(used, name)
		}
	}
	return used, nil
}

// route53Environment is _route53_environment.
func (d *Daemon) route53Environment(profile string) ([]string, error) {
	path, err := d.dnsProfilePath(profile)
	if err != nil {
		return nil, err
	}
	stored := readDNSProfile(path)
	if stored.Provider != "route53" {
		return nil, vErr("DNS profile %s is not a Route53 profile", pyRepr(profile))
	}
	keys := dnsProviders["route53"].Keys
	for _, k := range keys {
		if strings.TrimSpace(stored.Values[k]) == "" {
			return nil, vErr("Route53 requires both AWS access key and secret key")
		}
	}
	raw, _ := os.ReadFile(path)
	valid := iniHasDefault(string(raw), keys, stored.Values)
	if !valid {
		lines := []string{"# provider: route53", "[default]"}
		for _, k := range keys {
			lines = append(lines, k+" = "+stored.Values[k])
		}
		if err := writePrivateFile(path, []byte(strings.Join(lines, "\n")+"\n")); err != nil {
			return nil, err
		}
	}
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AWS_") {
			env = append(env, kv)
		}
	}
	abs := resolvePath(path)
	return append(env, "AWS_SHARED_CREDENTIALS_FILE="+abs, "AWS_PROFILE=default", "AWS_DEFAULT_PROFILE=default",
		"AWS_CONFIG_FILE=/dev/null", "AWS_EC2_METADATA_DISABLED=true", "BOTO_CONFIG=/dev/null"), nil
}

// iniHasDefault checks a [default] section holding exactly these values
// (configparser.RawConfigParser semantics, enough for files this daemon writes).
func iniHasDefault(text string, keys []string, values map[string]string) bool {
	section := ""
	found := map[string]string{}
	inDefault := false
	for _, line := range splitPyLines(text) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed[1 : len(trimmed)-1]
			if section == "default" {
				inDefault = true
			}
			continue
		}
		if section == "" {
			return false // option before any section: MissingSectionHeaderError
		}
		if section == "default" {
			if k, v, ok := strings.Cut(line, "="); ok {
				found[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	if !inDefault {
		return false
	}
	for _, k := range keys {
		if found[k] != values[k] {
			return false
		}
	}
	return true
}

func (d *Daemon) saveDNSProvider(payload map[string]any) (map[string]any, error) {
	name := strings.ToLower(strings.TrimSpace(pyx.StrOr(payload["name"])))
	provider := strings.ToLower(strings.TrimSpace(pyx.StrOr(payload["provider"])))
	spec, ok := dnsProviders[provider]
	if !ok {
		return nil, vErr("unsupported DNS provider")
	}
	path, err := d.dnsProfilePath(name)
	if err != nil {
		return nil, err
	}
	supplied, ok := payload["credentials"].(map[string]any)
	if !ok {
		return nil, vErr("credentials must be an object")
	}
	for k := range supplied {
		if !containsStr(spec.Keys, k) {
			return nil, vErr("credentials contain an unsupported field")
		}
	}
	stored := readDNSProfile(path)
	kept := map[string]string{}
	if stored.Provider == provider {
		kept = stored.Values
	}
	if stored.Provider != provider {
		used, err := d.dnsProfileLineages(name)
		if err != nil {
			return nil, err
		}
		if len(used) > 0 {
			return nil, vErr("this DNS profile is used for automatic renewal; reissue those lineages first")
		}
	}
	lines := []string{"# provider: " + provider}
	if provider == "route53" {
		lines = append(lines, "[default]")
	}
	for _, key := range spec.Keys {
		raw, present := supplied[key]
		value := ""
		if present && raw != nil {
			value = pyx.Str(raw)
		}
		if !present || raw == nil || value == "" {
			kv, ok := kept[key]
			if !ok || kv == "" {
				continue
			}
			value = kv
		}
		if len([]rune(value)) > dnsValueMax {
			return nil, vErr("%s exceeds the size limit", key)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, vErr("%s contains a line break", key)
		}
		lines = append(lines, key+" = "+value)
	}
	base := 1
	if provider == "route53" {
		base = 2
	}
	if len(lines) == base {
		return nil, vErr("no credentials were supplied")
	}
	if provider == "route53" && len(lines) != 4 {
		return nil, vErr("Route53 requires both AWS access key and secret key")
	}
	if err := writePrivateFile(path, []byte(strings.Join(lines, "\n")+"\n")); err != nil {
		return nil, err
	}
	log.Printf("Saved DNS provider profile %s (%s)", name, provider)
	return map[string]any{"name": name, "provider": provider}, nil
}

func (d *Daemon) deleteDNSProvider(name, actor string) (map[string]any, error) {
	path, err := d.dnsProfilePath(strings.ToLower(strings.TrimSpace(name)))
	if err != nil {
		return nil, err
	}
	used, err := d.dnsProfileLineages(stem(path))
	if err != nil {
		return nil, err
	}
	if len(used) > 0 {
		return nil, vErr("this DNS profile is used for automatic renewal by %s", strings.Join(used, ", "))
	}
	existed := exists(path)
	var kept string
	if existed {
		provider := readDNSProfile(path).Provider
		kept, err = d.trashPut("dns_provider", stem(path), []string{path}, actor, map[string]any{"provider": provider}, nil)
		if err != nil {
			return nil, err
		}
	}
	before := trashListing([]string{path})
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		d.trashSettle(kept, before, []string{path})
		return nil, err
	}
	d.trashCommit(kept)
	var trashID any
	if kept != "" {
		trashID = kept
	}
	return map[string]any{"name": stem(path), "deleted": existed, "trash_id": trashID}, nil
}

func (d *Daemon) dnsProviderOf(name string) (string, error) {
	path, err := d.dnsProfilePath(name)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", vErr("no DNS provider profile named %s", stem(path))
		}
		return "", vErr("the DNS provider profile cannot be read")
	}
	for _, line := range splitPyLines(string(raw)) {
		if strings.HasPrefix(line, "# provider:") {
			provider := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if _, ok := dnsProviders[provider]; ok {
				return provider, nil
			}
			break
		}
	}
	return "", vErr("the DNS provider profile is unusable")
}

func (d *Daemon) dnsChallengeFlags(profile string, propagation any) ([]string, error) {
	provider, err := d.dnsProviderOf(profile)
	if err != nil {
		return nil, err
	}
	spec := dnsProviders[provider]
	if !d.installedDNSPlugins()[spec.Plugin] {
		return nil, vErr("the %s certbot plugin is not installed; install and connect the %s snap first", spec.Plugin, spec.Snap)
	}
	seconds := propagationSeconds(propagation)
	flags := []string{"--" + spec.Plugin, "--preferred-challenges", "dns-01"}
	if provider != "route53" {
		path, _ := d.dnsProfilePath(profile)
		flags = append(flags, "--"+spec.Plugin+"-credentials", path)
	}
	return append(flags, "--"+spec.Plugin+"-propagation-seconds", strconv.Itoa(seconds)), nil
}

// certbotSettings is _get_certbot_settings.
func (d *Daemon) certbotSettings() (string, string, int, string) {
	cfg := loadYAML(d.Opts.ConfigYAML)
	email := yamlStrOr(cfg["certbot_email"], "admin@example.com")
	keyType := yamlStrOr(cfg["cert_key_type"], "ecdsa")
	rsaSize := 3072
	if v := cfg["rsa_key_size"]; yamlTruthy(v) {
		switch x := v.(type) {
		case int:
			rsaSize = x
		case float64:
			rsaSize = int(x)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
				rsaSize = n
			}
		}
	}
	curve := yamlStrOr(cfg["ecdsa_curve"], "secp256r1")
	return email, keyType, rsaSize, curve
}

func yamlTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case int:
		return x != 0
	case float64:
		return x != 0
	}
	return true
}

func yamlStrOr(v any, def string) string {
	if !yamlTruthy(v) {
		return def
	}
	return fmt.Sprint(v)
}

// runCertbotForLineage is _run_certbot_for_lineage.
func (d *Daemon) runCertbotForLineage(lineage, domain string, altNames []string, keyType, email string, rsaKeySize int,
	ecdsaCurve, accountID, dnsProfile string, dnsPropagation any) (map[string]any, error) {
	names := append([]string{domain}, altNames...)
	sanFlags := []string{}
	wildcard := false
	for _, n := range names {
		if n == "" {
			continue
		}
		sanFlags = append(sanFlags, "-d", n)
		if strings.HasPrefix(n, "*.") {
			wildcard = true
		}
	}
	if wildcard && dnsProfile == "" {
		return nil, vErr("a wildcard certificate requires DNS-01; select a DNS provider profile")
	}
	var challenge []string
	if dnsProfile != "" {
		flags, err := d.dnsChallengeFlags(dnsProfile, dnsPropagation)
		if err != nil {
			return nil, err
		}
		challenge = flags
	} else {
		challenge = []string{"--standalone", "--http-01-port", strconv.Itoa(certbotHTTPPort), "--http-01-address",
			certbotHTTPAddr, "--preferred-challenges", "http-01"}
	}
	cmd := []string{d.Opts.CertbotBin, "certonly", "--non-interactive", "--agree-tos", "--email", email}
	cmd = append(cmd, challenge...)
	cmd = append(cmd, "--key-type", keyType, "--cert-name", lineage, "--config-dir", d.Opts.LetsEncryptRoot, "--keep-until-expiring")
	if accountID != "" {
		cmd = append(cmd, "--account", accountID)
	}
	if keyType == "rsa" {
		cmd = append(cmd, "--rsa-key-size", strconv.Itoa(rsaKeySize))
	} else if keyType == "ecdsa" {
		cmd = append(cmd, "--elliptic-curve", ecdsaCurve)
	}
	cmd = append(cmd, sanFlags...)
	if d.Opts.DryRun {
		cmd = append(cmd, "--dry-run")
	}
	log.Printf("Running certbot for lineage %s: %s", lineage, strings.Join(cmd, " "))
	bindingPath, err := d.dnsBindingPath(lineage)
	if err != nil {
		return nil, err
	}
	previous, prevErr := os.ReadFile(bindingPath)
	hadPrevious := prevErr == nil
	route53 := false
	if dnsProfile != "" {
		if p, err := d.dnsProviderOf(dnsProfile); err == nil && p == "route53" {
			route53 = true
		} else if err != nil {
			return nil, err
		}
	}
	var env []string
	restore := func() {
		if hadPrevious {
			_ = writePrivateFile(bindingPath, previous)
		} else {
			_ = os.Remove(bindingPath)
		}
	}
	if route53 {
		if env, err = d.route53Environment(dnsProfile); err != nil {
			return nil, err
		}
		if !d.Opts.DryRun {
			raw, _ := json.Marshal(map[string]any{"profile": dnsProfile})
			if err := writePrivateFile(bindingPath, []byte(strings.Replace(string(raw), `":"`, `": "`, 1))); err != nil {
				return nil, err
			}
		}
	}
	res, err := runBounded(cmd, certbotTimeout(dnsProfile, dnsPropagation), env)
	if err != nil {
		if route53 && !d.Opts.DryRun {
			restore()
		}
		return nil, err
	}
	if !d.Opts.DryRun {
		if res.rc == 0 {
			if !route53 && hadPrevious {
				conf := filepath.Join(d.Opts.LetsEncryptRoot, "renewal", lineage+".conf")
				if isFile(conf) {
					if auth, err := renewalAuthenticator(conf); err == nil && auth != "" && auth != "dns-route53" {
						_ = os.Remove(bindingPath)
					}
				}
			}
		} else if route53 {
			restore()
		}
	}
	return map[string]any{"lineage": lineage, "rc": res.rc, "stdout": string(res.stdout), "stderr": string(res.stderr),
		"cmd": strings.Join(cmd, " ")}, nil
}

// RenewCertificates is renew_certificates, for `certd --renew`. It logs as
// logging.basicConfig(format="%(levelname)s: %(message)s") does.
func RenewCertificates(opts Options) int {
	d := &Daemon{Opts: opts}
	failed := false
	root := opts.LetsEncryptRoot
	for _, conf := range globSorted(filepath.Join(root, "renewal", "*.conf")) {
		name := stem(conf)
		err := func() error {
			var env []string
			bindingPath, err := d.dnsBindingPath(name)
			if err != nil {
				return err
			}
			auth, err := renewalAuthenticator(conf)
			if err != nil {
				return err
			}
			if exists(bindingPath) && auth == "dns-route53" {
				raw, err := os.ReadFile(bindingPath)
				if err != nil {
					return err
				}
				var binding map[string]any
				if err := json.Unmarshal(raw, &binding); err != nil {
					return err
				}
				if env, err = d.route53Environment(pyx.Str(binding["profile"])); err != nil {
					return err
				}
			}
			command := []string{opts.CertbotBin, "renew", "--non-interactive", "--quiet", "--cert-name", name,
				"--config-dir", root, "--no-random-sleep-on-renew"}
			res, err := runBounded(command, (certbotTimeoutSeconds+dnsPropagationMax)*time.Second, env)
			if err != nil {
				return err
			}
			if res.rc != 0 {
				failed = true
				fmt.Fprintf(os.Stderr, "ERROR: Certbot renewal failed for %s (rc=%d): %s\n", name, res.rc, pyx.TruncRunes(strings.TrimSpace(string(res.stderr)), 400))
			}
			return nil
		}()
		if err != nil {
			failed = true
			fmt.Fprintf(os.Stderr, "ERROR: Cannot renew %s: %v\n", name, err)
		}
	}
	if failed {
		return 1
	}
	return 0
}

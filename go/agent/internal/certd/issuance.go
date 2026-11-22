package certd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// setCertPermissions is _set_cert_permissions: root:haproxy 0640.
func setCertPermissions(path string) error {
	if g, err := user.LookupGroup("haproxy"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(path, 0, gid)
		}
	}
	return os.Chmod(path, 0o640)
}

// reloadHAProxy is _reload_haproxy: (rc, stdout, stderr); rc nil on a dry run.
func (d *Daemon) reloadHAProxy() (*int, string, string) {
	if d.Opts.DryRun {
		return nil, "", ""
	}
	if isFile(d.Opts.HAProxyBin) && isFile(d.Opts.HAProxyCfg) {
		res, err := runBounded([]string{d.Opts.HAProxyBin, "-c", "-f", d.Opts.HAProxyCfg}, haproxyCheckTimeout*time.Second, nil)
		if err == nil && res.rc != 0 {
			rc := res.rc
			return &rc, string(res.stdout), string(res.stderr)
		}
	}
	res, err := runBounded([]string{"systemctl", "reload", "haproxy"}, haproxyReloadTimeout*time.Second, nil)
	if err != nil {
		rc := -1
		return &rc, "", fmt.Sprintf("systemctl reload haproxy failed: %v", err)
	}
	rc := res.rc
	return &rc, string(res.stdout), string(res.stderr)
}

func rcOK(rc *int) bool { return rc == nil || *rc == 0 }

func rcValue(rc *int) any {
	if rc == nil {
		return nil
	}
	return *rc
}

type pinnedErr struct{ msg string }

func (e *pinnedErr) Error() string { return e.msg }

// shadowConflicts is _shadow_conflicts.
func shadowConflicts(destination string, data []byte) []string {
	certs, err := loadPEMCertificates(data)
	if err != nil || len(certs) == 0 {
		return nil
	}
	incoming := certs[0]
	family := keyFamily(incoming)
	names := map[string]bool{}
	for _, n := range certDNSNames(incoming) {
		names[strings.ToLower(n)] = true
	}
	if len(names) == 0 {
		return nil
	}
	conflicts := []string{}
	destResolved := resolvePath(destination)
	for _, other := range globSorted(filepath.Join(filepath.Dir(destination), "*.pem")) {
		if resolvePath(other) == destResolved {
			continue
		}
		raw, err := os.ReadFile(other)
		if err != nil {
			continue
		}
		existing, err := loadPEMCertificates(raw)
		if err != nil || len(existing) == 0 || keyFamily(existing[0]) != family {
			continue
		}
		shared := []string{}
		for _, n := range certDNSNames(existing[0]) {
			if names[strings.ToLower(n)] {
				shared = append(shared, strings.ToLower(n))
			}
		}
		sortStrings(shared)
		for _, name := range shared {
			conflicts = append(conflicts, fmt.Sprintf("%s (already in %s)", name, filepath.Base(other)))
		}
	}
	return conflicts
}

// activateServerPEM is _activate_server_pem.
func (d *Daemon) activateServerPEM(destination string, data []byte, overridePin, allowShadow bool) (bool, *int, string, string, error) {
	if !allowShadow {
		if conflicts := shadowConflicts(destination, data); len(conflicts) > 0 {
			if len(conflicts) > 5 {
				conflicts = conflicts[:5]
			}
			return false, nil, "", "", vErrS("another certificate already covers " + strings.Join(conflicts, "; ") +
				". HAProxy would pick one of them by file name and ignore the other. Keep this one as a standby instead, " +
				"and put it into service when you want it.")
		}
	}
	if !overridePin {
		if held := d.readPin(stem(destination)); held != "" {
			return false, nil, "", "", vErr("%s is being served by the standby %s; hand it back to Let's Encrypt first",
				stem(destination), pyRepr(held))
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return false, nil, "", "", err
	}
	previous, prevErr := os.ReadFile(destination)
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".cert-")
	if err != nil {
		return false, nil, "", "", err
	}
	temporary := tmp.Name()
	defer os.Remove(temporary)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, nil, "", "", err
	}
	_ = tmp.Close()
	if err := setCertPermissions(temporary); err != nil {
		return false, nil, "", "", err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return false, nil, "", "", err
	}
	rc, stdout, stderr := d.reloadHAProxy()
	if !rcOK(rc) {
		if prevErr != nil {
			_ = os.Remove(destination)
		} else {
			_ = os.WriteFile(destination, previous, 0o640)
			_ = setCertPermissions(destination)
		}
		return false, rc, stdout, stderr, nil
	}
	return true, rc, stdout, stderr, nil
}

type touchedPEM struct {
	stem, dest string
	previous   []byte
	had        bool
}

// putBackPEMs is _put_back_pems.
func (d *Daemon) putBackPEMs(touched []touchedPEM) string {
	changed := []touchedPEM{}
	for _, t := range touched {
		cur, err := os.ReadFile(t.dest)
		have := err == nil
		if err != nil && !os.IsNotExist(err) {
			changed = append(changed, t)
			continue
		}
		if have != t.had || (have && string(cur) != string(t.previous)) {
			changed = append(changed, t)
		}
	}
	if len(changed) == 0 {
		return "; nothing had changed"
	}
	failed := []string{}
	for _, t := range changed {
		var err error
		if !t.had {
			if rerr := os.Remove(t.dest); rerr != nil && !os.IsNotExist(rerr) {
				err = rerr
			}
		} else {
			err = func() error {
				tmp, err := os.CreateTemp(filepath.Dir(t.dest), ".cert-")
				if err != nil {
					return err
				}
				name := tmp.Name()
				defer os.Remove(name)
				if _, err := tmp.Write(t.previous); err != nil {
					_ = tmp.Close()
					return err
				}
				_ = tmp.Close()
				if err := setCertPermissions(name); err != nil {
					return err
				}
				return os.Rename(name, t.dest)
			}()
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", t.stem, err))
		}
	}
	rc, _, reloadErr := d.reloadHAProxy()
	names := []string{}
	for _, t := range changed {
		names = append(names, t.stem)
	}
	if len(failed) > 0 {
		msg := "; putting back failed for " + strings.Join(failed, ", ") + ": these files still hold the new certificate"
		if !rcOK(rc) {
			msg += "; HAProxy rollback reload failed: " + pyx.TruncRunes(strings.TrimSpace(reloadErr), 300)
		}
		return msg
	}
	if !rcOK(rc) {
		return fmt.Sprintf("; %s put back as they were, but HAProxy did not reload: %s", strings.Join(names, ", "),
			pyx.TruncRunes(strings.TrimSpace(reloadErr), 300))
	}
	return "; " + strings.Join(names, ", ") + " put back as they were"
}

// verifyExternalChain is _verify_external_chain.
func verifyExternalChain(certs []*x509Cert, caPath string) (bool, string) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return false, "openssl is required to verify an external certificate chain"
	}
	work, err := os.MkdirTemp("", "haproxy-cert-verify-")
	if err != nil {
		return false, err.Error()
	}
	defer os.RemoveAll(work)
	leaf := filepath.Join(work, "leaf.pem")
	_ = os.WriteFile(leaf, certPEM(certs[0]), 0o600)
	command := []string{openssl, "verify", "-partial_chain", "-CAfile", caPath}
	if len(certs) > 1 {
		chain := filepath.Join(work, "chain.pem")
		var buf []byte
		for _, c := range certs[1:] {
			buf = append(buf, certPEM(c)...)
		}
		_ = os.WriteFile(chain, buf, 0o600)
		command = append(command, "-untrusted", chain)
	}
	command = append(command, leaf)
	res, err := runBounded(command, opensslTimeout*time.Second, nil)
	if err != nil {
		return false, err.Error()
	}
	details := string(res.stderr)
	if details == "" {
		details = string(res.stdout)
	}
	if details == "" {
		details = "certificate chain verification failed"
	}
	return res.rc == 0, strings.TrimSpace(details)
}

func findCertFileByDomainInDir(dir, domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || !isDir(dir) {
		return ""
	}
	for _, path := range globSorted(filepath.Join(dir, "*.pem")) {
		if cert := firstCertificate(path); cert != nil && certMatchesDomain(cert, domain) {
			return path
		}
	}
	return ""
}

func (d *Daemon) leLiveDir() string { return filepath.Join(d.Opts.LetsEncryptRoot, "live") }

func sortedDirEntries(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sortStrings(out)
	return out
}

func (d *Daemon) findLEFullchainForDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	live := d.leLiveDir()
	for _, cand := range []string{domain, domain + "-ecdsa", domain + "-rsa"} {
		p := filepath.Join(live, cand, "fullchain.pem")
		if isFile(p) {
			return p
		}
	}
	for _, sub := range sortedDirEntries(live) {
		if !isDir(sub) {
			continue
		}
		cand := filepath.Join(sub, "fullchain.pem")
		if !isFile(cand) {
			continue
		}
		if cert := firstCertificate(cand); cert != nil && certMatchesDomain(cert, domain) {
			return cand
		}
	}
	return ""
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// certStatusForDomain is get_cert_status_for_domain.
func (d *Daemon) certStatusForDomain(domain string) map[string]any {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return map[string]any{"state": "no_domain", "short": "no domain",
			"tooltip": "Cannot check the certificate because the domain is empty.", "haproxy_path": nil, "haproxy_has": false,
			"haproxy_not_after": nil, "haproxy_days_left": nil, "le_path": nil, "le_has": false, "le_not_after": nil, "le_days_left": nil}
	}
	hap := findCertFileByDomainInDir(d.Opts.HAProxyCertsDir, domain)
	le := d.findLEFullchainForDomain(domain)
	hapInfo := loadCertInfo(hap)
	leInfo := loadCertInfo(le)
	result := map[string]any{"state": "", "short": "", "tooltip": "", "haproxy_path": strOrNil(hap), "haproxy_has": hapInfo != nil,
		"haproxy_not_after": nil, "haproxy_days_left": nil, "le_path": strOrNil(le), "le_has": leInfo != nil,
		"le_not_after": nil, "le_days_left": nil}
	if hapInfo != nil {
		result["haproxy_not_after"] = fmtDate(hapInfo.NotAfter)
		result["haproxy_days_left"] = hapInfo.DaysLeft
	}
	if leInfo != nil {
		result["le_not_after"] = fmtDate(leInfo.NotAfter)
		result["le_days_left"] = leInfo.DaysLeft
	}
	switch {
	case hapInfo == nil && leInfo == nil:
		result["state"], result["short"] = "missing", "No certificate"
		result["tooltip"] = "No HAProxy certificate and no Let's Encrypt certificate were found for this domain."
	case leInfo != nil && hapInfo == nil:
		result["state"] = "letsencrypt_only"
		if leInfo.DaysLeft < 0 {
			result["short"] = "LE: expired"
		} else {
			result["short"] = "LE until " + fmtDate(leInfo.NotAfter)
		}
		result["tooltip"] = "A Let's Encrypt certificate exists, but the matching HAProxy PEM is missing. The deploy hook may not have completed."
	case hapInfo != nil && leInfo == nil:
		days := hapInfo.DaysLeft
		switch {
		case days < 0:
			result["state"], result["short"] = "expired", "Expired"
		case days <= hapInfo.WarnDays:
			result["state"], result["short"] = "warning", fmt.Sprintf("Expires soon (%d days)", days)
		default:
			result["state"], result["short"] = "haproxy_only", "OK until "+fmtDate(hapInfo.NotAfter)
		}
		result["tooltip"] = "An HAProxy certificate exists without a Let's Encrypt lineage. It may come from an external or internal certificate authority."
	default:
		days := hapInfo.DaysLeft
		if leInfo.DaysLeft < days {
			days = leInfo.DaysLeft
		}
		warn := hapInfo.WarnDays
		if leInfo.WarnDays < warn {
			warn = leInfo.WarnDays
		}
		switch {
		case days < 0:
			result["state"], result["short"] = "expired", "Expired"
			result["tooltip"] = "The certificate has expired and must be renewed."
		case days <= warn:
			result["state"], result["short"] = "warning", fmt.Sprintf("Expires soon (%d days)", days)
			result["tooltip"] = fmt.Sprintf("The certificate is approaching expiration. Days remaining: %d.", days)
		default:
			result["state"], result["short"] = "ok", "OK until "+fmtDate(hapInfo.NotAfter)
			result["tooltip"] = "The certificate is valid."
		}
	}
	return result
}

// buildCertItemForList is _build_cert_item_for_list.
func buildCertItemForList(path string) map[string]any {
	cert := firstCertificate(path)
	if cert == nil {
		return nil
	}
	info := loadCertInfo(path)
	if info == nil {
		return nil
	}
	state, short := "ok", "OK until "+fmtDate(info.NotAfter)
	if info.DaysLeft < 0 {
		state, short = "expired", "Expired"
	} else if info.DaysLeft <= info.WarnDays {
		state, short = "warning", fmt.Sprintf("Expires soon (%d days)", info.DaysLeft)
	}
	return map[string]any{"path": path, "not_after": fmtDate(info.NotAfter), "days_left": info.DaysLeft, "state": state,
		"short": short, "domains": certDNSNames(cert)}
}

// ---------------------------------------------------------------------------
// Delivery targets
// ---------------------------------------------------------------------------

func (d *Daemon) deliveryPaths(name string) (string, string, string) {
	return filepath.Join(d.Opts.DeliveryDir, name+".json"), filepath.Join(d.Opts.DeliveryDir, name+".key"),
		filepath.Join(d.Opts.DeliveryDir, name+".known_hosts")
}

func deliveryName(value any) (string, error) {
	text := strings.ToLower(strings.TrimSpace(pyx.StrOr(value)))
	if !deliveryNameRe.MatchString(text) {
		return "", vErr("name must be 1-40 characters of a-z, 0-9 and -, starting with a letter or digit")
	}
	return text, nil
}

func (d *Daemon) deliveryPublic(record map[string]any, name string) map[string]any {
	_, key, known := d.deliveryPaths(name)
	domains := []any{}
	if l, ok := record["domains"].([]any); ok {
		domains = l
	}
	lastResult := pyx.Get(record, "last_result", map[string]any{})
	return map[string]any{
		"name": name, "enabled": pyx.Truthy(pyx.Get(record, "enabled", true)), "domains": domains,
		"transport": pyx.Get(record, "transport", "sftp"), "host": pyx.Get(record, "host", ""),
		"port": pyx.Get(record, "port", 22), "user": pyx.Get(record, "user", ""),
		"remote_path": pyx.Get(record, "remote_path", ""), "format": pyx.Get(record, "format", "pfx"),
		"post_command": pyx.Get(record, "post_command", ""), "pfx_password_set": pyx.Truthy(record["pfx_password"]),
		"key_present": isFile(key), "host_key_present": isFile(known), "last_result": lastResult,
	}
}

func readJSONMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not an object")
	}
	return m, nil
}

func (d *Daemon) listCertDeliveries() map[string]any {
	items := []any{}
	if isDir(d.Opts.DeliveryDir) {
		for _, path := range globSorted(filepath.Join(d.Opts.DeliveryDir, "*.json")) {
			record, err := readJSONMap(path)
			if err != nil {
				log.Printf("cannot read %s (%v)", path, err)
				continue
			}
			items = append(items, d.deliveryPublic(record, stem(path)))
		}
	}
	return map[string]any{"ok": true, "targets": items, "formats": deliveryFormats, "transports": deliveryTransports,
		"legacy_hooks": d.unmanagedDeliveryHooks()}
}

func (d *Daemon) unmanagedDeliveryHooks() []string {
	found := []string{}
	if !isDir(d.Opts.HooksDir) {
		return found
	}
	for _, path := range globSorted(filepath.Join(d.Opts.HooksDir, "*.sh")) {
		switch filepath.Base(path) {
		case "905-haproxy-pems-reload.sh", "906-deliver-certificates.sh", "910-mail-notify.sh":
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(raw)
		if strings.Contains(text, "sftp") || strings.Contains(text, "scp ") || strings.Contains(text, "pkcs12") {
			found = append(found, filepath.Base(path))
		}
	}
	return found
}

var (
	deliveryHostRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	deliveryUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@\\-]{0,127}$`)
	controlCharRe  = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// jsonIndent is json.dumps(v, indent=2, ensure_ascii=False).
func jsonIndent(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func (d *Daemon) saveCertDelivery(payload map[string]any) (map[string]any, error) {
	name, err := deliveryName(payload["name"])
	if err != nil {
		return nil, err
	}
	recordPath, keyFile, knownFile := d.deliveryPaths(name)
	if err := os.MkdirAll(d.Opts.DeliveryDir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(d.Opts.DeliveryDir, 0o700)
	existing := map[string]any{}
	if isFile(recordPath) {
		if existing, err = readJSONMap(recordPath); err != nil {
			return nil, err
		}
	} else if len(globSorted(filepath.Join(d.Opts.DeliveryDir, "*.json"))) >= maxDeliveryTargets {
		return nil, vErr("at most %d delivery targets", maxDeliveryTargets)
	}
	domains := []string{}
	if l, ok := payload["domains"].([]any); ok {
		for _, v := range l {
			s := pyx.Str(v)
			if strings.TrimSpace(s) == "" {
				continue
			}
			n, err := normalizeDNSName(s, false)
			if err != nil {
				return nil, err
			}
			domains = append(domains, n)
		}
	}
	if len(domains) == 0 {
		return nil, vErr("choose at least one certificate to deliver")
	}
	if len(domains) > 1 && d.resolveLineage(domains[0]) != "" && d.lineageCovering(domains) == "" {
		return nil, vErrS("no one certificate covers all of " + strings.Join(domains, ", ") +
			"; a target receives one certificate, so give each certificate a target of its own")
	}
	transport := strings.ToLower(strings.TrimSpace(orDefault(payload["transport"], "sftp")))
	if !containsStr(deliveryTransports, transport) {
		return nil, vErr("transport must be sftp or scp")
	}
	format := strings.ToLower(strings.TrimSpace(orDefault(payload["format"], "pfx")))
	if !containsStr(deliveryFormats, format) {
		return nil, vErr("format must be pfx, pem-pair or pem-combined")
	}
	host := strings.TrimSpace(pyx.StrOr(payload["host"]))
	userName := strings.TrimSpace(pyx.StrOr(payload["user"]))
	remotePath := strings.TrimSpace(pyx.StrOr(payload["remote_path"]))
	if host == "" || userName == "" || remotePath == "" {
		return nil, vErr("host, user and remote path are all required")
	}
	if len([]rune(host)) > 253 || strings.HasPrefix(host, "-") {
		return nil, vErr("host must be a valid hostname or IP address")
	}
	if net.ParseIP(strings.Trim(host, "[]")) == nil && !deliveryHostRe.MatchString(host) {
		return nil, vErr("host must be a valid hostname or IP address")
	}
	if !deliveryUserRe.MatchString(userName) {
		return nil, vErr("user contains unsupported characters")
	}
	if len([]rune(remotePath)) > 512 || controlCharRe.MatchString(remotePath) || containsStr(regexp.MustCompile(`[/\\]`).Split(remotePath, -1), "..") {
		return nil, vErr("remote_path is invalid")
	}
	port := int64(22)
	if pyx.Truthy(payload["port"]) {
		n, ok := pyIntLoose(payload["port"])
		if !ok {
			return nil, vErr("port must be a number")
		}
		port = n
	}
	if port < 1 || port > 65535 {
		return nil, vErr("port must be between 1 and 65535")
	}
	postCommand := strings.TrimSpace(pyx.StrOr(payload["post_command"]))
	if len([]rune(postCommand)) > 2048 || strings.Contains(postCommand, "\x00") {
		return nil, vErr("post_command is invalid")
	}
	pfxPassword := pyx.StrOr(pyx.Get(existing, "pfx_password", ""))
	if v, ok := payload["pfx_password"]; ok && v != nil {
		pfxPassword = pyx.Str(v)
	}
	if len([]rune(pfxPassword)) > 1024 || strings.Contains(pfxPassword, "\x00") {
		return nil, vErr("pfx_password is invalid")
	}
	record := map[string]any{
		"enabled": pyx.Truthy(pyx.Get(payload, "enabled", true)), "domains": domains, "transport": transport,
		"host": host, "port": port, "user": userName, "remote_path": remotePath, "format": format,
		"post_command": postCommand, "pfx_password": pfxPassword,
		"last_result": pyx.Get(existing, "last_result", map[string]any{}),
	}
	if m := payload["private_key"]; pyx.Truthy(m) {
		if err := writeSecret(keyFile, strings.TrimSpace(pyx.Str(m))+"\n"); err != nil {
			return nil, err
		}
	}
	if hk := payload["host_key"]; pyx.Truthy(hk) {
		if err := writeSecret(knownFile, strings.TrimSpace(pyx.Str(hk))+"\n"); err != nil {
			return nil, err
		}
	}
	raw := jsonIndent(record)
	tmp := strings.TrimSuffix(recordPath, ".json") + ".json.tmp"
	if err := writeModeFile(tmp, raw, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, recordPath); err != nil {
		return nil, err
	}
	anyDomains := make([]any, len(domains))
	for i, s := range domains {
		anyDomains[i] = s
	}
	record["domains"] = anyDomains
	return d.deliveryPublic(record, name), nil
}

func orDefault(v any, def string) string {
	s := pyx.StrOr(v)
	if s == "" {
		return def
	}
	return s
}

func writeSecret(path, text string) error {
	tmp := path + ".tmp"
	if err := writeModeFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (d *Daemon) deleteCertDelivery(name any, actor string) (map[string]any, error) {
	checked, err := deliveryName(name)
	if err != nil {
		return nil, err
	}
	a, b, c := d.deliveryPaths(checked)
	paths := []string{a, b, c}
	kept := ""
	if exists(a) || exists(b) || exists(c) {
		details := map[string]any{}
		if record, err := readJSONMap(a); err == nil {
			for _, k := range []string{"lineage", "host", "format", "transport"} {
				switch record[k].(type) {
				case string, json.Number, float64:
					details[k] = record[k]
				}
			}
		}
		if kept, err = d.trashPut("cert_delivery", checked, paths, actor, details, nil); err != nil {
			return nil, err
		}
	}
	before := trashListing(paths)
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			d.trashSettle(kept, before, paths)
			return nil, err
		}
	}
	d.trashCommit(kept)
	return map[string]any{"name": checked, "deleted": true, "trash_id": strOrNil(kept)}, nil
}

func (d *Daemon) testCertDelivery(name any) (map[string]any, error) {
	checked, err := deliveryName(name)
	if err != nil {
		return nil, err
	}
	recordPath, _, _ := d.deliveryPaths(checked)
	if !isFile(recordPath) {
		return nil, vErr("no delivery target named %s", checked)
	}
	record, err := readJSONMap(recordPath)
	if err != nil {
		return nil, err
	}
	domains := []string{}
	for _, v := range pyx.List(record["domains"]) {
		domains = append(domains, pyx.Str(v))
	}
	if len(domains) == 0 {
		return nil, vErr("this target has no certificate chosen")
	}
	lineage := d.lineageCovering(domains)
	if lineage == "" {
		if d.resolveLineage(domains[0]) == "" {
			return nil, vErr("there is no issued certificate for %s to send yet", domains[0])
		}
		return nil, vErrS("no one certificate covers all of " + strings.Join(domains, ", ") +
			"; a target receives one certificate, so give each certificate a target of its own")
	}
	res, err := runBounded([]string{d.Opts.DeliveryWorker, "--lineage", lineage, "--target", checked}, deliveryTimeout*time.Second, nil)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(strings.ToValidUTF8(string(res.stdout)+string(res.stderr), "�"))
	outcome := map[string]any{"ok": res.rc == 0, "output": tailRunes(output, 4000), "lineage": filepath.Base(lineage)}
	record["last_result"] = map[string]any{"ok": res.rc == 0, "at": time.Now().Unix(), "detail": tailRunes(output, 400)}
	raw := jsonIndent(record)
	tmp := strings.TrimSuffix(recordPath, ".json") + ".json.tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return nil, err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, recordPath); err != nil {
		return nil, err
	}
	return outcome, nil
}

func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func (d *Daemon) resolveLineage(domain string) string {
	live := d.leLiveDir()
	if !isDir(live) {
		return ""
	}
	for _, cand := range []string{domain, domain + "-ecdsa", domain + "-rsa"} {
		p := filepath.Join(live, cand)
		if isFile(filepath.Join(p, "fullchain.pem")) {
			return p
		}
	}
	for _, p := range sortedDirEntries(live) {
		chain := filepath.Join(p, "fullchain.pem")
		if !isFile(chain) {
			continue
		}
		if cert := firstCertificate(chain); cert != nil && certMatchesDomain(cert, domain) {
			return p
		}
	}
	return ""
}

func (d *Daemon) lineageCovering(domains []string) string {
	first := d.resolveLineage(domains[0])
	candidates := []string{}
	if first != "" {
		candidates = append(candidates, first)
	}
	if live := d.leLiveDir(); isDir(live) {
		for _, p := range sortedDirEntries(live) {
			if p != first {
				candidates = append(candidates, p)
			}
		}
	}
	for _, p := range candidates {
		cert := firstCertificate(filepath.Join(p, "fullchain.pem"))
		if cert == nil {
			continue
		}
		all := true
		for _, dm := range domains {
			if !certMatchesDomain(cert, dm) {
				all = false
			}
		}
		if all {
			return p
		}
	}
	return ""
}

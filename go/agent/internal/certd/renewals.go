package certd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func lineageDomain(name string) string {
	loc := lineageSuffix.FindStringIndex(name)
	if loc != nil {
		name = name[:loc[0]]
	}
	return strings.ToLower(name)
}

func renewalTextWithPause(text string, paused bool) string {
	kept := []string{}
	skipNext := false
	for _, line := range splitPyLines(text) {
		if skipNext {
			skipNext = false
			if strings.ToLower(strings.ReplaceAll(strings.TrimSpace(line), " ", "")) == "autorenew=false" {
				continue
			}
		}
		if strings.TrimSpace(line) == renewalPauseMarker {
			skipNext = true
			continue
		}
		kept = append(kept, line)
	}
	if paused {
		section := -1
		for i, line := range kept {
			if strings.TrimSpace(line) == "[renewalparams]" {
				section = i
				break
			}
		}
		if section < 0 {
			kept = append(kept, "[renewalparams]", renewalPauseMarker, "autorenew = False")
		} else {
			tail := append([]string{renewalPauseMarker, "autorenew = False"}, kept[section+1:]...)
			kept = append(kept[:section+1], tail...)
		}
	}
	return strings.Join(kept, "\n") + "\n"
}

func (d *Daemon) syncRenewalPauses(domains []string) (map[string]any, error) {
	paused := map[string]bool{}
	for _, dm := range domains {
		n, err := normalizeDNSName(dm, false)
		if err != nil {
			return nil, err
		}
		paused[n] = true
	}
	renewalDir := filepath.Join(d.Opts.LetsEncryptRoot, "renewal")
	changed := []string{}
	lineages := map[string]bool{}
	names := []string{}
	if isDir(renewalDir) {
		for _, conf := range globSorted(filepath.Join(renewalDir, "*.conf")) {
			if isSymlink(conf) || !isFile(conf) {
				continue
			}
			name := strings.TrimSuffix(filepath.Base(conf), ".conf")
			want := paused[lineageDomain(name)]
			lineages[name] = want
			names = append(names, name)
			raw, err := os.ReadFile(conf)
			if err != nil {
				return nil, err
			}
			text := string(raw)
			updated := renewalTextWithPause(text, want)
			if updated == text {
				continue
			}
			fi, err := os.Stat(conf)
			if err != nil {
				return nil, err
			}
			tmp, err := os.CreateTemp(renewalDir, ".pause.")
			if err != nil {
				return nil, err
			}
			name2 := tmp.Name()
			if _, err := tmp.WriteString(updated); err != nil {
				_ = tmp.Close()
				_ = os.Remove(name2)
				return nil, err
			}
			_ = tmp.Close()
			_ = os.Chmod(name2, fi.Mode().Perm())
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				_ = os.Chown(name2, int(st.Uid), int(st.Gid))
			}
			if err := os.Rename(name2, conf); err != nil {
				_ = os.Remove(name2)
				return nil, err
			}
			changed = append(changed, name)
		}
	}
	if len(changed) > 0 {
		log.Printf("renewal pauses updated for: %s", strings.Join(changed, ", "))
	}
	pausedList := []string{}
	for _, n := range names {
		if lineages[n] {
			pausedList = append(pausedList, n)
		}
	}
	sort.Strings(pausedList)
	without := []string{}
	for dm := range paused {
		found := false
		for n := range lineages {
			if lineageDomain(n) == dm {
				found = true
			}
		}
		if !found {
			without = append(without, dm)
		}
	}
	sort.Strings(without)
	return map[string]any{"ok": true, "paused": pausedList, "changed": changed, "without_lineage": without}, nil
}

var reservedSuffixes = []string{".test", ".example", ".invalid", ".localhost", ".local"}

func (d *Daemon) latestAccountID(accountsDir string) string {
	entries, err := os.ReadDir(accountsDir)
	if err != nil {
		return ""
	}
	latest := ""
	var latestTime time.Time
	for _, e := range entries {
		p := filepath.Join(accountsDir, e.Name())
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			continue
		}
		ctime := fi.ModTime()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ctime = time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
		}
		if latest == "" || ctime.After(latestTime) {
			latest, latestTime = e.Name(), ctime
		}
	}
	return latest
}

func (d *Daemon) handleCertsIssue(body map[string]any) (int, map[string]any) {
	domain := strings.TrimSpace(pyx.StrOr(body["domain"]))
	altRaw := body["alt_names"]
	keyTypesRaw := body["key_types"]
	dnsProfile := strings.ToLower(strings.TrimSpace(pyx.StrOr(body["dns_profile"])))
	dnsPropagation := body["dns_propagation"]
	allowWildcard := dnsProfile != ""
	if domain == "" {
		return 200, map[string]any{"ok": false, "error": "domain is required"}
	}
	domain, err := normalizeDNSName(domain, allowWildcard)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": "invalid domain: " + err.Error()}
	}
	altList, ok := altRaw.([]any)
	if !ok {
		altList = nil
	}
	altNames := []string{}
	for _, x := range altList {
		if !pyx.Truthy(x) {
			continue
		}
		n, err := normalizeDNSName(pyx.Str(x), allowWildcard)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": "invalid alternative domain: " + err.Error()}
		}
		altNames = append(altNames, n)
	}
	if len(altNames) > 100 {
		return 400, map[string]any{"ok": false, "error": "too many alternative domains"}
	}
	all := append([]string{domain}, altNames...)
	wildcard := false
	for _, n := range all {
		if strings.HasPrefix(n, "*.") {
			wildcard = true
		}
	}
	if wildcard && dnsProfile == "" {
		return 400, map[string]any{"ok": false, "error": "a wildcard certificate requires DNS-01; select a DNS provider profile for this site"}
	}
	if dnsProfile != "" {
		if _, err := d.dnsChallengeFlags(dnsProfile, dnsPropagation); err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
	}
	reserved := []string{}
	for _, n := range all {
		if n == "localhost" {
			reserved = append(reserved, n)
			continue
		}
		for _, sfx := range reservedSuffixes {
			if strings.HasSuffix(n, sfx) {
				reserved = append(reserved, n)
				break
			}
		}
	}
	if len(reserved) > 0 {
		return 200, map[string]any{"ok": false, "domain": domain, "alt_names": altNames, "source": "letsencrypt",
			"dry_run": d.Opts.DryRun, "error": "Let's Encrypt cannot issue certificates for reserved/private domains: " +
				strings.Join(reserved, ", ") + ". Select Internal CA for this site."}
	}
	if !isFile(d.Opts.CertbotBin) {
		return 200, map[string]any{"ok": false, "domain": domain, "alt_names": altNames, "source": "letsencrypt",
			"dry_run": d.Opts.DryRun, "error": "Certbot executable was not found: " + d.Opts.CertbotBin}
	}
	settings, err := d.certbotSettings()
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	keyTypes := []string{}
	if l, ok := keyTypesRaw.([]any); ok && len(l) > 0 {
		for _, kt := range l {
			if s, ok := kt.(string); ok && (s == "rsa" || s == "ecdsa") {
				keyTypes = append(keyTypes, s)
			}
		}
	}
	if len(keyTypes) == 0 {
		keyTypes = []string{settings.keyType}
	}
	accountID := d.latestAccountID(filepath.Join(d.Opts.LetsEncryptRoot, "accounts/acme-v02.api.letsencrypt.org/directory"))
	results := []any{}
	anyOK := false
	lineageBase := strings.TrimPrefix(domain, "*.")
	for _, kt := range keyTypes {
		lineage := lineageBase
		if len(keyTypes) > 1 {
			lineage = lineageBase + "-" + kt
		}
		res, err := d.runCertbotForLineage(lineage, domain, altNames, kt, settings.email, settings.rsaSize, settings.curve, accountID, dnsProfile, dnsPropagation)
		if err != nil {
			if isValueErr(err) {
				panic(err)
			}
			panic(err)
		}
		results = append(results, res)
		if res["rc"] == 0 {
			anyOK = true
		}
	}
	var pemRC *int
	pemStdout, pemStderr := "", ""
	if anyOK && exists(d.Opts.PEMsScript) && !d.Opts.DryRun {
		log.Printf("Running PEM rebuild script: %s", d.Opts.PEMsScript)
		if res, err := runBounded([]string{d.Opts.PEMsScript}, pemRebuildTimeout*time.Second, nil); err == nil {
			rc := res.rc
			pemRC, pemStdout, pemStderr = &rc, string(res.stdout), string(res.stderr)
		} else {
			panic(err)
		}
	}
	ok2 := anyOK && rcOK(pemRC)
	errText := ""
	if !anyOK {
		for _, r := range results {
			m := r.(map[string]any)
			errText = strings.TrimSpace(firstNonEmpty(pyx.StrOr(m["stderr"]), pyx.StrOr(m["stdout"])))
			if errText != "" {
				break
			}
		}
		if errText == "" {
			errText = "Certbot did not issue a certificate; inspect haproxy-certd logs."
		}
	} else if !rcOK(pemRC) {
		errText = firstNonEmpty(strings.TrimSpace(pemStderr), strings.TrimSpace(pemStdout), "The HAProxy PEM rebuild hook failed.")
	}
	response := map[string]any{"ok": ok2, "domain": domain, "alt_names": altNames, "key_types": keyTypes, "results": results,
		"dry_run": d.Opts.DryRun, "pem_rc": rcValue(pemRC), "pem_stdout": pemStdout, "pem_stderr": pemStderr}
	if errText != "" {
		response["error"] = errText
		d.reportAlert("certificate.renewal_failed", domain, "Certificate issuance failed for "+domain, pyx.TruncRunes(errText, 1000))
	}
	return 200, response
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// The CA root and the internal CA
// ---------------------------------------------------------------------------

func (d *Daemon) prepareCARoot(create bool) (string, error) {
	root := d.Opts.CARootDir
	if isSymlink(root) {
		return "", vErr("certificate authority root must not be a symlink")
	}
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
	}
	if exists(root) {
		if !isDir(root) {
			return "", vErr("certificate authority root is not a directory")
		}
		if err := os.Chmod(root, 0o700); err != nil {
			return "", err
		}
	}
	return root, nil
}

func (d *Daemon) prepareCASubdir(name string, create bool) (string, error) {
	if name != "internal" && name != "external" {
		return "", vErr("invalid certificate authority directory")
	}
	root, err := d.prepareCARoot(create)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, name)
	if isSymlink(dir) {
		return "", vErr("certificate authority directory %s must not be a symlink", pyRepr(name))
	}
	if create {
		if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	if exists(dir) {
		if !isDir(dir) {
			return "", vErr("certificate authority path %s is not a directory", pyRepr(name))
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (d *Daemon) internalCAPaths() (string, string, error) {
	dir, err := d.prepareCASubdir("internal", false)
	if err != nil {
		return "", "", err
	}
	return filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt"), nil
}

func (d *Daemon) ensureInternalCA() (*x509.Certificate, crypto.Signer, bool, error) {
	d.caMu.Lock()
	defer d.caMu.Unlock()
	return d.ensureInternalCALocked()
}

func (d *Daemon) ensureInternalCALocked() (*x509.Certificate, crypto.Signer, bool, error) {
	if _, err := d.prepareCARoot(false); err != nil {
		return nil, nil, false, err
	}
	keyPath, certPath, err := d.internalCAPaths()
	if err != nil {
		return nil, nil, false, err
	}
	if isFile(keyPath) && isFile(certPath) {
		keyRaw, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, false, err
		}
		key, err := loadAnyPrivateKey(keyRaw)
		if err != nil {
			return nil, nil, false, err
		}
		certRaw, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, false, err
		}
		cert := firstCertificateIn(certRaw)
		if cert == nil {
			return nil, nil, false, fmt.Errorf("Unable to load PEM file")
		}
		if !samePublicKey(key.Public(), cert.PublicKey) {
			return nil, nil, false, vErr("internal CA certificate and private key do not match")
		}
		return cert, key, false, nil
	}
	if exists(keyPath) || exists(certPath) {
		return nil, nil, false, vErr("internal CA is incomplete; restore or remove its directory")
	}
	root, err := d.prepareCARoot(true)
	if err != nil {
		return nil, nil, false, err
	}
	cert, key, err := generateInternalCAMaterial()
	if err != nil {
		return nil, nil, false, err
	}
	tmp, err := os.MkdirTemp(root, ".internal-ca-")
	if err != nil {
		return nil, nil, false, err
	}
	defer os.RemoveAll(tmp)
	if err := writeInternalCAMaterial(tmp, cert, key); err != nil {
		return nil, nil, false, err
	}
	if err := os.Rename(tmp, filepath.Dir(keyPath)); err != nil {
		return nil, nil, false, err
	}
	return cert, key, true, nil
}

func loadAnyPrivateKey(raw []byte) (crypto.Signer, error) {
	rest := raw
	for {
		var block *pemBlock
		block, rest = pemDecode(rest)
		if block == nil {
			return nil, fmt.Errorf("Could not deserialize key data")
		}
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return parsePrivateKeyDER(block.Bytes)
		}
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func subjectKeyID(pub crypto.PublicKey) []byte {
	der := publicKeyBytes(pub)
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil
	}
	sum := sha1.Sum(spki.Key.Bytes)
	return sum[:]
}

// generateInternalCAMaterial is _generate_internal_ca_material.
func generateInternalCAMaterial() (*x509.Certificate, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	subject := pkix.Name{CommonName: "Easy HA Proxy Local Root CA"}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: subject, Issuer: subject,
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(3650 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, MaxPathLenZero: false,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: subjectKeyID(&key.PublicKey), SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func writeInternalCAMaterial(dir string, cert *x509.Certificate, key crypto.Signer) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	keyPEM, err := keyPEMPKCS8(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Join(dir, "ca.key"), 0o600)
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM(cert), 0o644); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(dir, "ca.crt"), 0o644)
}

// buildInternalServerPEM is _build_internal_server_pem.
func buildInternalServerPEM(caCert *x509.Certificate, caKey crypto.Signer, names []string) (*x509.Certificate, []byte, error) {
	if len(names) == 0 {
		return nil, nil, vErr("at least one DNS name is required")
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(397 * 24 * time.Hour),
		DNSNames: names, BasicConstraintsValid: true, IsCA: false,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:   subjectKeyID(&leafKey.PublicKey),
		AuthorityKeyId: subjectKeyID(caKey.Public()), SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if _, isRSA := caKey.(*rsa.PrivateKey); !isRSA {
		tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := keyPEMPKCS8(leafKey)
	if err != nil {
		return nil, nil, err
	}
	return leaf, append(certPEM(leaf), keyPEM...), nil
}

type leafEntry struct {
	path  string
	names []string
}

func (d *Daemon) internalLeafCertificates(authority *x509.Certificate) ([]leafEntry, error) {
	dir := d.Opts.HAProxyCertsDir
	if !isDir(dir) {
		return nil, nil
	}
	out := []leafEntry{}
	for _, path := range globSorted(filepath.Join(dir, "*.pem")) {
		if isSymlink(path) || !isFile(path) {
			continue
		}
		if _, err := ensureWithin(dir, path); err != nil {
			return nil, err
		}
		cert := firstCertificate(path)
		if cert == nil || !certificateIsIssuedBy(cert, authority) {
			continue
		}
		raw := certDNSNames(cert)
		primary := strings.ToLower(firstAttr(cert.Subject.Names, oidCN))
		ordered := []string{}
		if containsStr(raw, primary) {
			ordered = append(ordered, primary)
		}
		rest := []string{}
		for _, n := range raw {
			if n != primary {
				rest = append(rest, n)
			}
		}
		sort.Strings(rest)
		ordered = append(ordered, rest...)
		if len(ordered) == 0 {
			return nil, vErr("internal certificate has no DNS names: %s", path)
		}
		norm := []string{}
		for _, n := range ordered {
			v, err := normalizeDNSName(n, false)
			if err != nil {
				return nil, err
			}
			norm = append(norm, v)
		}
		out = append(out, leafEntry{path, norm})
	}
	return out, nil
}

func replaceServerPEMWithoutReload(dest string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".cert-rotate-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Close()
	if err := setCertPermissions(name); err != nil {
		return err
	}
	return os.Rename(name, dest)
}

func caItem(id, kind string, certs []*x509.Certificate) map[string]any {
	first := certs[0]
	return map[string]any{"id": id, "kind": kind, "name": certificateLabel(first), "certificates": len(certs),
		"not_before": fmtDate(first.NotBefore), "not_after": fmtDate(first.NotAfter), "sha256": fingerprint(first)}
}

func (d *Daemon) listCertificateAuthorities() (map[string]any, error) {
	if _, err := d.prepareCARoot(false); err != nil {
		return nil, err
	}
	trusted := d.loadClientAuthIDs()
	trustedSet := map[string]bool{}
	for _, id := range trusted {
		trustedSet[id] = true
	}
	decorate := func(item map[string]any, certs []*x509.Certificate) map[string]any {
		item["client_auth"] = trustedSet[pyx.Str(item["id"])]
		item["subject_cns"] = subjectCNs(certs)
		return item
	}
	var internal any
	_, certPath, err := d.internalCAPaths()
	if err != nil {
		return nil, err
	}
	if isFile(certPath) {
		raw, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		certs, err := loadPEMCertificates(raw)
		if err != nil {
			return nil, err
		}
		if len(certs) > 0 {
			internal = decorate(caItem("internal", "internal", certs), certs)
		}
	}
	external := []any{}
	extDir, err := d.prepareCASubdir("external", false)
	if err != nil {
		return nil, err
	}
	if isDir(extDir) {
		for _, path := range globSorted(filepath.Join(extDir, "*.pem")) {
			raw, err := os.ReadFile(path)
			var certs []*x509.Certificate
			if err == nil {
				certs, err = validateCABundle(raw)
			}
			if err != nil {
				log.Printf("Skipping invalid CA bundle %s: %v", path, err)
				continue
			}
			item := decorate(caItem(stem(path), "external", certs), certs)
			item["path"] = path
			external = append(external, item)
		}
	}
	ids := append([]string{}, trusted...)
	ids = uniqueSorted(ids)
	revoked, err := d.loadRevokedFingerprints()
	if err != nil {
		return nil, err
	}
	return map[string]any{"internal": internal, "external": external, "client_auth_ids": ids,
		"revoked_client_certificates": revoked}, nil
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func (d *Daemon) mtlsDir(create bool) (string, error) {
	dir := d.Opts.MTLSDir
	if isSymlink(dir) {
		return "", vErr("the client authentication directory must not be a symlink")
	}
	if create {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	if exists(dir) {
		if !isDir(dir) {
			return "", vErr("the client authentication path is not a directory")
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			return "", err
		}
	}
	return dir, nil
}

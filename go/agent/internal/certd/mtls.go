package certd

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/hostfile"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func writePublicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".mtls-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (d *Daemon) clientAuthTrustPath() (string, error) {
	root, err := d.prepareCARoot(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, mtlsTrustFile), nil
}

func (d *Daemon) loadClientAuthIDs() []string {
	path, err := d.clientAuthTrustPath()
	if err != nil || !isFile(path) {
		return []string{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("cannot read the client authentication list: %v", err)
		return []string{}
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		log.Printf("cannot read the client authentication list: %v", err)
		return []string{}
	}
	ids, ok := payload["ids"].([]any)
	if !ok {
		return []string{}
	}
	out := []string{}
	for _, v := range ids {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (d *Daemon) caCertificates(caID string) ([]*x509.Certificate, error) {
	if caID == "internal" {
		_, path, err := d.internalCAPaths()
		if err != nil {
			return nil, err
		}
		if !isFile(path) {
			return nil, vErr("the internal certificate authority does not exist")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return loadPEMCertificates(raw)
	}
	s, err := safeSlug(caID)
	if err != nil {
		return nil, err
	}
	safe := strings.ToLower(s)
	ext, err := d.prepareCASubdir("external", false)
	if err != nil {
		return nil, err
	}
	path, err := ensureWithin(ext, filepath.Join(ext, safe+".pem"))
	if err != nil {
		return nil, err
	}
	if !isFile(path) {
		return nil, vErr("certificate authority %s was not found", pyRepr(safe))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return validateCABundle(raw)
}

func (d *Daemon) issuerListPath(caID string) (string, error) {
	dir, err := d.mtlsDir(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "issuers-"+caID+".list"), nil
}

// rebuildClientAuthMaterial is _rebuild_client_auth_material.
func (d *Daemon) rebuildClientAuthMaterial(ids []string) (map[string][]string, error) {
	dir, err := d.mtlsDir(true)
	if err != nil {
		return nil, err
	}
	resolved := map[string][]string{}
	order := []string{}
	var bundle []byte
	seenCNs := map[string]string{}
	for _, id := range ids {
		certs, err := d.caCertificates(id)
		if err != nil {
			return nil, err
		}
		names := subjectCNs(certs)
		if len(names) == 0 {
			return nil, vErr("certificate authority %s has no Common Name, so a certificate it signed cannot be told apart from another authority's", pyRepr(id))
		}
		for _, n := range names {
			if owner, ok := seenCNs[strings.ToLower(n)]; ok && owner != id {
				return nil, vErr("%s and %s both use the Common Name %s; a site could not tell their certificates apart",
					pyRepr(id), pyRepr(owner), pyRepr(n))
			}
			seenCNs[strings.ToLower(n)] = id
		}
		if _, dup := resolved[id]; !dup {
			order = append(order, id)
		}
		resolved[id] = names
		for _, c := range certs {
			bundle = append(bundle, certPEM(c)...)
		}
	}
	for _, id := range order {
		path, err := d.issuerListPath(id)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		for _, n := range resolved[id] {
			b.WriteString(n + "\n")
		}
		if err := writePublicFile(path, []byte(b.String())); err != nil {
			return nil, err
		}
	}
	liveRaw, _ := os.ReadFile(d.Opts.HAProxyCfg)
	live := strings.ToValidUTF8(string(liveRaw), "�")
	for _, path := range globSorted(filepath.Join(dir, "issuers-*.list")) {
		id := strings.TrimPrefix(stem(path), "issuers-")
		if _, ok := resolved[id]; ok {
			continue
		}
		if strings.Contains(live, filepath.Base(path)) {
			if err := writePublicFile(path, []byte(mtlsEmptyMarker)); err != nil {
				return nil, err
			}
		} else {
			_ = os.Remove(path)
		}
	}
	content := bundle
	if len(content) == 0 {
		content = []byte(mtlsEmptyMarker)
	}
	if err := writePublicFile(filepath.Join(dir, mtlsBundleName), content); err != nil {
		return nil, err
	}
	revoked := filepath.Join(dir, mtlsRevokedName)
	if !isFile(revoked) {
		if err := writePublicFile(revoked, []byte(mtlsEmptyMarker)); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

func (d *Daemon) loadRevokedFingerprints() ([]string, error) {
	dir, err := d.mtlsDir(false)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, mtlsRevokedName)
	values := []string{}
	if !isFile(path) {
		return values, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range splitPyLines(strings.ToValidUTF8(string(raw), "�")) {
		c := strings.ToLower(strings.TrimSpace(line))
		if c != "" && !strings.HasPrefix(c, "#") {
			values = append(values, c)
		}
	}
	return values, nil
}

func (d *Daemon) handleCAClientAuth(body map[string]any) (int, map[string]any) {
	raw, ok := body["ids"].([]any)
	if !ok || len(raw) > 64 {
		return 400, map[string]any{"ok": false, "error": "ids must be a list of CA identifiers"}
	}
	ids := []string{}
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			return 400, map[string]any{"ok": false, "error": "ids must be a list of CA identifiers"}
		}
		c := strings.ToLower(strings.TrimSpace(s))
		if c == "" {
			continue
		}
		if c != "internal" {
			slug, err := safeSlug(c)
			if err != nil {
				return 400, map[string]any{"ok": false, "error": err.Error()}
			}
			c = strings.ToLower(slug)
		}
		if !containsStr(ids, c) {
			ids = append(ids, c)
		}
	}
	d.caMu.Lock()
	resolved, err := d.rebuildClientAuthMaterial(ids)
	if err != nil {
		d.caMu.Unlock()
		if isValueErr(err) {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		return 500, map[string]any{"ok": false, "error": "cannot write client authentication material: " + pyOSErr(err)}
	}
	path, err := d.clientAuthTrustPath()
	if err == nil {
		raw := jsonIndent(map[string]any{"version": 1, "ids": ids})
		err = hostfile.WriteAtomic(path, append(raw, '\n'), 0o600)
	}
	d.caMu.Unlock()
	if err != nil {
		panic(err)
	}
	rc, _, errText := d.reloadHAProxy()
	reloadErr := ""
	if rc == nil || *rc != 0 {
		reloadErr = pyx.TruncRunes(strings.TrimSpace(errText), 400)
	}
	message := "No certificate authority is trusted for client authentication."
	if len(ids) > 0 {
		message = fmt.Sprintf("Client authentication trusts %d certificate authorities.", len(ids))
	}
	issuers := map[string]any{}
	for k, v := range resolved {
		issuers[k] = v
	}
	return 200, map[string]any{"ok": true, "ids": ids, "issuers": issuers, "reload_rc": rcValue(rc), "reload_error": reloadErr,
		"message": message}
}

var nonHexRe = regexp.MustCompile(`[^0-9a-fA-F]`)

func (d *Daemon) handleCARevoked(body map[string]any) (int, map[string]any) {
	raw, ok := body["fingerprints"].([]any)
	if !ok || len(raw) > mtlsMaxRevoked {
		return 400, map[string]any{"ok": false, "error": fmt.Sprintf("fingerprints must be a list of at most %d entries", mtlsMaxRevoked)}
	}
	values := []string{}
	for _, entry := range raw {
		s, ok := entry.(string)
		if !ok {
			return 400, map[string]any{"ok": false, "error": "each fingerprint must be a string"}
		}
		c := strings.ToLower(nonHexRe.ReplaceAllString(s, ""))
		if c == "" {
			continue
		}
		if !sha256HexRe.MatchString(c) {
			return 400, map[string]any{"ok": false, "error": pyRepr(strings.TrimSpace(s)) + " is not a SHA-256 fingerprint"}
		}
		if !containsStr(values, c) {
			values = append(values, c)
		}
	}
	d.caMu.Lock()
	dir, err := d.mtlsDir(true)
	if err == nil {
		var b strings.Builder
		b.WriteString(mtlsEmptyMarker)
		for _, v := range values {
			b.WriteString(v + "\n")
		}
		err = writePublicFile(filepath.Join(dir, mtlsRevokedName), []byte(b.String()))
	}
	d.caMu.Unlock()
	if err != nil {
		return 500, map[string]any{"ok": false, "error": "cannot write the revocation list: " + pyOSErr(err)}
	}
	rc, _, errText := d.reloadHAProxy()
	reloadErr := ""
	if rc == nil || *rc != 0 {
		reloadErr = pyx.TruncRunes(strings.TrimSpace(errText), 400)
	}
	return 200, map[string]any{"ok": true, "fingerprints": values, "reload_rc": rcValue(rc), "reload_error": reloadErr,
		"message": fmt.Sprintf("%d client certificates are refused.", len(values))}
}

func (d *Daemon) handleInternalCAEnsure(_ map[string]any) (int, map[string]any) {
	cert, _, created, err := d.ensureInternalCA()
	if err != nil {
		panic(err)
	}
	msg := "Internal certificate authority already exists."
	if created {
		msg = "Internal certificate authority created."
	}
	return 200, map[string]any{"ok": true, "created": created, "certificate_authority": caItem("internal", "internal", []*x509.Certificate{cert}),
		"message": msg}
}

func (d *Daemon) handleInternalCertIssue(body map[string]any) (int, map[string]any) {
	domain, err := normalizeDNSName(pyx.StrOr(body["domain"]), false)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	rawAlt := body["alt_names"]
	if rawAlt == nil || rawAlt == false || rawAlt == "" {
		rawAlt = []any{}
	}
	alt, ok := rawAlt.([]any)
	if !ok || len(alt) > 100 {
		return 400, map[string]any{"ok": false, "error": "alt_names must be a list of at most 100 items"}
	}
	names := []string{domain}
	for _, v := range alt {
		n, err := normalizeDNSName(pyx.Str(v), false)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		if !containsStr(names, n) {
			names = append(names, n)
		}
	}
	caCert, caKey, created, err := d.ensureInternalCA()
	if err != nil {
		panic(err)
	}
	leaf, pemData, err := buildInternalServerPEM(caCert, caKey, names)
	if err != nil {
		panic(err)
	}
	dest, err := ensureWithin(d.Opts.HAProxyCertsDir, filepath.Join(d.Opts.HAProxyCertsDir, mustSlug(domain)+".pem"))
	if err != nil {
		panic(err)
	}
	ok2, rc, stdout, stderr, err := d.activateServerPEM(dest, pemData, false, false)
	if err != nil {
		panic(err)
	}
	msg := "HAProxy rejected the certificate; the previous PEM was restored."
	if ok2 {
		msg = "Internal certificate issued successfully."
	}
	return 200, map[string]any{"ok": ok2, "domain": domain, "alt_names": names[1:], "source": "internal", "path": dest,
		"not_after": fmtDate(leaf.NotAfter), "internal_ca_created": created, "reload_rc": rcValue(rc),
		"reload_stdout": stdout, "reload_stderr": stderr, "message": msg}
}

func (d *Daemon) internalCAClientTrust(authority *x509.Certificate) map[string]any {
	listed := containsStr(d.loadClientAuthIDs(), "internal")
	inBundle := false
	if dir, err := d.mtlsDir(false); err == nil {
		if raw, err := os.ReadFile(filepath.Join(dir, mtlsBundleName)); err == nil {
			if held, err := loadPEMCertificates(raw); err == nil {
				fp := fingerprint(authority)
				for _, c := range held {
					if fingerprint(c) == fp {
						inBundle = true
					}
				}
			}
		}
	}
	if !listed && !inBundle {
		return nil
	}
	sites := map[string]bool{}
	for _, path := range []string{d.Opts.AppliedWebsites, filepath.Join(filepath.Dir(d.Opts.ConfigYAML), "websites.yml")} {
		if !exists(path) {
			continue
		}
		entries, _ := loadYAML(path)["sites"].([]any)
		for _, e := range entries {
			site, ok := e.(map[string]any)
			if !ok {
				continue
			}
			mode := strings.ToLower(strings.TrimSpace(yamlStrOr(site["mtls_mode"], "disabled")))
			if strings.ToLower(strings.TrimSpace(yamlStrOr(site["mtls_ca_id"], ""))) == "internal" && mode != "disabled" {
				sites[yamlStrOr(site["name"], yamlStrOr(site["domain"], "?"))] = true
			}
		}
	}
	list := []string{}
	for s := range sites {
		list = append(list, s)
	}
	sortStrings(list)
	return map[string]any{"trust_list": listed, "bundle": inBundle, "sites": list}
}

func (d *Daemon) handleInternalCARotate(body map[string]any) (int, map[string]any) {
	if pyx.StrOr(body["confirmation"]) != "ROTATE" {
		return 400, map[string]any{"ok": false, "error": "type ROTATE to confirm internal root CA rotation"}
	}
	d.caMu.Lock()
	defer d.caMu.Unlock()
	keyPath, certPath, err := d.internalCAPaths()
	if err != nil {
		panic(err)
	}
	if !isFile(keyPath) || !isFile(certPath) {
		return 404, map[string]any{"ok": false, "error": "internal certificate authority was not found"}
	}
	oldCert, _, _, err := d.ensureInternalCALocked()
	if err != nil {
		panic(err)
	}
	if trust := d.internalCAClientTrust(oldCert); trust != nil {
		return 409, map[string]any{"ok": false, "error": "The internal CA is trusted to authenticate client certificates, " +
			"and rotating it would leave HAProxy trusting the old root. Move the sites that ask for its client certificates " +
			"to another authority or switch their client certificates off, take it off the client certificate trust list, then rotate.",
			"client_trust": trust}
	}
	affected, err := d.internalLeafCertificates(oldCert)
	if err != nil {
		panic(err)
	}
	newCert, newKey, err := generateInternalCAMaterial()
	if err != nil {
		panic(err)
	}
	replacement := map[string][]byte{}
	previous := map[string][]byte{}
	for _, a := range affected {
		_, pemData, err := buildInternalServerPEM(newCert, newKey, a.names)
		if err != nil {
			panic(err)
		}
		replacement[a.path] = pemData
		if previous[a.path], err = os.ReadFile(a.path); err != nil {
			panic(err)
		}
	}
	root, err := d.prepareCARoot(true)
	if err != nil {
		panic(err)
	}
	internalDir := filepath.Dir(keyPath)
	staged, err := os.MkdirTemp(root, ".internal-ca-new-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(staged)
	rollback := filepath.Join(root, fmt.Sprintf(".internal-ca-rollback-%d", time.Now().UnixNano()))
	oldMoved := false
	rotateErr := func() error {
		if err := writeInternalCAMaterial(staged, newCert, newKey); err != nil {
			return err
		}
		if err := os.Rename(internalDir, rollback); err != nil {
			return err
		}
		oldMoved = true
		if err := os.Rename(staged, internalDir); err != nil {
			return err
		}
		for _, a := range affected {
			if err := replaceServerPEMWithoutReload(a.path, replacement[a.path]); err != nil {
				return err
			}
		}
		rc, stdout, stderr := d.reloadHAProxy()
		if !rcOK(rc) {
			return fmt.Errorf("%s", firstNonEmpty(stderr, stdout, "HAProxy rejected the rotated certificates"))
		}
		return nil
	}()
	if rotateErr != nil {
		for path, data := range previous {
			if err := replaceServerPEMWithoutReload(path, data); err != nil {
				log.Printf("Failed to restore certificate %s", path)
			}
		}
		if oldMoved {
			if exists(internalDir) {
				_ = os.RemoveAll(internalDir)
			}
			if err := os.Rename(rollback, internalDir); err != nil {
				log.Printf("Failed to restore the previous internal CA")
			}
		}
		d.reloadHAProxy()
		return 500, map[string]any{"ok": false, "error": "internal CA rotation failed and was rolled back: " + rotateErr.Error()}
	}
	_ = os.RemoveAll(rollback)
	reissued := []any{}
	for _, a := range affected {
		reissued = append(reissued, map[string]any{"path": a.path, "domains": a.names})
	}
	return 200, map[string]any{"ok": true, "certificate_authority": caItem("internal", "internal", []*x509.Certificate{newCert}),
		"previous_sha256": fingerprint(oldCert), "reissued": reissued,
		"message": "Internal root CA rotated and all certificates issued by the previous root were reissued. Install the new public root certificate on client devices."}
}

func (d *Daemon) handleInternalCADelete(body map[string]any) (int, map[string]any) {
	if pyx.StrOr(body["confirmation"]) != "DELETE" {
		return 400, map[string]any{"ok": false, "error": "type DELETE to confirm internal root CA deletion"}
	}
	d.caMu.Lock()
	defer d.caMu.Unlock()
	keyPath, certPath, err := d.internalCAPaths()
	if err != nil {
		panic(err)
	}
	if !isFile(keyPath) || !isFile(certPath) {
		return 404, map[string]any{"ok": false, "error": "internal certificate authority was not found"}
	}
	authority, _, _, err := d.ensureInternalCALocked()
	if err != nil {
		panic(err)
	}
	if trust := d.internalCAClientTrust(authority); trust != nil {
		return 409, map[string]any{"ok": false, "error": "The internal CA is trusted to authenticate client certificates, " +
			"and deleting it would leave HAProxy trusting it still. Move the sites that ask for its client certificates to " +
			"another authority or switch their client certificates off, take it off the client certificate trust list, then delete.",
			"client_trust": trust}
	}
	affected, err := d.internalLeafCertificates(authority)
	if err != nil {
		panic(err)
	}
	if len(affected) > 0 {
		blocking := []any{}
		for _, a := range affected {
			blocking = append(blocking, map[string]any{"path": a.path, "domains": a.names})
		}
		return 409, map[string]any{"ok": false, "error": "internal CA cannot be deleted while HAProxy certificates signed by it exist",
			"blocking_certificates": blocking}
	}
	dir := filepath.Dir(keyPath)
	kept, err := d.trashPut("internal_ca", "internal", []string{dir}, pyx.StrOr(body["actor"]), d.certDetails(certPath), nil)
	if err != nil {
		return 500, map[string]any{"ok": false, "error": "cannot keep a copy in the trash, nothing deleted: " + pyOSErr(err)}
	}
	before := trashListing([]string{dir})
	if err := os.RemoveAll(dir); err != nil {
		if d.trashSettle(kept, before, []string{dir}) != "" {
			return 500, map[string]any{"ok": false, "trash_id": kept, "error": fmt.Sprintf(
				"the internal certificate authority was only partly deleted (%s); the copy taken before is in the trash", pyOSErr(err))}
		}
		return 500, map[string]any{"ok": false, "error": "cannot delete the internal certificate authority: " + pyOSErr(err)}
	}
	d.trashCommit(kept)
	return 200, map[string]any{"ok": true, "message": "Internal certificate authority moved to the trash."}
}

func (d *Daemon) handleCAExport(body map[string]any) (int, map[string]any) {
	if _, err := d.prepareCARoot(false); err != nil {
		panic(err)
	}
	caID := strings.TrimSpace(pyx.StrOr(body["ca_id"]))
	var path string
	if caID == "internal" {
		_, p, err := d.internalCAPaths()
		if err != nil {
			panic(err)
		}
		path = p
	} else {
		slug, err := safeSlug(caID)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		caID = strings.ToLower(slug)
		ext, err := d.prepareCASubdir("external", false)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		if path, err = ensureWithin(ext, filepath.Join(ext, caID+".pem")); err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
	}
	if !isFile(path) {
		return 404, map[string]any{"ok": false, "error": "certificate authority was not found"}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	filename := caID + ".pem"
	if caID == "internal" {
		filename = "easy-ha-proxy-root-ca.crt"
	}
	return 200, map[string]any{"ok": true, "ca_id": caID, "filename": filename, "certificate_b64": base64.StdEncoding.EncodeToString(raw)}
}

func (d *Daemon) handleExternalCADelete(body map[string]any) (int, map[string]any) {
	if _, err := d.prepareCARoot(false); err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	slug, err := safeSlug(pyx.StrOr(body["ca_id"]))
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	caID := strings.ToLower(slug)
	ext, err := d.prepareCASubdir("external", false)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	path, err := ensureWithin(ext, filepath.Join(ext, caID+".pem"))
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	d.caMu.Lock()
	if !isFile(path) {
		d.caMu.Unlock()
		return 404, map[string]any{"ok": false, "error": "certificate authority was not found"}
	}
	trustedBefore := containsStr(d.loadClientAuthIDs(), caID)
	kept, err := d.trashPut("external_ca", caID, []string{path}, pyx.StrOr(body["actor"]), d.certDetails(path),
		map[string]any{"client_auth": trustedBefore})
	if err != nil {
		d.caMu.Unlock()
		return 500, map[string]any{"ok": false, "error": "cannot keep a copy in the trash, nothing deleted: " + pyOSErr(err)}
	}
	before := trashListing([]string{path})
	if err := os.Remove(path); err != nil {
		d.trashSettle(kept, before, []string{path})
		d.caMu.Unlock()
		return 500, map[string]any{"ok": false, "error": "cannot delete the certificate authority: " + pyOSErr(err)}
	}
	d.trashCommit(kept)
	d.caMu.Unlock()
	trusted := d.loadClientAuthIDs()
	if containsStr(trusted, caID) {
		remaining := []any{}
		for _, v := range trusted {
			if v != caID {
				remaining = append(remaining, v)
			}
		}
		status, resp := d.handleCAClientAuth(map[string]any{"ids": remaining})
		if resp["ok"] != true {
			return status, resp
		}
	}
	return 200, map[string]any{"ok": true, "message": "External certificate authority moved to the trash: " + caID}
}

var _ = bytes.Buffer{}

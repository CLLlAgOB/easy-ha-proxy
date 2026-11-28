package certd

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

type pemBlock = pem.Block

func pemDecode(b []byte) (*pem.Block, []byte) { return pem.Decode(b) }

// pyOSErr renders an error the way str(OSError) does.
func pyOSErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		var errno syscall.Errno
		if errors.As(pe.Err, &errno) {
			msg := errno.Error()
			if msg != "" {
				msg = strings.ToUpper(msg[:1]) + msg[1:]
			}
			return fmt.Sprintf("[Errno %d] %s: '%s'", int(errno), msg, pe.Path)
		}
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		var errno syscall.Errno
		if errors.As(le.Err, &errno) {
			msg := errno.Error()
			if msg != "" {
				msg = strings.ToUpper(msg[:1]) + msg[1:]
			}
			return fmt.Sprintf("[Errno %d] %s: '%s' -> '%s'", int(errno), msg, le.Old, le.New)
		}
	}
	return err.Error()
}

type uploadedFile struct {
	filename string
	content  []byte
}

type multipartForm struct {
	fields map[string][]string
	files  map[string]uploadedFile
}

func (f *multipartForm) getfirst(name, def string) string {
	if v := f.fields[name]; len(v) > 0 {
		return v[0]
	}
	return def
}

func multipartBoundary(contentType string) (string, string) {
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		parts := strings.SplitN(contentType, ";", 2)
		return strings.ToLower(strings.TrimSpace(parts[0])), ""
	}
	return strings.ToLower(media), params["boundary"]
}

func parseMultipart(contentType string, body []byte) (*multipartForm, error) {
	media, boundary := multipartBoundary(contentType)
	if media != "multipart/form-data" || boundary == "" {
		return nil, vErr("not a multipart/form-data body")
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	form := &multipartForm{fields: map[string][]string{}, files: map[string]uploadedFile{}}
	parts := 0
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(form.fields) == 0 && len(form.files) == 0 {
				return nil, vErr("the multipart body could not be read")
			}
			break
		}
		parts++
		_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		name := params["name"]
		if name == "" {
			continue
		}
		content, _ := io.ReadAll(part)
		filename, hasFilename := params["filename"]
		if !hasFilename {
			form.fields[name] = append(form.fields[name], strings.ToValidUTF8(string(content), "�"))
		} else if filename != "" {
			if _, seen := form.files[name]; !seen {
				form.files[name] = uploadedFile{filename, content}
			}
		}
	}
	if parts == 0 {
		return nil, vErr("the multipart body could not be read")
	}
	return form, nil
}

// loadPrivateKeyBlocks is _load_private_key_blocks.
func loadPrivateKeyBlocks(data []byte, secret []byte) ([]crypto.Signer, error) {
	blocks := [][]byte{}
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		found, err := extractPEMBlocks(data, label)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, found...)
	}
	keys := []crypto.Signer{}
	for _, raw := range blocks {
		b := decodeBlock(raw)
		var key crypto.Signer
		if b != nil {
			key = decryptKeyBlock(b, secret)
		}
		if key == nil {
			return nil, vErr("a private key in this file is encrypted; enter its password")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func decryptKeyBlock(b *pem.Block, secret []byte) crypto.Signer {
	if b.Type == "ENCRYPTED PRIVATE KEY" {
		if secret == nil {
			return nil
		}
		k, err := pkcs8.ParsePKCS8PrivateKey(b.Bytes, secret)
		if err != nil {
			return nil
		}
		s, _ := k.(crypto.Signer)
		return s
	}
	der := b.Bytes
	//nolint:staticcheck // legacy encrypted PEM is what OpenSSL still writes
	if x509.IsEncryptedPEMBlock(b) {
		if secret == nil {
			return nil
		}
		plain, err := x509.DecryptPEMBlock(b, secret) //nolint:staticcheck
		if err != nil {
			return nil
		}
		der = plain
	}
	key, err := parsePrivateKeyDER(der)
	if err != nil {
		return nil
	}
	return key
}

// decodeUploadedMaterial is _decode_uploaded_material.
func decodeUploadedMaterial(data []byte, password string) ([]*x509.Certificate, []crypto.Signer, string, error) {
	var secret []byte
	if password != "" {
		secret = []byte(password)
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		certs, err := loadPEMCertificates(data)
		if err != nil {
			return nil, nil, "", err
		}
		keys, err := loadPrivateKeyBlocks(data, secret)
		if err != nil {
			return nil, nil, "", err
		}
		if len(certs) == 0 && len(keys) == 0 {
			return nil, nil, "", vErr("this PEM file holds no certificate and no private key")
		}
		return certs, keys, "PEM", nil
	}
	pkcs12Err := ""
	key, cert, extra, err := pkcs12.DecodeChain(data, password)
	if err == nil {
		certs := []*x509.Certificate{}
		if cert != nil {
			certs = append(certs, cert)
		}
		certs = append(certs, extra...)
		keys := []crypto.Signer{}
		if s, ok := key.(crypto.Signer); ok && s != nil {
			keys = append(keys, s)
		}
		if len(certs) == 0 && len(keys) == 0 {
			return nil, nil, "", vErr("this PKCS#12 file is empty")
		}
		return certs, keys, "PKCS#12", nil
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		if password == "" {
			pkcs12Err = "this looks like a PKCS#12 file and the password is missing or wrong"
		} else {
			pkcs12Err = "the PKCS#12 password is wrong"
		}
	}
	if c, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{c}, nil, "DER", nil
	}
	if k, err := parsePrivateKeyDER(data); err == nil {
		return nil, []crypto.Signer{k}, "DER", nil
	}
	if secret != nil {
		if k, err := pkcs8.ParsePKCS8PrivateKey(data, secret); err == nil {
			if s, ok := k.(crypto.Signer); ok {
				return nil, []crypto.Signer{s}, "DER", nil
			}
		}
	}
	if pkcs12Err != "" {
		return nil, nil, "", vErr("%s", pkcs12Err)
	}
	return nil, nil, "", vErr("unrecognised file: expected PEM, DER or PKCS#12 (.p12/.pfx)")
}

type importPlan struct {
	summary     map[string]any
	authorities []*x509.Certificate
	leaf        *x509.Certificate
	key         crypto.Signer
}

// sortUploadedMaterial is _sort_uploaded_material.
func sortUploadedMaterial(data []byte, password, name, domain string) (*importPlan, error) {
	certs, keys, detected, err := decodeUploadedMaterial(data, password)
	if err != nil {
		return nil, err
	}
	authorities, leaves := []*x509.Certificate{}, []*x509.Certificate{}
	for _, c := range certs {
		if certificateIsAuthority(c) {
			authorities = append(authorities, c)
		} else {
			leaves = append(leaves, c)
		}
	}
	var pairedLeaf *x509.Certificate
	var pairedKey crypto.Signer
	for _, leaf := range leaves {
		for _, k := range keys {
			if samePublicKey(leaf.PublicKey, k.Public()) {
				pairedLeaf, pairedKey = leaf, k
				break
			}
		}
		if pairedLeaf != nil {
			break
		}
	}
	problems, actions := []string{}, []string{}
	caID := ""
	if len(authorities) > 0 {
		root := authorities[0]
		for _, c := range authorities {
			if isSelfSigned(c) {
				root = c
				break
			}
		}
		label := name
		if label == "" {
			label = certificateLabel(root)
		}
		slug, err := safeSlug(label)
		if err != nil {
			return nil, err
		}
		caID = strings.ToLower(slug)
		if caID == "internal" {
			problems = append(problems, "the identifier 'internal' is reserved")
			caID = ""
		} else if len(authorities) > 1 {
			actions = append(actions, fmt.Sprintf("import %d certificate authorities as %s", len(authorities), pyRepr(caID)))
		} else {
			actions = append(actions, "import the certificate authority "+pyRepr(caID))
		}
	}
	var server any
	target := ""
	if pairedLeaf != nil {
		names := certDNSNames(pairedLeaf)
		target = domain
		if target == "" && len(names) > 0 {
			target = names[0]
		}
		if target == "" {
			problems = append(problems, "the certificate carries no host name, so there is nothing to install it under; choose a domain")
		} else {
			chain := chainForLeaf(pairedLeaf, authorities)
			srv := describeCertificate(pairedLeaf)
			srv["domain"] = target
			srv["chain_length"] = len(chain)
			server = srv
			actions = append(actions, "install a server certificate for "+target)
			if len(chain) == 0 && !isSelfSigned(pairedLeaf) {
				problems = append(problems, "no intermediate certificate came with it, so clients that do not already hold the chain may reject this certificate")
			}
		}
	} else if len(leaves) > 0 {
		problems = append(problems, "a server certificate was found but not its private key, so it cannot be installed; upload both together")
	} else if len(keys) > 0 && len(authorities) == 0 {
		problems = append(problems, "a private key was found but no certificate to go with it")
	}
	described := []any{}
	for _, c := range authorities {
		described = append(described, describeCertificate(c))
	}
	return &importPlan{
		summary: map[string]any{"format": detected, "authorities": described, "server_certificate": server, "ca_id": caID,
			"domain": target, "actions": actions, "problems": problems},
		authorities: authorities, leaf: pairedLeaf, key: pairedKey,
	}, nil
}

func merge(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range base {
		out[k] = v
	}
	return out
}

func (d *Daemon) formFile(form *multipartForm, field string) ([]byte, bool, bool) {
	f, ok := form.files[field]
	if !ok {
		return nil, false, false
	}
	if int64(len(f.content)) > d.Opts.MaxRequestBytes {
		return nil, true, true
	}
	return f.content, true, false
}

func (d *Daemon) handleCertsInspectForm(form *multipartForm) (int, map[string]any) {
	data, ok, tooBig := d.formFile(form, "file")
	if !ok {
		return 400, map[string]any{"ok": false, "error": "file is required"}
	}
	if tooBig {
		return 413, map[string]any{"ok": false, "error": "the upload is too large"}
	}
	plan, err := sortUploadedMaterial(data, form.getfirst("password", ""), strings.TrimSpace(form.getfirst("name", "")),
		strings.TrimSpace(form.getfirst("domain", "")))
	if err != nil {
		if isValueErr(err) {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		panic(err)
	}
	return 200, merge(map[string]any{"ok": true}, plan.summary)
}

func (d *Daemon) handleCertsImportForm(form *multipartForm) (int, map[string]any) {
	data, ok, tooBig := d.formFile(form, "file")
	if !ok {
		return 400, map[string]any{"ok": false, "error": "file is required"}
	}
	if tooBig {
		return 413, map[string]any{"ok": false, "error": "the upload is too large"}
	}
	replace := containsStr([]string{"1", "true", "yes", "on"}, strings.ToLower(strings.TrimSpace(form.getfirst("replace", ""))))
	plan, err := sortUploadedMaterial(data, form.getfirst("password", ""), strings.TrimSpace(form.getfirst("name", "")),
		strings.TrimSpace(form.getfirst("domain", "")))
	if err != nil {
		if isValueErr(err) {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		panic(err)
	}
	actions := plan.summary["actions"].([]string)
	if len(actions) == 0 {
		msg := strings.Join(plan.summary["problems"].([]string), "; ")
		if msg == "" {
			msg = "there is nothing in this file to install"
		}
		return 400, map[string]any{"ok": false, "error": msg}
	}
	done := []string{}
	caID := pyx.Str(plan.summary["ca_id"])
	caPath := ""
	if len(plan.authorities) > 0 && caID != "" {
		var canonical []byte
		for _, c := range plan.authorities {
			canonical = append(canonical, certPEM(c)...)
		}
		ext, err := d.prepareCASubdir("external", true)
		if err != nil {
			panic(err)
		}
		if caPath, err = ensureWithin(ext, filepath.Join(ext, caID+".pem")); err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		if isFile(caPath) {
			if existing, err := os.ReadFile(caPath); err == nil && !bytes.Equal(existing, canonical) && !replace {
				return 409, merge(map[string]any{"ok": false, "error": "a different certificate authority is already stored as " +
					pyRepr(caID) + ". Choose another name, or confirm the replacement.", "needs_replace": true}, plan.summary)
			}
		}
		if err := writePublicFile(caPath, canonical); err != nil {
			panic(err)
		}
		done = append(done, "certificate authority "+pyRepr(caID)+" imported")
	}
	if plan.leaf != nil {
		chain := chainForLeaf(plan.leaf, plan.authorities)
		var pemData []byte
		for _, c := range append([]*x509.Certificate{plan.leaf}, chain...) {
			pemData = append(pemData, certPEM(c)...)
		}
		keyPEM, err := keyPEMPKCS8(plan.key)
		if err != nil {
			panic(err)
		}
		pemData = append(pemData, keyPEM...)
		domain := pyx.Str(plan.summary["domain"])
		certs, _, err := validateServerPEM(pemData, domain)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error(), "completed": done}
		}
		if caPath != "" {
			if ok, detail := verifyExternalChain(certs, caPath); !ok {
				return 400, map[string]any{"ok": false, "error": fmt.Sprintf("the chain does not verify against %s: %s", pyRepr(caID), detail),
					"completed": done}
			}
		}
		dir := d.Opts.HAProxyCertsDir
		_ = os.MkdirAll(dir, 0o755)
		slug, err := safeSlug(domain)
		var dest string
		if err == nil {
			dest, err = ensureWithin(dir, filepath.Join(dir, slug+".pem"))
		}
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error(), "completed": done}
		}
		ok2, _, _, stderr, err := d.activateServerPEM(dest, pemData, false, false)
		if err != nil {
			panic(err)
		}
		if !ok2 {
			return 400, map[string]any{"ok": false, "error": "HAProxy rejected the certificate and the previous one was restored: " +
				pyx.TruncRunes(strings.TrimSpace(stderr), 300), "completed": done}
		}
		done = append(done, "server certificate installed for "+domain)
	}
	return 200, merge(map[string]any{"ok": true, "completed": done, "message": strings.Join(done, "; ")}, plan.summary)
}

func (d *Daemon) handleCertsUploadForm(form *multipartForm) (int, map[string]any) {
	f, ok := form.files["cert_file"]
	if !ok {
		return 200, map[string]any{"ok": false, "error": "cert_file is required"}
	}
	siteName := strings.TrimSpace(form.getfirst("site_name", ""))
	domain := strings.TrimSpace(form.getfirst("domain", ""))
	externalCAID := strings.TrimSpace(form.getfirst("external_ca_id", ""))
	if domain != "" {
		n, err := normalizeDNSName(domain, false)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": "invalid domain: " + err.Error()}
		}
		domain = n
	}
	dir := d.Opts.HAProxyCertsDir
	_ = os.MkdirAll(dir, 0o755)
	if int64(len(f.content)) > d.Opts.MaxRequestBytes {
		return 413, map[string]any{"ok": false, "error": "uploaded certificate is too large"}
	}
	pemData := f.content
	certs, _, err := validateServerPEM(pemData, domain)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	if externalCAID != "" {
		if _, err := d.prepareCARoot(false); err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		slug, err := safeSlug(externalCAID)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		externalCAID = strings.ToLower(slug)
		ext, err := d.prepareCASubdir("external", false)
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		caPath, err := ensureWithin(ext, filepath.Join(ext, externalCAID+".pem"))
		if err != nil {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		if !isFile(caPath) {
			return 400, map[string]any{"ok": false, "error": "selected external CA was not found"}
		}
		if ok, detail := verifyExternalChain(certs, caPath); !ok {
			return 400, map[string]any{"ok": false, "error": fmt.Sprintf("certificate chain is not trusted by %s: %s", pyRepr(externalCAID), detail)}
		}
	}
	names := certDNSNames(certs[0])
	sort.Strings(names)
	base := domain
	if base == "" && len(names) > 0 {
		base, err = safeSlug(names[0])
	}
	if base == "" && err == nil {
		base, err = safeSlug(siteName)
	}
	var dest string
	if err == nil {
		dest, err = ensureWithin(dir, filepath.Join(dir, base+".pem"))
	}
	if err != nil {
		return 400, map[string]any{"ok": false, "error": "unsafe certificate name: " + err.Error()}
	}
	ok2, rc, stdout, stderr, err := d.activateServerPEM(dest, pemData, false, false)
	if err != nil {
		panic(err)
	}
	var notAfter, daysLeft any
	if ok2 {
		if info := loadCertInfo(dest); info != nil {
			notAfter, daysLeft = fmtDate(info.NotAfter), info.DaysLeft
		}
	}
	msg := "HAProxy rejected the certificate; the previous PEM was restored."
	if ok2 {
		msg = "Certificate uploaded successfully."
	}
	return 200, map[string]any{"ok": ok2, "site_name": strOrNil(siteName), "domain": strOrNil(domain),
		"external_ca_id": strOrNil(externalCAID), "path": dest, "not_after": notAfter, "days_left": daysLeft,
		"reload_rc": rcValue(rc), "reload_stdout": stdout, "reload_stderr": stderr, "message": msg}
}

func (d *Daemon) handleExternalCAUploadForm(form *multipartForm) (int, map[string]any) {
	f, ok := form.files["ca_file"]
	if !ok {
		return 400, map[string]any{"ok": false, "error": "ca_file is required"}
	}
	if int64(len(f.content)) > d.Opts.MaxRequestBytes {
		return 413, map[string]any{"ok": false, "error": "CA bundle is too large"}
	}
	certs, err := validateCABundle(f.content)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	label := strings.TrimSpace(form.getfirst("name", ""))
	if label == "" {
		label = certificateLabel(certs[0])
	}
	slug, err := safeSlug(label)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	caID := strings.ToLower(slug)
	if caID == "internal" {
		return 400, map[string]any{"ok": false, "error": "the CA identifier 'internal' is reserved"}
	}
	ext, err := d.prepareCASubdir("external", true)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	dest, err := ensureWithin(ext, filepath.Join(ext, caID+".pem"))
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	var canonical []byte
	for _, c := range certs {
		canonical = append(canonical, certPEM(c)...)
	}
	if err := writeNewExternalCA(dest, canonical); err != nil {
		if os.IsExist(err) {
			return 409, map[string]any{"ok": false, "error": "certificate authority " + pyRepr(caID) + " already exists"}
		}
		panic(err)
	}
	item := caItem(caID, "external", certs)
	item["path"] = dest
	return 200, map[string]any{"ok": true, "certificate_authority": item, "message": "External certificate authority imported."}
}

func writeNewExternalCA(dest string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(dest), ".external-ca-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := errors.Join(file.Chmod(0o644), file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Link(file.Name(), dest)
}

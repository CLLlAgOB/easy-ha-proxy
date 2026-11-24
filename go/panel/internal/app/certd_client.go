package app

// Port of certd_client.py: the client of haproxy-certd (HTTP on its Unix socket).

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

var certdSocketPath = func() string {
	if v, ok := os.LookupEnv("CERTD_SOCKET_PATH"); ok {
		return v
	}
	return "/run/easy-ha-proxy/haproxy-certd.sock"
}()

// CertdUnavailable is certd_client.CertdUnavailable.
type CertdUnavailable struct{ Msg string }

func (e *CertdUnavailable) Error() string { return e.Msg }

type certdResponse struct {
	status int
	body   []byte
	url    string
}

func (r *certdResponse) json() (any, bool) {
	v, err := pyyaml.JSONLoads(r.body)
	return v, err == nil
}

func (r *certdResponse) text200() string {
	return truncRunes(strings.ToValidUTF8(string(r.body), "�"), 200)
}

func certdBaseURL(path string) string { return "http://localhost/api/v1" + path }

func certdDisplayURL(path string) string {
	return "http+unix://" + strings.ReplaceAll(pyQuotePlus(certdSocketPath), "%2F", "%2F") + "/api/v1" + path
}

func pyQuotePlus(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte("_.-~", c) >= 0:
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func certdPost(path string, body []byte, contentType string, timeout time.Duration) (*certdResponse, error) {
	client := unixSocketClient(certdSocketPath, timeout)
	req, err := http.NewRequest("POST", certdBaseURL(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, &OSError{pyOSError(err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &OSError{pyOSError(err)}
	}
	return &certdResponse{status: resp.StatusCode, body: raw, url: certdDisplayURL(path)}, nil
}

func certdPostJSON(path string, payload any, timeout time.Duration) (*certdResponse, error) {
	text, err := PyJSON(payload, JSONOpts{EnsureASCII: true})
	if err != nil {
		return nil, err
	}
	return certdPost(path, []byte(text), "application/json", timeout)
}

// certdSection is _dns_request / _delivery_request.
func certdSection(path string, payload any, timeout time.Duration) (*Map, error) {
	resp, err := certdPostJSON("/certs/"+path, payload, timeout)
	if err != nil {
		log.Printf("haproxy-certd unreachable (%s): %v", certdDisplayURL("/certs/"+path), err)
		return nil, &CertdUnavailable{err.Error()}
	}
	v, ok := resp.json()
	if !ok {
		return nil, &CertdUnavailable{"certd returned a non-JSON response"}
	}
	m, ok := asMap(v)
	if !ok {
		return nil, &CertdUnavailable{"certd returned an unexpected payload"}
	}
	return m, nil
}

// CertdDNS is _dns_request (timeout 70 s by default).
func CertdDNS(path string, payload *Map) (*Map, error) {
	return certdSection(path, payload, 70*time.Second)
}

// CertdDelivery is _delivery_request.
func CertdDelivery(path string, payload *Map) (*Map, error) {
	timeout := 70 * time.Second
	if strings.HasSuffix(path, "test") {
		timeout = 200 * time.Second
	}
	return certdSection(path, payload, timeout)
}

// CertdSetRenewalPauses is set_renewal_pauses.
func CertdSetRenewalPauses(domains []string) (*Map, error) {
	resp, err := certdPostJSON("/certs/renewal-pauses", newMap("domains", strList(domains...)), 30*time.Second)
	if err != nil {
		return nil, &CertdUnavailable{err.Error()}
	}
	if resp.status == 404 {
		return newMap("ok", false, "error", "certd does not support renewal pauses yet"), nil
	}
	v, ok := resp.json()
	if !ok {
		return nil, &CertdUnavailable{"certd returned a non-JSON response"}
	}
	m, ok := asMap(v)
	if !ok {
		return nil, &CertdUnavailable{"certd returned an unexpected payload"}
	}
	return m, nil
}

// CertdStatusForDomains is get_certs_status_for_domains.
func CertdStatusForDomains(domains []string) *Map {
	set := map[string]bool{}
	for _, d := range domains {
		if d != "" {
			set[strings.TrimSpace(d)] = true
		}
	}
	uniq := sortedKeys(set)
	if len(uniq) == 0 {
		return pyyaml.NewMap()
	}
	resp, err := certdPostJSON("/certs/status", newMap("domains", strList(uniq...)), 2*time.Second)
	if err != nil || resp.status >= 400 {
		return pyyaml.NewMap()
	}
	v, ok := resp.json()
	if !ok {
		return pyyaml.NewMap()
	}
	items, ok := asMap(orValue(get(v, "items"), pyyaml.NewMap()))
	if !ok {
		return pyyaml.NewMap()
	}
	return items
}

// CertdStatusForDomain is get_cert_status_for_domain.
func CertdStatusForDomain(domain string) *Map {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return pyyaml.NewMap()
	}
	if m, ok := asMap(CertdStatusForDomains([]string{domain}).Value(domain)); ok {
		return m
	}
	return pyyaml.NewMap()
}

func capLines(lines []string) []string {
	if len(lines) > 20 {
		return append(append([]string{}, lines[:20]...), "... (truncated)")
	}
	return lines
}

// normalizeCertIssueResponse is _normalize_cert_issue_response.
func normalizeCertIssueResponse(data *Map) *Map {
	res := copyMap(data)
	ok := truthy(res.Value("ok"))
	res.Set("ok", ok)
	if _, has := res.Get("status"); !has {
		if ok {
			res.Set("status", "OK")
		} else {
			res.Set("status", "ERROR")
		}
	}
	if truthy(res.Value("message")) {
		return res
	}
	if truthy(res.Value("error")) {
		res.Set("message", pyStr(res.Value("error")))
		return res
	}
	var details, generic []string
	results, _ := asList(orValue(res.Value("results"), []any{}))
	for _, e := range results {
		entry, ok := asMap(e)
		if !ok {
			continue
		}
		rc := entry.Value("rc")
		if rc == nil {
			continue
		}
		lineage := strOrEmpty(entry.Value("lineage"))
		combined := strings.TrimSpace(strOrEmpty(entry.Value("stderr")) + "\n" + strOrEmpty(entry.Value("stdout")))
		header := "[" + orStr(orValue(noneIfEmpty(lineage), "certbot")) + "]"
		if combined == "" {
			generic = append(generic, fmt.Sprintf("%s exit code %s (no output).", header, pyStr(rc)))
			continue
		}
		lines := pySplitlines(combined)
		var dl, hl []string
		for _, ln := range lines {
			s := strings.TrimSpace(ln)
			if strings.HasPrefix(s, "Detail:") {
				dl = append(dl, s)
			} else if strings.HasPrefix(s, "Hint:") {
				hl = append(hl, s)
			}
		}
		if len(dl) > 0 || len(hl) > 0 {
			details = append(details, strings.Join(append(append([]string{header}, dl...), hl...), "\n"))
		}
		generic = append(generic, fmt.Sprintf("%s exit code %s\n", header, pyStr(rc))+strings.Join(capLines(lines), "\n"))
	}
	if prc := res.Value("pem_rc"); prc != nil && !pyEqual(prc, int64(0)) {
		perr := strings.TrimSpace(strOrEmpty(orValue(res.Value("pem_stderr"), res.Value("pem_stdout"))))
		header := "[haproxy-pems-reload]"
		if perr != "" {
			generic = append(generic, fmt.Sprintf("%s exit code %s\n", header, pyStr(prc))+strings.Join(capLines(pySplitlines(perr)), "\n"))
		} else {
			generic = append(generic, fmt.Sprintf("%s exit code %s (no output).", header, pyStr(prc)))
		}
	}
	var parts []string
	if len(details) > 0 {
		parts = append(parts, "ACME rejection reason:\n"+strings.Join(details, "\n\n"))
	}
	if len(generic) > 0 {
		if len(details) > 0 {
			parts = append(parts, "\n--- Full certbot output ---\n")
		}
		parts = append(parts, strings.Join(generic, "\n\n"))
	}
	if len(parts) == 0 {
		if ok {
			res.Set("message", "Request completed successfully with no errors.")
		} else {
			res.Set("message", "The request failed, but certd returned no details. Check the haproxy-certd service log.")
		}
	} else {
		res.Set("message", strings.Join(parts, "\n"))
	}
	return res
}

// certdIssueStyle posts JSON and normalizes the answer like issue/backup/restore.
func certdIssueStyle(path string, payload any, timeout time.Duration) *Map {
	resp, err := certdPostJSON(path, payload, timeout)
	if err != nil {
		return normalizeCertIssueResponse(newMap("ok", false, "error", "haproxy-certd unreachable: "+err.Error()))
	}
	v, ok := resp.json()
	if !ok {
		return normalizeCertIssueResponse(newMap("ok", false, "error", fmt.Sprintf("haproxy-certd non-JSON response (HTTP %d) from %s: %s", resp.status, resp.url, resp.text200())))
	}
	m, ok := asMap(v)
	if !ok {
		m = newMap("ok", false, "error", "unexpected JSON from certd: "+pyRepr(v))
	}
	return normalizeCertIssueResponse(m)
}

// CertdIssue is issue_cert_for_domain.
func CertdIssue(domain string, altNames []any, keyTypes any, dnsProfile string, dnsPropagation any) *Map {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return normalizeCertIssueResponse(newMap("ok", false, "error", "domain is empty"))
	}
	alts := []any{}
	for _, a := range altNames {
		if truthy(a) {
			alts = append(alts, strip(a))
		}
	}
	payload := newMap("domain", domain, "alt_names", alts, "key_types", orValue(keyTypes, []any{}))
	if dnsProfile != "" {
		payload.Set("dns_profile", strings.ToLower(strings.TrimSpace(dnsProfile)))
		if dnsPropagation != nil {
			payload.Set("dns_propagation", dnsPropagation)
		}
	}
	return certdIssueStyle("/certs/issue", payload, 600*time.Second)
}

// CertdIssueInternal is issue_internal_cert_for_domain.
func CertdIssueInternal(domain string, altNames []any) *Map {
	alts := []any{}
	for _, a := range altNames {
		if truthy(a) {
			alts = append(alts, strip(a))
		}
	}
	resp, err := certdPostJSON("/certs/ca/internal/issue", newMap("domain", strings.TrimSpace(domain), "alt_names", alts), 120*time.Second)
	if err != nil {
		return newMap("ok", false, "error", "haproxy-certd request failed: "+err.Error())
	}
	v, ok := resp.json()
	if !ok {
		return newMap("ok", false, "error", "haproxy-certd request failed: Expecting value: line 1 column 1 (char 0)")
	}
	if m, ok := asMap(v); ok {
		return m
	}
	return newMap("ok", false, "error", "unexpected response from haproxy-certd")
}

// CertdBackup is backup_certs.
func CertdBackup() *Map { return certdIssueStyle("/certs/backup", pyyaml.NewMap(), 600*time.Second) }

// CertdRestore is restore_certs_from_archive.
func CertdRestore(archive []byte) *Map {
	if len(archive) == 0 {
		return normalizeCertIssueResponse(newMap("ok", false, "error", "archive_bytes is empty"))
	}
	return certdIssueStyle("/certs/restore", newMap("archive_b64", base64.StdEncoding.EncodeToString(archive)), 600*time.Second)
}

// CertdUpload is upload_cert_for_site.
func CertdUpload(siteName, domain string, pem []byte, filename, externalCAID string) *Map {
	if filename == "" {
		filename = "cert.pem"
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, kv := range [][2]string{{"site_name", strings.TrimSpace(siteName)}, {"domain", strings.TrimSpace(domain)}, {"external_ca_id", strings.TrimSpace(externalCAID)}} {
		_ = w.WriteField(kv[0], kv[1])
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="cert_file"; filename="%s"`, filename))
	h.Set("Content-Type", "application/x-pem-file")
	part, _ := w.CreatePart(h)
	_, _ = part.Write(pem)
	_ = w.Close()
	resp, err := certdPost("/certs/upload", buf.Bytes(), w.FormDataContentType(), 60*time.Second)
	if err != nil {
		return newMap("ok", false, "error", "haproxy-certd unreachable: "+err.Error())
	}
	v, ok := resp.json()
	if !ok {
		return newMap("ok", false, "error", fmt.Sprintf("haproxy-certd non-JSON response (HTTP %d) from %s: %s", resp.status, resp.url, resp.text200()))
	}
	m, ok := asMap(v)
	if !ok {
		return newMap("ok", false, "error", "unexpected JSON from certd: "+pyRepr(v))
	}
	res := copyMap(m)
	ok = truthy(res.Value("ok"))
	res.Set("ok", ok)
	if !ok && !truthy(res.Value("message")) {
		if truthy(res.Value("error")) {
			res.Set("message", pyStr(res.Value("error")))
		} else {
			res.Set("message", "Certificate upload failed through haproxy-certd")
		}
	}
	return res
}

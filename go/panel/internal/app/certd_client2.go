package app

// The rest of certd_client.py: standby certificates, authorities, material
// import, the certificate list and deletions.

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

// certdSimple is the "try: post; data = response.json() except: request
// failed" pattern most certd_client functions share.
func certdSimple(path string, payload any, timeout time.Duration) *Map {
	resp, err := certdPostJSON(path, payload, timeout)
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

func certdMultipart(path string, fields [][2]string, fileField, filename, fileType string, data []byte, timeout time.Duration) *Map {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, kv := range fields {
		_ = w.WriteField(kv[0], kv[1])
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": fileField, "filename": filename}))
	h.Set("Content-Type", fileType)
	part, _ := w.CreatePart(h)
	_, _ = part.Write(data)
	_ = w.Close()
	resp, err := certdPost(path, buf.Bytes(), w.FormDataContentType(), timeout)
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

func ts(s string) string { return strings.TrimSpace(s) }

func CertdStandbyList() *Map {
	return certdSimple("/certs/standby", pyyaml.NewMap(), 30*time.Second)
}
func CertdStandbyStore(domain, slot, pem string) *Map {
	return certdSimple("/certs/standby/store", newMap("domain", ts(domain), "slot", ts(slot), "pem", pem), 60*time.Second)
}
func CertdStandbyAdopt(domain, slot string) *Map {
	return certdSimple("/certs/standby/adopt", newMap("domain", ts(domain), "slot", ts(slot)), 60*time.Second)
}
func CertdStandbyStoreAll(slot, pem string) *Map {
	return certdSimple("/certs/standby/store-all", newMap("slot", ts(slot), "pem", pem), 120*time.Second)
}
func CertdStandbyActivate(domain, slot string) *Map {
	return certdSimple("/certs/standby/activate", newMap("domain", ts(domain), "slot", ts(slot)), 60*time.Second)
}
func CertdReleaseToLE(domain string) *Map {
	return certdSimple("/certs/standby/release", newMap("domain", ts(domain)), 60*time.Second)
}
func CertdStandbyDelete(domain, slot, actor string) *Map {
	return certdSimple("/certs/standby/delete", newMap("domain", ts(domain), "slot", ts(slot), "actor", actor), 30*time.Second)
}
func CertdEnsureInternalCA() *Map {
	return certdSimple("/certs/ca/internal/ensure", pyyaml.NewMap(), 120*time.Second)
}
func CertdRotateInternalCA(confirmation string) *Map {
	return certdSimple("/certs/ca/internal/rotate", newMap("confirmation", ts(confirmation)), 180*time.Second)
}
func CertdDeleteInternalCA(confirmation, actor string) *Map {
	return certdSimple("/certs/ca/internal/delete", newMap("confirmation", ts(confirmation), "actor", actor), 30*time.Second)
}
func CertdUploadExternalCA(name string, pem []byte, filename string) *Map {
	if filename == "" {
		filename = "ca.pem"
	}
	return certdMultipart("/certs/ca/upload", [][2]string{{"name", ts(name)}}, "ca_file", filename, "application/x-pem-file", pem, 60*time.Second)
}
func CertdMaterial(action string, payload []byte, filename, password, name, domain string, replace bool) *Map {
	if filename == "" {
		filename = "upload.pem"
	}
	fields := [][2]string{{"password", password}, {"name", name}, {"domain", domain}}
	if replace {
		fields = append(fields, [2]string{"replace", "true"})
	}
	return certdMultipart("/certs/"+action, fields, "file", filename, "application/octet-stream", payload, 60*time.Second)
}
func CertdExportCA(caID string) *Map {
	return certdSimple("/certs/ca/export", newMap("ca_id", caID), 10*time.Second)
}
func CertdDeleteExternalCA(caID, actor string) *Map {
	return certdSimple("/certs/ca/delete-external", newMap("ca_id", caID, "actor", actor), 10*time.Second)
}
func CertdSetClientAuthCAs(ids []any) *Map {
	return certdSimple("/certs/ca/client-auth", newMap("ids", ids), 30*time.Second)
}
func CertdSetRevoked(fps []any) *Map {
	return certdSimple("/certs/ca/revoked", newMap("fingerprints", fps), 30*time.Second)
}

func emptyCertList(err string) *Map {
	return newMap("ok", false, "error", err, "haproxy", []any{}, "letsencrypt", []any{},
		"certificate_authorities", newMap("internal", nil, "external", []any{}))
}

// CertdListAll is list_all_certs.
func CertdListAll() *Map {
	client := unixSocketClient(certdSocketPath, 5*time.Second)
	resp, err := client.Get(certdBaseURL("/certs/list"))
	if err != nil {
		return emptyCertList("haproxy-certd unreachable: " + pyOSError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return emptyCertList(fmt.Sprintf("haproxy-certd HTTP %d", resp.StatusCode))
	}
	raw, err := readBoundedBody(resp, maxDaemonResponseBytes)
	if err != nil {
		return emptyCertList("haproxy-certd incomplete or oversized response")
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return emptyCertList("haproxy-certd non-JSON response")
	}
	data, ok := asMap(v)
	if !ok {
		return emptyCertList("unexpected JSON from certd: " + pyRepr(v))
	}
	for _, kv := range []struct {
		k string
		v any
	}{{"haproxy", []any{}}, {"letsencrypt", []any{}}, {"certificate_authorities", newMap("internal", nil, "external", []any{})}, {"ok", true}} {
		if _, has := data.Get(kv.k); !has {
			data.Set(kv.k, kv.v)
		}
	}
	return data
}

func certdDeleteStyle(path string, payload *Map, timeout time.Duration) *Map {
	resp, err := certdPostJSON(path, payload, timeout)
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
	if _, has := m.Get("ok"); !has {
		m.Set("ok", false)
	}
	return m
}

// CertdDeleteHAProxy is delete_haproxy_cert.
func CertdDeleteHAProxy(path, actor string) *Map {
	path = ts(path)
	if path == "" {
		return newMap("ok", false, "error", "empty path")
	}
	return certdDeleteStyle("/certs/delete-haproxy", newMap("path", path, "actor", actor), 10*time.Second)
}

// CertdDeleteLE is delete_le_cert.
func CertdDeleteLE(lineage, actor string) *Map {
	lineage = ts(lineage)
	if lineage == "" {
		return newMap("ok", false, "error", "empty lineage")
	}
	return certdDeleteStyle("/certs/delete-le", newMap("lineage", lineage, "actor", actor), 60*time.Second)
}

package certd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// NewDaemon builds a daemon over opts.
func NewDaemon(opts Options) *Daemon {
	return &Daemon{Opts: opts, alertsClient: alerts.FromEnv()}
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
	raw := bytes.TrimRight(buf.Bytes(), "\n")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func (d *Daemon) readJSONBody(r *http.Request) (map[string]any, error) {
	length, err := strconv.ParseInt(strings.TrimSpace(firstNonEmpty(r.Header.Get("Content-Length"), "0")), 10, 64)
	if err != nil {
		return nil, vErr("invalid Content-Length")
	}
	if length <= 0 || length > d.Opts.MaxRequestBytes {
		return nil, vErr("request body size is outside the allowed range")
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, length))
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&parsed); err != nil {
		return map[string]any{}, nil
	}
	if m, ok := parsed.(map[string]any); ok {
		return m, nil
	}
	return map[string]any{}, nil
}

type handlerFunc func(map[string]any) (int, map[string]any)

func (d *Daemon) routes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"/api/v1/certs/status": func(b map[string]any) (int, map[string]any) {
			raw := b["domains"]
			if !pyx.Truthy(raw) {
				raw = []any{}
			}
			domains, ok := raw.([]any)
			if !ok || len(domains) > 500 {
				return 400, map[string]any{"ok": false, "error": "domains must be a list of at most 500 items"}
			}
			items := map[string]any{}
			for _, dm := range domains {
				n, err := normalizeDNSName(pyx.Str(dm), false)
				if err != nil {
					return 400, map[string]any{"ok": false, "error": "invalid domain: " + pyReprAny(dm)}
				}
				items[n] = d.certStatusForDomain(n)
			}
			return 200, map[string]any{"ok": true, "items": items}
		},
		"/api/v1/certs/renewal-pauses": func(b map[string]any) (int, map[string]any) {
			domains, ok := b["domains"].([]any)
			if !ok || len(domains) > 1000 {
				return 400, map[string]any{"ok": false, "error": "domains must be a list"}
			}
			list := []string{}
			for _, dm := range domains {
				list = append(list, pyx.Str(dm))
			}
			out, err := d.syncRenewalPauses(list)
			if err != nil {
				if isValueErr(err) {
					return 400, map[string]any{"ok": false, "error": err.Error()}
				}
				panic(err)
			}
			return 200, out
		},
		"/api/v1/certs/issue":          d.handleCertsIssue,
		"/api/v1/certs/backup":         d.handleCertsBackup,
		"/api/v1/certs/restore":        d.handleCertsRestore,
		"/api/v1/certs/delete-haproxy": d.handleDeleteHAProxy,
		"/api/v1/certs/delete-le":      d.handleDeleteLE,
		"/api/v1/certs/standby": func(map[string]any) (int, map[string]any) {
			return 200, d.listStandbyCertificates()
		},
		"/api/v1/certs/standby/store": d.standbyHandler(func(b map[string]any) (map[string]any, error) {
			return d.storeStandbyCertificate(b["domain"], b["slot"], pemArg(b["pem"]))
		}),
		"/api/v1/certs/standby/adopt": d.standbyHandler(func(b map[string]any) (map[string]any, error) {
			return d.adoptDeployedAsStandby(b["domain"], b["slot"])
		}),
		"/api/v1/certs/standby/store-all": d.standbyHandler(func(b map[string]any) (map[string]any, error) {
			return d.storeStandbyForCoveredNames(b["slot"], pemArg(b["pem"]), nil)
		}),
		"/api/v1/certs/standby/activate": d.standbyHandler(func(b map[string]any) (map[string]any, error) {
			return d.activateStandbyCertificate(b["domain"], b["slot"])
		}),
		"/api/v1/certs/standby/release": d.standbyHandler(func(b map[string]any) (map[string]any, error) {
			return d.releaseToLetsEncrypt(b["domain"])
		}),
		"/api/v1/certs/standby/delete": d.standbyHandler(func(b map[string]any) (map[string]any, error) {
			return d.deleteStandbyCertificate(b["domain"], b["slot"], pyx.StrOr(b["actor"]))
		}),
		"/api/v1/certs/ca/internal/ensure": d.handleInternalCAEnsure,
		"/api/v1/certs/ca/internal/issue":  d.handleInternalCertIssue,
		"/api/v1/certs/ca/internal/rotate": d.handleInternalCARotate,
		"/api/v1/certs/ca/internal/delete": d.handleInternalCADelete,
		"/api/v1/certs/ca/export":          d.handleCAExport,
		"/api/v1/certs/ca/delete-external": d.handleExternalCADelete,
		"/api/v1/certs/ca/client-auth":     d.handleCAClientAuth,
		"/api/v1/certs/ca/revoked":         d.handleCARevoked,
		"/api/v1/certs/dns-providers": func(map[string]any) (int, map[string]any) {
			return 200, merge(map[string]any{"ok": true}, d.listDNSProviders())
		},
		"/api/v1/certs/dns-providers/save": func(b map[string]any) (int, map[string]any) {
			saved, err := d.saveDNSProvider(b)
			if err != nil {
				if isValueErr(err) {
					return 400, map[string]any{"ok": false, "error": err.Error()}
				}
				panic(err)
			}
			return 200, merge(map[string]any{"ok": true}, saved)
		},
		"/api/v1/certs/dns-providers/delete": func(b map[string]any) (int, map[string]any) {
			removed, err := d.deleteDNSProvider(pyx.StrOr(b["name"]), pyx.StrOr(b["actor"]))
			if err != nil {
				if isValueErr(err) {
					return 400, map[string]any{"ok": false, "error": err.Error()}
				}
				return 500, map[string]any{"ok": false, "error": "cannot delete the DNS profile: " + pyOSErr(err)}
			}
			return 200, merge(map[string]any{"ok": true}, removed)
		},
		"/api/v1/certs/deliveries": func(map[string]any) (int, map[string]any) { return 200, d.listCertDeliveries() },
		"/api/v1/certs/deliveries/save": func(b map[string]any) (int, map[string]any) {
			saved, err := d.saveCertDelivery(b)
			if err != nil {
				if isValueErr(err) {
					return 400, map[string]any{"ok": false, "error": err.Error()}
				}
				panic(err)
			}
			return 200, map[string]any{"ok": true, "target": saved}
		},
		"/api/v1/certs/deliveries/delete": func(b map[string]any) (int, map[string]any) {
			removed, err := d.deleteCertDelivery(b["name"], pyx.StrOr(b["actor"]))
			if err != nil {
				if isValueErr(err) {
					return 400, map[string]any{"ok": false, "error": err.Error()}
				}
				return 500, map[string]any{"ok": false, "error": "cannot delete the delivery target: " + pyOSErr(err)}
			}
			return 200, merge(map[string]any{"ok": true}, removed)
		},
		"/api/v1/certs/deliveries/test": func(b map[string]any) (int, map[string]any) {
			outcome, err := d.testCertDelivery(b["name"])
			if err != nil {
				if isValueErr(err) {
					return 400, map[string]any{"ok": false, "error": err.Error()}
				}
				panic(err)
			}
			return 200, outcome
		},
		"/api/v1/certs/trash":          d.handleTrashList,
		"/api/v1/certs/trash/restore":  d.handleTrashRestore,
		"/api/v1/certs/trash/purge":    d.handleTrashPurge,
		"/api/v1/certs/trash/settings": d.handleTrashSettings,
	}
}

func pyReprAny(v any) string {
	if s, ok := v.(string); ok {
		return pyRepr(s)
	}
	return pyx.Str(v)
}

func (d *Daemon) standbyHandler(f func(map[string]any) (map[string]any, error)) handlerFunc {
	return func(b map[string]any) (int, map[string]any) {
		out, err := f(b)
		if err != nil {
			if isValueErr(err) {
				return 400, map[string]any{"ok": false, "error": err.Error()}
			}
			log.Printf("standby request failed: %v", err)
			return 500, map[string]any{"ok": false, "error": pyOSErr(err)}
		}
		return 200, out
	}
}

func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.RequestURI()
	switch r.Method {
	case http.MethodGet:
		if path == "/api/v1/certs/list" {
			d.safely(w, func() (int, map[string]any) { return d.handleCertsList() }, false)
			return
		}
		writeJSON(w, 404, map[string]any{"ok": false, "error": "unknown path"})
	case http.MethodPost:
		switch path {
		case "/api/v1/certs/restore":
			if !d.restoreMu.TryLock() {
				writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "a certificate restore is already running"})
				return
			}
			defer d.restoreMu.Unlock()
		case "/api/v1/certs/upload", "/api/v1/certs/ca/upload", "/api/v1/certs/inspect", "/api/v1/certs/import":
			d.handleMultipart(w, r, path)
			return
		}
		body, err := d.readJSONBody(r)
		if err != nil {
			writeJSON(w, 413, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		h, ok := d.routes()[path]
		if !ok {
			writeJSON(w, 404, map[string]any{"ok": false, "error": "unknown path"})
			return
		}
		d.safely(w, func() (int, map[string]any) { return h(body) }, true)
	default:
		writeJSON(w, 501, map[string]any{"ok": false, "error": "Unsupported method"})
	}
}

// safely is the handler's `except Exception: 500 {"ok": false, "error": str(exc)}`.
func (d *Daemon) safely(w http.ResponseWriter, f func() (int, map[string]any), catch bool) {
	status, resp := 500, map[string]any(nil)
	func() {
		defer func() {
			if r := recover(); r != nil {
				if !catch {
					panic(r)
				}
				log.Printf("certificate request failed: %v", r)
				msg := fmt.Sprint(r)
				if err, ok := r.(error); ok {
					msg = pyOSErr(err)
				}
				status, resp = 500, map[string]any{"ok": false, "error": msg}
			}
		}()
		status, resp = f()
	}()
	writeJSON(w, status, resp)
}

func (d *Daemon) handleMultipart(w http.ResponseWriter, r *http.Request, path string) {
	contentType := r.Header.Get("Content-Type")
	media, boundary := multipartBoundary(contentType)
	if media != "multipart/form-data" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "Content-Type must be multipart/form-data"})
		return
	}
	if boundary == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "multipart boundary missing"})
		return
	}
	length, err := strconv.ParseInt(strings.TrimSpace(r.Header.Get("Content-Length")), 10, 64)
	if err != nil {
		length = 0
	}
	if length <= 0 || length > d.Opts.MaxRequestBytes {
		writeJSON(w, 413, map[string]any{"ok": false, "error": "upload is too large"})
		return
	}
	d.safely(w, func() (int, map[string]any) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, length))
		if int64(len(body)) < length {
			return 400, map[string]any{"ok": false, "error": "the upload was cut short"}
		}
		form, err := parseMultipart(contentType, body)
		if err != nil {
			panic(err)
		}
		switch path {
		case "/api/v1/certs/ca/upload":
			return d.handleExternalCAUploadForm(form)
		case "/api/v1/certs/inspect":
			return d.handleCertsInspectForm(form)
		case "/api/v1/certs/import":
			return d.handleCertsImportForm(form)
		}
		return d.handleCertsUploadForm(form)
	}, true)
}

// ---------------------------------------------------------------------------
// Certificate expiry watch
// ---------------------------------------------------------------------------

func (d *Daemon) siteNames(site map[string]any) map[string]bool {
	names := map[string]bool{}
	for _, key := range []string{"domain", "alt_names", "aliases", "domains"} {
		value := site[key]
		items := []any{value}
		if l, ok := value.([]any); ok {
			items = l
		}
		for _, it := range items {
			if yamlTruthy(it) {
				if n, err := normalizeDNSName(fmt.Sprint(it), false); err == nil && n != "" {
					names[n] = true
				} else if err != nil {
					panic(err)
				}
			}
		}
	}
	return names
}

func (d *Daemon) certificateUsers() (map[string]bool, map[string]bool, bool) {
	files := []string{}
	for _, p := range []string{filepath.Join(filepath.Dir(d.Opts.ConfigYAML), "websites.yml"), d.Opts.AppliedWebsites} {
		if exists(p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return nil, nil, false
	}
	used, off := map[string]bool{}, map[string]bool{}
	for _, p := range files {
		sites, ok := loadYAML(p)["sites"].([]any)
		if !ok {
			return nil, nil, false
		}
		for _, s := range sites {
			site, ok := s.(map[string]any)
			if !ok {
				continue
			}
			target := used
			if site["paused"] == true && site["cert_renewal_paused"] == true {
				target = off
			}
			for n := range d.siteNames(site) {
				target[n] = true
			}
		}
	}
	for _, vp := range []string{d.Opts.ConfigYAML, d.Opts.AppliedVars} {
		settings := loadYAML(vp)
		for _, key := range []string{"admin_domain", "aut_domain"} {
			if yamlTruthy(settings[key]) {
				if n, err := normalizeDNSName(fmt.Sprint(settings[key]), false); err == nil {
					used[n] = true
				}
			}
		}
		// The portals of the extra Authelia sign-in domains.
		for _, extra := range pyx.List(settings["authelia_extra_domains"]) {
			if entry, ok := extra.(map[string]any); ok && yamlTruthy(entry["portal"]) {
				if n, err := normalizeDNSName(fmt.Sprint(entry["portal"]), false); err == nil {
					used[n] = true
				}
			}
		}
	}
	if isDir(d.Opts.DeliveryDir) {
		for _, rp := range globSorted(filepath.Join(d.Opts.DeliveryDir, "*.json")) {
			record, err := readJSONMap(rp)
			if err != nil {
				return nil, nil, false
			}
			for _, dm := range pyx.List(record["domains"]) {
				if n, err := normalizeDNSName(pyx.Str(dm), false); err == nil {
					used[n] = true
				}
			}
		}
	}
	for n := range used {
		delete(off, n)
	}
	return used, off, true
}

func nameCovers(certName, name string) bool {
	if certName == name {
		return true
	}
	if strings.HasPrefix(certName, "*.") {
		suffix := certName[1:]
		return strings.HasSuffix(name, suffix) && !strings.Contains(name[:len(name)-len(suffix)], ".")
	}
	return false
}

func onlySwitchedOff(names []string, used, off map[string]bool, known bool) bool {
	if !known || len(names) == 0 {
		return false
	}
	for _, c := range names {
		for n := range used {
			if nameCovers(c, n) {
				return false
			}
		}
	}
	for _, c := range names {
		for n := range off {
			if nameCovers(c, n) {
				return true
			}
		}
	}
	return false
}

func (d *Daemon) expiryScan() int {
	reported := 0
	entries := globSorted(filepath.Join(d.Opts.HAProxyCertsDir, "*.pem"))
	used, off, known := func() (u, o map[string]bool, k bool) {
		defer func() {
			if r := recover(); r != nil {
				u, o, k = nil, nil, false
			}
		}()
		return d.certificateUsers()
	}()
	for _, path := range entries {
		info := loadCertInfo(path)
		if info == nil {
			continue
		}
		days := info.DaysLeft
		domain := stem(path)
		names := []string{}
		if cert := firstCertificate(path); cert != nil {
			names = certDNSNames(cert)
		}
		if onlySwitchedOff(names, used, off, known) {
			obs := alerts.Observation{Rule: "certificate.expiring", Subject: domain, Active: alerts.BoolPtr(false), Retired: true,
				Summary: fmt.Sprintf("The certificate for %s is not checked: only switched-off sites use it", domain)}
			d.observe(obs)
			reported++
			continue
		}
		severity := "warning"
		if days <= 7 {
			severity = "critical"
		}
		summary := fmt.Sprintf("The certificate for %s expires in %d days", domain, days)
		if days < 0 {
			summary = fmt.Sprintf("The certificate for %s expired %d days ago", domain, -days)
		}
		d.observe(alerts.Observation{Rule: "certificate.expiring", Subject: domain, Active: alerts.BoolPtr(days <= info.WarnDays),
			Severity: severity, Summary: summary, Detail: "Not after: " + pyDatetime(info.NotAfter) + d.standbyHint(domain)})
		reported++
	}
	return reported
}

func (d *Daemon) expiryWatch(ctx context.Context) {
	if !d.alertsOn() {
		return
	}
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("certificate expiry scan failed: %v", r)
				}
			}()
			d.expiryScan()
		}()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(d.Opts.ExpiryWatchIntervalSecond) * time.Second):
		}
	}
}

func (d *Daemon) trashPurgeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(trashPurgeIntervalSeconds * time.Second):
		}
		d.trashMu.Lock()
		d.trashPurgeLocked(time.Now())
		d.trashMu.Unlock()
	}
}

// Run is main().
func Run(opts Options) error {
	d := NewDaemon(opts)
	log.Printf("Starting haproxy-certd: SOCKET_PATH=%s, CERTBOT_BIN=%s, DRY_RUN=%v", opts.SocketPath, opts.CertbotBin, opts.DryRun)
	if root, err := d.prepareCARoot(false); err == nil && exists(root) {
		_, _ = d.prepareCASubdir("internal", false)
		_, _ = d.prepareCASubdir("external", false)
	}
	startup := []string{}
	for _, id := range d.loadClientAuthIDs() {
		if _, err := d.caCertificates(id); err != nil {
			log.Printf("dropping %s from client authentication: %v", pyRepr(id), err)
			continue
		}
		startup = append(startup, id)
	}
	if _, err := d.rebuildClientAuthMaterial(startup); err != nil {
		log.Printf("cannot prepare client authentication material: %v", err)
	}
	ln, err := unixrpc.ListenUnix(opts.SocketPath, "", opts.GroupName, 0o660)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.expiryWatch(ctx)
	go d.trashPurgeLoop(ctx)
	srv := &http.Server{Handler: d, ReadHeaderTimeout: requestTimeoutSeconds * time.Second,
		ReadTimeout: 2 * time.Minute, IdleTimeout: requestTimeoutSeconds * time.Second}
	serveCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("haproxy-certd is listening on unix://%s", opts.SocketPath)
	defer os.Remove(opts.SocketPath)
	return unixrpc.ServeHTTP(serveCtx, srv, unixrpc.PanelListener(ln), 5*time.Second)
}

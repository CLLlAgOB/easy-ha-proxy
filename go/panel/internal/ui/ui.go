// Package ui renders the Go panel's HTML administration pages using embedded
// Go html/template views connected to the shared static JS/CSS and i18n assets.
package ui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
)

//go:embed templates/base.html templates/generic.html templates/pages/*.html
var templateFS embed.FS

// NavItem represents one sidebar navigation link.
type NavItem struct {
	Label          string
	Href           string
	SuperadminOnly bool
}

// NavGroup groups related sidebar navigation items.
type NavGroup struct {
	Label          string
	SuperadminOnly bool
	Items          []NavItem
}

// ServerTimeContext mirrors server_time.context() in Python.
type ServerTimeContext struct {
	Zone         string `json:"zone"`
	Abbreviation string `json:"abbreviation"`
	Offset       string `json:"offset"`
}

// PageSpec defines metadata, template name, and scripts for one admin page.
type PageSpec struct {
	Template    string
	PageID      string
	Title       string
	HeaderTitle string
	Description string
	APIEndpoint string
	Scripts     []string
	Extra       map[string]any
}

type pageData struct {
	Language           string
	CSRFToken          string
	CSPNonce           string
	Title              string
	HeaderTitle        string
	Description        string
	APIEndpoint        string
	PageID             string
	CurrentPath        string
	Username           string
	IsSuperadmin       bool
	I18NMessagesURL    string
	I18NConfigJSON     template.JS
	ServerTime         ServerTimeContext
	ServerTimeJSON     template.JS
	SupportedLanguages []i18n.Language
	NavGroups          []NavGroup
	Scripts            []string
	PanelVersion       string

	// Page-specific template fields matching Flask templates.
	Ranges            []string
	DefaultRange      string
	CanSwitchMonitors bool
	Windows           []int
	Providers         []string
	Transports        []string
	MaxKeepDays       int
	EventTypes        []string
	Hours24           []int
	OSIntervals       []int
	MaxUploadGiB      string
	BanJSON           string
}

// Renderer compiles embedded templates (base + each page) and caches static
// asset content hashes.
type Renderer struct {
	pages     map[string]*template.Template
	generic   *template.Template
	staticDir string
	serverTZ  string
	catalog   *i18n.Catalog

	mu       sync.RWMutex
	versions map[string]string
}

// NewRenderer compiles base.html together with generic.html and every page
// template under templates/pages/*.html.
func NewRenderer(staticDir, serverTZ string, catalog *i18n.Catalog) (*Renderer, error) {
	if serverTZ == "" {
		serverTZ = "UTC"
	}
	r := &Renderer{
		pages:     make(map[string]*template.Template),
		staticDir: staticDir,
		serverTZ:  serverTZ,
		catalog:   catalog,
		versions:  make(map[string]string),
	}

	funcs := template.FuncMap{
		"staticURL": r.StaticURL,
		"upper":     strings.ToUpper,
		"fmtHour":   func(h int) string { return fmt.Sprintf("%02d:00", h) },
		"windowLabel": func(sec int) string {
			if sec < 60 {
				return fmt.Sprintf("%d sec", sec)
			}
			return fmt.Sprintf("%d min", sec/60)
		},
	}

	gen, err := template.New("base.html").Funcs(funcs).ParseFS(templateFS, "templates/base.html", "templates/generic.html")
	if err != nil {
		return nil, fmt.Errorf("parse generic template: %w", err)
	}
	r.generic = gen

	entries, err := fs.ReadDir(templateFS, "templates/pages")
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
				continue
			}
			t, err := template.New("base.html").Funcs(funcs).ParseFS(
				templateFS,
				"templates/base.html",
				"templates/pages/"+entry.Name(),
			)
			if err != nil {
				return nil, fmt.Errorf("parse page template %s: %w", entry.Name(), err)
			}
			r.pages[entry.Name()] = t
		}
	}

	return r, nil
}

// StaticURL returns `/static/<rel>?v=<hash>` when the asset exists on disk.
func (r *Renderer) StaticURL(rel string) string {
	base := "/static/" + rel
	if r.staticDir == "" {
		return base
	}
	r.mu.RLock()
	ver, ok := r.versions[rel]
	r.mu.RUnlock()
	if !ok {
		ver = computeStaticVersion(filepath.Join(r.staticDir, filepath.FromSlash(rel)))
		r.mu.Lock()
		r.versions[rel] = ver
		r.mu.Unlock()
	}
	if ver == "" {
		return base
	}
	return base + "?v=" + ver
}

func computeStaticVersion(fullPath string) string {
	info, err := os.Stat(fullPath)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	tag := fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
	sum := sha256.Sum256([]byte(tag))
	return hex.EncodeToString(sum[:])[:12]
}

func (r *Renderer) serverTimeContext() ServerTimeContext {
	loc, err := time.LoadLocation(r.serverTZ)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	abbr, offSec := now.Zone()
	sign := "+"
	if offSec < 0 {
		sign = "-"
		offSec = -offSec
	}
	hours := offSec / 3600
	mins := (offSec % 3600) / 60
	return ServerTimeContext{
		Zone:         r.serverTZ,
		Abbreviation: abbr,
		Offset:       fmt.Sprintf("UTC%s%02d:%02d", sign, hours, mins),
	}
}

// Render writes a complete HTML page with security context, i18n, and scripts.
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, spec PageSpec) {
	lang := r.catalog.SelectLanguage(req)
	langs := r.catalog.SupportedLanguages()
	id := security.FromContext(req.Context())
	user := "HAProxy"
	isSuper := false
	nonce := ""
	csrf := ""
	if id != nil {
		if id.User != "" {
			user = id.User
		}
		isSuper = id.IsSuperadmin
		nonce = id.CSPNonce
		csrf = id.CSRFToken
	}

	i18nCfgRaw, _ := json.Marshal(map[string]any{
		"language":  lang,
		"languages": langs,
	})
	st := r.serverTimeContext()
	stRaw, _ := json.Marshal(st)

	hours24 := make([]int, 24)
	for i := 0; i < 24; i++ {
		hours24[i] = i
	}

	data := pageData{
		Language:           lang,
		CSRFToken:          csrf,
		CSPNonce:           nonce,
		Title:              r.catalog.Translate(lang, spec.Title),
		HeaderTitle:        r.catalog.Translate(lang, spec.HeaderTitle),
		Description:        r.catalog.Translate(lang, spec.Description),
		APIEndpoint:        spec.APIEndpoint,
		PageID:             spec.PageID,
		CurrentPath:        req.URL.Path,
		Username:           user,
		IsSuperadmin:       isSuper,
		I18NMessagesURL:    r.catalog.MessagesURL(lang),
		I18NConfigJSON:     template.JS(i18nCfgRaw),
		ServerTime:         st,
		ServerTimeJSON:     template.JS(stRaw),
		SupportedLanguages: langs,
		NavGroups:          defaultNavGroups,
		Scripts:            spec.Scripts,
		PanelVersion:       config.Version,
		Ranges:             []string{"1h", "6h", "24h", "7d", "30d", "90d", "1y"},
		DefaultRange:       "24h",
		CanSwitchMonitors:  isSuper,
		Windows:            []int{30, 60, 300, 900},
		Providers:          []string{"cloudflare", "digitalocean", "route53", "rfc2136"},
		Transports:         []string{"sftp", "scp"},
		MaxKeepDays:        365,
		EventTypes:         defaultEventTypes,
		Hours24:            hours24,
		OSIntervals:        []int{1, 2, 4, 6, 12, 24},
		MaxUploadGiB:       "8.0",
		BanJSON:            "{}",
	}

	if spec.Template == "audit.html" {
		data.Ranges = []string{"1h", "24h", "7d", "30d", "90d", "all"}
		data.DefaultRange = "7d"
	}
	if spec.Extra != nil {
		if v, ok := spec.Extra["max_upload_gib"].(string); ok && v != "" {
			data.MaxUploadGiB = v
		}
		if v, ok := spec.Extra["ban_json"].(string); ok && v != "" {
			data.BanJSON = v
		}
	}

	tmpl := r.generic
	if spec.Template != "" {
		if compiled, ok := r.pages[spec.Template]; ok {
			tmpl = compiled
		}
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		http.Error(w, "template rendering error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// HasPageTemplate reports whether a dedicated DOM template is loaded for name.
func (r *Renderer) HasPageTemplate(name string) bool {
	_, ok := r.pages[name]
	return ok
}

var defaultEventTypes = []string{
	"SCANNER_PATH",
	"SCANNER_PATH_DECISIVE",
	"QUERY_INJECTION",
	"SCANNER_MULTI_CATEGORY",
	"LOW_AND_SLOW_SCANNER",
	"NOT_FOUND_ENUMERATION",
	"WIDE_ENUMERATION",
	"MASS_ENUMERATION",
	"RECURRING_SCANNER",
	"INVALID_HOST_ACTIVITY",
	"NOSNI_PROBING",
	"RATE_EXCEEDED",
	"ERROR_RATE_EXCEEDED",
	"LEGACY_HAPROXY_BAN",
	"HARD_FLOOR_EPISODE",
}

var defaultNavGroups = []NavGroup{
	{
		Label: "Overview",
		Items: []NavItem{
			{Label: "Dashboard", Href: "/"},
			{Label: "Monitoring", Href: "/monitoring"},
			{Label: "Live activity", Href: "/monitoring/live"},
			{Label: "System health", Href: "/system/health"},
			{Label: "Alerts", Href: "/system/alerts"},
			{Label: "Audit log", Href: "/system/audit"},
		},
	},
	{
		Label: "Security",
		Items: []NavItem{
			{Label: "Adaptive protection", Href: "/security/adaptive"},
			{Label: "Adaptive bans", Href: "/security/adaptive/bans"},
			{Label: "Detection rules", Href: "/security/detection-rules"},
			{Label: "Request log", Href: "/security/requests"},
		},
	},
	{
		Label:          "HAProxy",
		SuperadminOnly: true,
		Items: []NavItem{
			{Label: "Backends", Href: "/haproxy/backends", SuperadminOnly: true},
			{Label: "Sites", Href: "/haproxy/sites", SuperadminOnly: true},
			{Label: "TCP", Href: "/haproxy/tcp", SuperadminOnly: true},
			{Label: "UDP", Href: "/haproxy/udp", SuperadminOnly: true},
			{Label: "Certificates", Href: "/haproxy/certs", SuperadminOnly: true},
			{Label: "DNS providers", Href: "/haproxy/certs/dns-providers", SuperadminOnly: true},
			{Label: "Cert delivery", Href: "/haproxy/certs/delivery", SuperadminOnly: true},
			{Label: "GeoIP", Href: "/haproxy/geoip", SuperadminOnly: true},
			{Label: "Configuration", Href: "/haproxy/config", SuperadminOnly: true},
			{Label: "Config history", Href: "/haproxy/config/history", SuperadminOnly: true},
			{Label: "Trash", Href: "/haproxy/trash", SuperadminOnly: true},
		},
	},
	{
		Label:          "Authelia & System",
		SuperadminOnly: true,
		Items: []NavItem{
			{Label: "Users", Href: "/authelia/users", SuperadminOnly: true},
			{Label: "Authelia bans", Href: "/authelia/bans", SuperadminOnly: true},
			{Label: "Authelia settings", Href: "/authelia/settings/", SuperadminOnly: true},
			{Label: "Backups", Href: "/system/backups/", SuperadminOnly: true},
			{Label: "Updates", Href: "/system/updates/", SuperadminOnly: true},
			{Label: "OS security", Href: "/system/os-security/", SuperadminOnly: true},
			{Label: "SSH security", Href: "/system/ssh-security/", SuperadminOnly: true},
			{Label: "Schedule", Href: "/system/schedule/", SuperadminOnly: true},
		},
	},
}

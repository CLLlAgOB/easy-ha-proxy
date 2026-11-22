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
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
)

//go:embed templates/*.html
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

// PageSpec defines metadata and scripts for one rendered admin page.
type PageSpec struct {
	PageID      string
	Title       string
	HeaderTitle string
	Description string
	APIEndpoint string
	Scripts     []string
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
	StaticURL          func(string) string
}

// Renderer compiles embedded templates and caches static asset hashes.
type Renderer struct {
	tmpl      *template.Template
	staticDir string
	serverTZ  string
	catalog   *i18n.Catalog

	mu       sync.RWMutex
	versions map[string]string
}

// NewRenderer builds a Renderer from the embedded HTML templates.
func NewRenderer(staticDir, serverTZ string, catalog *i18n.Catalog) (*Renderer, error) {
	if serverTZ == "" {
		serverTZ = "UTC"
	}
	r := &Renderer{
		staticDir: staticDir,
		serverTZ:  serverTZ,
		catalog:   catalog,
		versions:  make(map[string]string),
	}
	tmpl, err := template.New("page.html").Funcs(template.FuncMap{
		"staticURL": r.StaticURL,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	r.tmpl = tmpl
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
		StaticURL:          r.StaticURL,
	}

	var buf bytes.Buffer
	if err := r.tmpl.ExecuteTemplate(&buf, "page.html", data); err != nil {
		http.Error(w, "template rendering error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
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

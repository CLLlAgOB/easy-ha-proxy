// Package i18n implements the translation catalog loader, browser language
// selection, immutable /i18n/messages.js asset builder, and JSON response
// localization with parity to docker/app/haproxy_admin/i18n.py.
package i18n

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const LanguageCookie = "easy_ha_proxy_language"

// Language describes one supported interface language.
type Language struct {
	Code  string `json:"code"`
	Label string `json:"label"`
}

type jsAsset struct {
	Body []byte
	Gzip []byte
	ETag string
}

// Catalog holds loaded translation tables and pre-compressed JS bundles.
type Catalog struct {
	defaultLang string
	languages   []Language
	messages    map[string]map[string]string
	assets      map[string]jsAsset
}

type rawCatalogFile struct {
	Meta struct {
		Code  string `json:"code"`
		Label string `json:"label"`
	} `json:"meta"`
	Messages map[string]string `json:"messages"`
}

// LoadDir walks translations/**/*.json and merges catalogs by meta.code.
// If dir does not exist, a minimal built-in English fallback catalog is used
// so unit tests and minimal containers can still start cleanly.
func LoadDir(dir, defaultLang string) (*Catalog, error) {
	defaultLang = strings.ToLower(strings.TrimSpace(defaultLang))
	if defaultLang != "en" && defaultLang != "ru" {
		defaultLang = "en"
	}

	c := &Catalog{
		defaultLang: defaultLang,
		messages:    make(map[string]map[string]string),
		assets:      make(map[string]jsAsset),
	}

	if dir == "" {
		return c.withFallback(), nil
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return c.withFallback(), nil
	}

	var files []string
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk translations dir %s: %w", dir, err)
	}
	sort.Strings(files)

	labels := make(map[string]string)
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read translation %s: %w", path, err)
		}
		var parsed rawCatalogFile
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("parse translation %s: %w", path, err)
		}
		code := strings.ToLower(strings.TrimSpace(parsed.Meta.Code))
		label := strings.TrimSpace(parsed.Meta.Label)
		if code == "" || label == "" || parsed.Messages == nil {
			return nil, fmt.Errorf("invalid translation catalog: %s", path)
		}
		if existingLabel, ok := labels[code]; ok && existingLabel != label {
			return nil, fmt.Errorf("conflicting translation label in %s", path)
		}
		labels[code] = label
		if c.messages[code] == nil {
			c.messages[code] = make(map[string]string, len(parsed.Messages))
		}
		for k, v := range parsed.Messages {
			if _, dup := c.messages[code][k]; dup {
				return nil, fmt.Errorf("duplicate translation key for %s: %s", code, k)
			}
			c.messages[code][k] = v
		}
	}

	if len(c.messages) == 0 {
		return c.withFallback(), nil
	}

	codes := make([]string, 0, len(labels))
	for code := range labels {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		c.languages = append(c.languages, Language{Code: code, Label: labels[code]})
	}
	if _, ok := c.messages[c.defaultLang]; !ok {
		c.defaultLang = codes[0]
	}

	for _, code := range codes {
		c.assets[code] = buildJSAsset(c.messages[code])
	}
	return c, nil
}

func (c *Catalog) withFallback() *Catalog {
	c.defaultLang = "en"
	c.languages = []Language{{Code: "en", Label: "English"}}
	c.messages["en"] = map[string]string{}
	c.assets["en"] = buildJSAsset(c.messages["en"])
	return c
}

func buildJSAsset(msgs map[string]string) jsAsset {
	// json.dumps(ensure_ascii=False, separators=(",", ":"), sort_keys=True):
	// map keys sorted, UTF-8 kept, and no HTML escaping of <, > and &, which
	// json.Marshal adds and Python does not -- the body, and so its ETag, must
	// be the same bytes.
	var enc bytes.Buffer
	encoder := json.NewEncoder(&enc)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(msgs)
	payload := bytes.TrimSuffix(enc.Bytes(), []byte("\n"))
	body := append([]byte("window.HAPROXY_ADMIN_I18N=window.HAPROXY_ADMIN_I18N||{};window.HAPROXY_ADMIN_I18N.messages="), payload...)
	body = append(body, ';')

	var gzBuf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&gzBuf, 6)
	_, _ = gz.Write(body)
	_ = gz.Close()

	sum := sha256.Sum256(body)
	return jsAsset{
		Body: body,
		Gzip: gzBuf.Bytes(),
		ETag: hex.EncodeToString(sum[:])[:16],
	}
}

// SupportedLanguages returns the loaded language list.
func (c *Catalog) SupportedLanguages() []Language {
	out := make([]Language, len(c.languages))
	copy(out, c.languages)
	return out
}

// NormalizeLanguage resolves a raw locale string ("ru-RU", "en_US") to a
// loaded language code, or "" if unsupported.
func (c *Catalog) NormalizeLanguage(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "_", "-")
	if idx := strings.IndexByte(s, '-'); idx > 0 {
		s = s[:idx]
	}
	if _, ok := c.messages[s]; ok {
		return s
	}
	return ""
}

// SelectLanguage chooses the request language from the saved cookie, then
// Accept-Language header, then default language.
func (c *Catalog) SelectLanguage(r *http.Request) string {
	if cookie, err := r.Cookie(LanguageCookie); err == nil && cookie != nil {
		if code := c.NormalizeLanguage(cookie.Value); code != "" {
			return code
		}
	}
	if al := r.Header.Get("Accept-Language"); al != "" {
		bestCode := ""
		bestQ := 0.0
		for _, part := range strings.Split(al, ",") {
			segs := strings.Split(part, ";")
			tag := strings.TrimSpace(segs[0])
			if tag == "" {
				continue
			}
			q := 1.0
			valid := true
			for _, param := range segs[1:] {
				k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(k), "q") {
					continue
				}
				parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
				if err != nil || math.IsNaN(parsed) || parsed < 0 || parsed > 1 {
					valid = false
					break
				}
				q = parsed
			}
			if !valid || q <= 0 {
				continue
			}
			if code := c.NormalizeLanguage(tag); code != "" && q > bestQ {
				bestCode = code
				bestQ = q
			}
		}
		if bestCode != "" {
			return bestCode
		}
	}
	return c.defaultLang
}

// Translate returns the localized string for msg in lang, falling back to msg.
func (c *Catalog) Translate(lang, msg string) string {
	code := c.NormalizeLanguage(lang)
	if code == "" {
		code = c.defaultLang
	}
	table := c.messages[code]
	if table == nil {
		return msg
	}
	if v, ok := table[msg]; ok {
		return v
	}
	normalized := strings.Join(strings.Fields(msg), " ")
	if v, ok := table[normalized]; ok {
		return v
	}
	return msg
}

// TranslateRequest translates msg using the language negotiated for r.
func (c *Catalog) TranslateRequest(r *http.Request, msg string) string {
	return c.Translate(c.SelectLanguage(r), msg)
}

// MessagesURL returns the versioned URL for /i18n/messages.js.
func (c *Catalog) MessagesURL(lang string) string {
	code := c.NormalizeLanguage(lang)
	if code == "" {
		code = c.defaultLang
	}
	asset := c.assets[code]
	return "/i18n/messages.js?lang=" + url.QueryEscape(code) + "&v=" + asset.ETag
}

// ServeMessagesJS handles GET /i18n/messages.js with ETag + immutable caching.
func (c *Catalog) ServeMessagesJS(w http.ResponseWriter, r *http.Request) {
	code := c.NormalizeLanguage(r.URL.Query().Get("lang"))
	if code == "" {
		code = c.defaultLang
	}
	asset := c.assets[code]
	etag := `"` + asset.ETag + `"`
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	// Flask never answers this route conditionally: the URL carries the
	// content hash, so a browser does not revalidate it anyway.
	acceptsGzip := strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip")
	data := asset.Body
	if acceptsGzip {
		data = asset.Gzip
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ServeSetLanguage handles POST /language.
func (c *Catalog) ServeSetLanguage(sessionSecure bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lang := c.NormalizeLanguage(r.FormValue("language"))
		if lang == "" {
			http.Error(w, c.TranslateRequest(r, "Unsupported interface language"), http.StatusBadRequest)
			return
		}
		target := SafeLocalRedirect(r.FormValue("next"), "/")
		http.SetCookie(w, &http.Cookie{
			Name:     LanguageCookie,
			Value:    lang,
			Path:     "/",
			MaxAge:   365 * 24 * 60 * 60,
			Secure:   sessionSecure,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}

// SafeLocalRedirect validates that target is a safe relative path on this host.
func SafeLocalRedirect(raw, fallback string) string {
	if raw == "" || strings.Contains(raw, `\`) {
		return fallback
	}
	for _, r := range raw {
		if r < 32 {
			return fallback
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return fallback
	}
	return raw
}

// LocalizeJSON recursively translates user-facing JSON fields
// ("error", "message", "warning", "detail") matching i18n.py.
func (c *Catalog) LocalizeJSON(lang string, v any) any {
	return c.localizeValue(lang, "", v)
}

func (c *Catalog) localizeValue(lang, key string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = c.localizeValue(lang, k, item)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = c.localizeValue(lang, key, item)
		}
		return out
	case string:
		switch key {
		case "error", "message", "warning", "detail":
			return c.Translate(lang, x)
		}
		return x
	default:
		return v
	}
}

package app

// Flask's static route (send_from_directory with the immutable cache policy
// of security.apply_security_headers) and the POST /language switch of
// create_app.

import (
	"fmt"
	"hash/adler32"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/i18n"
)

// staticTypes is what Python's mimetypes says for the files the panel ships.
var staticTypes = map[string]string{
	".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png",
	".ico": "image/vnd.microsoft.icon", ".woff2": "font/woff2", ".woff": "font/woff", ".json": "application/json",
	".html": "text/html", ".txt": "text/plain", ".map": "", ".gif": "image/gif", ".jpg": "image/jpeg",
	".jpeg": "image/jpeg", ".webp": "image/webp",
}

// pyStatMtime is os.stat().st_mtime: seconds plus nanoseconds times 1e-9,
// computed in doubles the way CPython does.
func pyStatMtime(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())*1e-9
}

// werkzeugContentType is get_content_type: a charset for text/*, +xml and
// the JavaScript/XML application types.
func werkzeugContentType(mimetype string) string {
	switch {
	case strings.HasPrefix(mimetype, "text/"), strings.HasSuffix(mimetype, "+xml"),
		mimetype == "application/ecmascript", mimetype == "application/javascript", mimetype == "application/sql",
		mimetype == "application/xml", mimetype == "application/xml-dtd", mimetype == "application/xml-external-parsed-entity":
		return mimetype + "; charset=utf-8"
	}
	return mimetype
}

// safeStaticPath is werkzeug's safe_join under the static folder.
func safeStaticPath(root, filename string) (string, bool) {
	if filename == "" || strings.Contains(filename, "\\") || strings.HasPrefix(filename, "/") {
		return "", false
	}
	clean := path.Clean(filename)
	if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", false
	}
	for _, part := range strings.Split(filename, "/") {
		if part == ".." {
			return "", false
		}
	}
	return filepath.Join(root, filepath.FromSlash(clean)), true
}

func (a *App) registerStaticLanguage() {
	static := func(c *Ctx) error {
		full, ok := safeStaticPath(a.Cfg.StaticDir, c.Args["filename"])
		if !ok {
			return Abort(404, "")
		}
		f, err := os.Open(full)
		if err != nil {
			return Abort(404, "")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return Abort(404, "")
		}
		name := filepath.Base(full)
		mimetype, known := staticTypes[strings.ToLower(filepath.Ext(name))]
		if !known || mimetype == "" {
			mimetype = "application/octet-stream"
		}
		h := c.W.Header()
		h.Set("Content-Type", werkzeugContentType(mimetype))
		h.Set("Content-Disposition", strings.Replace(contentDisposition(name), "attachment", "inline", 1))
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		h.Set("Expires", httpDate(time.Now().Add(31536000*time.Second)))
		mtime := pyStatMtime(info.ModTime())
		h.Set("ETag", fmt.Sprintf(`"%s-%d-%d"`, pyStr(mtime), info.Size(), adler32.Checksum([]byte(full))))
		// The static route never touches the session, so no cookie goes out.
		c.written = true
		http.ServeContent(c.W, c.R, "", info.ModTime(), f)
		return nil
	}
	a.Handle("static", static)
	a.Handle("routes.static", static)

	a.Handle("set_language", func(c *Ctx) error {
		language := ""
		if c.App.Catalog != nil {
			language = c.App.Catalog.NormalizeLanguage(c.FormStr("language"))
		}
		if language == "" {
			return Abort(400, c.T("Unsupported interface language"))
		}
		target := i18n.SafeLocalRedirect(c.FormStr("next"), "/")
		http.SetCookie(c.W, &http.Cookie{Name: i18n.LanguageCookie, Value: language, Path: "/", MaxAge: 365 * 24 * 60 * 60,
			Expires: time.Now().Add(365 * 24 * time.Hour), Secure: c.App.Cfg.SessionSecure, HttpOnly: true,
			SameSite: http.SameSiteStrictMode})
		return c.Redirect(target, 303)
	})
}

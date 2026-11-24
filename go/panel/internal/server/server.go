// Package server wires the middleware chain around the Go port of the Flask
// panel (internal/app) and runs the HTTP server.
package server

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"os"
	"regexp"
	"time"

	"easy-ha-proxy/panel/internal/app"
	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
)

// Server holds the configured HTTP handler and dependencies.
type Server struct {
	Cfg      *config.Config
	Catalog  *i18n.Catalog
	Boundary *security.Boundary
	App      *app.App
	handler  http.Handler
}

// New constructs a Server: the Flask port behind the request boundary.
func New(cfg *config.Config, cat *i18n.Catalog) *Server {
	if cat == nil {
		var err error
		cat, err = i18n.LoadDir(cfg.TranslationsDir, cfg.DefaultLanguage)
		if err != nil {
			cat, _ = i18n.LoadDir("", cfg.DefaultLanguage)
		}
	}
	boundary := security.NewBoundary(cfg.ProxySecret, cfg.SecretKey, cfg.SessionSecure, cat.TranslateRequest)

	templatesDir := os.Getenv("HAPROXY_ADMIN_TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = "/app/templates"
	}
	s := &Server{Cfg: cfg, Catalog: cat, Boundary: boundary, App: app.New(cfg, cat, templatesDir)}

	// Middleware order (outermost -> innermost):
	// GzipJSONMiddleware -> BodyLimit -> Boundary (proxy secret, RBAC, CSRF, security headers) -> App.
	var h http.Handler = s.App
	h = boundary.Wrap(h)
	h = s.bodyLimitMiddleware(h)
	h = security.GzipJSONMiddleware(h)
	s.handler = h
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

var portalUploadPath = regexp.MustCompile(`^/haproxy/sites/[^/]+/portal/files$`)

func (s *Server) bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := s.Cfg.MaxBodyBytes
		mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaType == "application/octet-stream" && r.URL.Path == "/system/backups/api/uploads" && s.Cfg.MaxUploadBytes > 0 {
			limit = s.Cfg.MaxUploadBytes
		} else if mediaType == "application/octet-stream" && portalUploadPath.MatchString(r.URL.Path) {
			// access_portal.upload takes an attachment of up to 128 MiB.
			limit = 128 * 1024 * 1024
		}
		if limit > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the HTTP server with graceful shutdown.
//
// No whole-request read or write deadline, as under gunicorn's threaded
// workers (whose --timeout 870 is a worker heartbeat, not a request limit):
// a restore upload of up to 8 GiB, a backup download, or the Authelia mail
// update that waits up to 840 s on its daemon all outlast one. The headers
// must still arrive promptly, and the views that stream to visitors (the
// access-portal download) set their own deadlines.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.Cfg.ListenAddr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

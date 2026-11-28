package tools

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeoIPRedirectPolicy(t *testing.T) {
	origLookup := geoipLookupIP
	origTransport := geoipHTTPTransport
	defer func() {
		geoipLookupIP = origLookup
		geoipHTTPTransport = origTransport
	}()

	t.Run("allows HTTPS redirect to public IP", func(t *testing.T) {
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("geoip-ok"))
		}))
		defer target.Close()
		redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/db.mmdb.gz", http.StatusFound)
		}))
		defer redir.Close()

		geoipLookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		geoipHTTPTransport = redir.Client().Transport

		// Replace redir's transport TLS config to trust both test servers.
		tr := target.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.InsecureSkipVerify = true
		geoipHTTPTransport = tr

		dest := filepath.Join(t.TempDir(), "db.mmdb.gz")
		if err := downloadFile(redir.URL+"/start", dest, &bytes.Buffer{}); err != nil {
			t.Fatalf("expected allowed HTTPS redirect to succeed, got %v", err)
		}
		got, err := os.ReadFile(dest)
		if err != nil || string(got) != "geoip-ok" {
			t.Fatalf("unexpected downloaded content: %q err=%v", string(got), err)
		}
	})

	t.Run("rejects HTTPS to HTTP downgrade", func(t *testing.T) {
		geoipLookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		u, _ := url.Parse("http://download.example.com/db.mmdb.gz")
		req, _ := http.NewRequest("GET", u.String(), nil)
		viaReq, _ := http.NewRequest("GET", "https://download.example.com/start", nil)
		err := geoipCheckRedirect(req, []*http.Request{viaReq})
		if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
			t.Fatalf("expected HTTPS->HTTP downgrade rejection, got %v", err)
		}
	})

	t.Run("rejects redirect to loopback or private IP", func(t *testing.T) {
		for _, ip := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fc00::1"} {
			geoipLookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(ip)}, nil
			}
			req, _ := http.NewRequest("GET", "https://internal.example.com/db.mmdb.gz", nil)
			viaReq, _ := http.NewRequest("GET", "https://download.example.com/start", nil)
			err := geoipCheckRedirect(req, []*http.Request{viaReq})
			if err == nil || !strings.Contains(err.Error(), "disallowed address") {
				t.Fatalf("expected private/loopback IP %s rejection, got %v", ip, err)
			}
		}
	})

	t.Run("rejects excessive redirect chain", func(t *testing.T) {
		geoipLookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		req, _ := http.NewRequest("GET", "https://download.example.com/final", nil)
		via := make([]*http.Request, geoipMaxRedirects+1)
		if err := geoipCheckRedirect(req, via); err == nil || !strings.Contains(err.Error(), "too many") {
			t.Fatalf("expected too many redirects rejection, got %v", err)
		}
	})
}

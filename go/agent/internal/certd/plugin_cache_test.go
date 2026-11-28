package certd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestListedDNSPluginsReusesTheAnswerUntilSnapStateChanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script stand-in for certbot")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	output := filepath.Join(dir, "output")
	certbot := filepath.Join(dir, "certbot")
	_ = os.WriteFile(certbot, []byte("#!/bin/sh\necho x >> "+calls+"\ncat "+output+"\n"), 0o755)
	_ = os.WriteFile(output, []byte("* standalone\n* dns-cloudflare\n"), 0o644)

	oldState, oldRoot := snapdStateFile, snapRoot
	snapdStateFile, snapRoot = filepath.Join(dir, "state.json"), filepath.Join(dir, "snap")
	defer func() { snapdStateFile, snapRoot = oldState, oldRoot }()
	_ = os.WriteFile(snapdStateFile, []byte("{}"), 0o600)
	_ = os.MkdirAll(filepath.Join(snapRoot, "certbot", "5941"), 0o755)
	_ = os.Symlink("5941", filepath.Join(snapRoot, "certbot", "current"))

	d := &Daemon{Opts: Options{CertbotBin: certbot}}
	count := func() int {
		raw, _ := os.ReadFile(calls)
		return strings.Count(string(raw), "x")
	}

	if got := d.listedDNSPlugins(); !got["dns-cloudflare"] || count() != 1 {
		t.Fatalf("first listing: %v after %d calls", got, count())
	}
	got := d.listedDNSPlugins()
	if !got["dns-cloudflare"] || count() != 1 {
		t.Fatalf("unchanged state must reuse the answer: %v after %d calls", got, count())
	}
	got["dns-route53"] = true // a caller's change must not leak into the cache
	if d.listedDNSPlugins()["dns-route53"] {
		t.Fatal("cache shares its map with callers")
	}

	// A plugin snap installed and connected: snapd rewrites its state.
	_ = os.WriteFile(output, []byte("* standalone\n* dns-cloudflare\n* dns-route53\n"), 0o644)
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(snapdStateFile, future, future)
	if got := d.listedDNSPlugins(); !got["dns-route53"] || count() != 2 {
		t.Fatalf("snapd state change must ask again: %v after %d calls", got, count())
	}

	// A refreshed certbot snap moves current.
	_ = os.MkdirAll(filepath.Join(snapRoot, "certbot", "6000"), 0o755)
	_ = os.Remove(filepath.Join(snapRoot, "certbot", "current"))
	_ = os.Symlink("6000", filepath.Join(snapRoot, "certbot", "current"))
	d.listedDNSPlugins()
	if count() != 3 {
		t.Fatalf("a new snap revision must ask again, %d calls", count())
	}

	// Past the lifetime it asks again even with nothing changed.
	d.plugins.at = time.Now().Add(-pluginCacheTTL - time.Second)
	d.listedDNSPlugins()
	if count() != 4 {
		t.Fatalf("an expired answer must be refreshed, %d calls", count())
	}

	// A failed certbot (no plugins at all) is not remembered.
	_ = os.WriteFile(output, []byte(""), 0o644)
	_ = os.Chtimes(snapdStateFile, future.Add(time.Minute), future.Add(time.Minute))
	d.listedDNSPlugins()
	d.listedDNSPlugins()
	if count() != 6 {
		t.Fatalf("an empty answer must not be cached, %d calls", count())
	}
}

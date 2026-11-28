package certd

// Which certbot DNS plugins are installed, for the pages that list DNS
// profiles. `certbot plugins` takes about 3 s on a gateway (the snap starts a
// whole Python interpreter), and the site editor and the DNS provider page
// asked for it on every load, where the Python certd did the same.
//
// Deliberately unlike the Python certd, the listing reuses the last answer
// while nothing a plugin install touches has changed: the certbot binary, the
// snap revisions under /snap, and snapd's state (a plugin snap is installed
// and connected through snapd). A plugin added any other way, with pip say,
// shows within pluginCacheTTL. Issuance still asks certbot itself, so it
// never acts on a stale answer.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const pluginCacheTTL = 5 * time.Minute

type pluginCache struct {
	mu      sync.Mutex
	sig     string
	at      time.Time
	plugins map[string]bool
}

// snapdStateFile is a variable so tests can point it elsewhere.
var snapdStateFile = "/var/lib/snapd/state.json"
var snapRoot = "/snap"

func fileSig(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return path + ":-"
	}
	return fmt.Sprintf("%s:%d:%d", path, fi.ModTime().UnixNano(), fi.Size())
}

// pluginSignature changes whenever a plugin can have been installed or removed.
func (d *Daemon) pluginSignature() string {
	parts := []string{fileSig(d.Opts.CertbotBin), fileSig(snapdStateFile)}
	if target, err := filepath.EvalSymlinks(d.Opts.CertbotBin); err == nil {
		parts = append(parts, fileSig(target))
	}
	if entries, err := os.ReadDir(snapRoot); err == nil {
		var revs []string
		for _, ent := range entries {
			if rev, err := os.Readlink(filepath.Join(snapRoot, ent.Name(), "current")); err == nil {
				revs = append(revs, ent.Name()+"="+rev)
			}
		}
		sort.Strings(revs)
		parts = append(parts, strings.Join(revs, ","))
	}
	return strings.Join(parts, "|")
}

// listedDNSPlugins is installedDNSPlugins for display, reused while the
// signature holds and the answer is younger than pluginCacheTTL.
func (d *Daemon) listedDNSPlugins() map[string]bool {
	c := &d.plugins
	c.mu.Lock()
	defer c.mu.Unlock()
	sig := d.pluginSignature()
	if c.plugins != nil && c.sig == sig && time.Since(c.at) < pluginCacheTTL {
		return copyPlugins(c.plugins)
	}
	found := d.installedDNSPlugins()
	// An empty answer is what a failed or timed-out certbot gives: ask again
	// next time rather than show "plugin missing" for five minutes.
	if len(found) > 0 {
		c.plugins, c.sig, c.at = copyPlugins(found), sig, time.Now()
	} else {
		c.plugins = nil
	}
	return found
}

func copyPlugins(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

package app

// Ports of build_info.py, updates_badge.py, updated_client.py and
// server_time.format_datetime.

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

var (
	revisionRe       = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	treeRe           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRe        = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,24})?$`)
	haproxyVersionRe = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?(?:[-+~][0-9A-Za-z.+~-]{0,60})?$`)
)

const (
	haproxyVersionTTL = 300 * time.Second
	badgeTTL          = 60 * time.Second
	badgeTimeout      = time.Second
)

type badgeCache struct {
	mu    sync.Mutex
	at    time.Time
	level any
	build any
}

type haproxyVersionCache struct {
	mu    sync.Mutex
	at    time.Time
	value any
}

var (
	badge      badgeCache
	haproxyVer haproxyVersionCache
)

// UpdatedRequest is updated_client.updated_request.
func (a *App) UpdatedRequest(payload any, timeout time.Duration) (*pyyaml.Map, error) {
	return JSONLineRequest(a.Cfg.UpdatedSocket, payload, "software-update", timeout, 64*1024, 4*1024*1024)
}

// RememberBadge is updates_badge.remember.
func RememberBadge(summary any) any {
	var level, build any
	if m, ok := summary.(*pyyaml.Map); ok {
		if l, ok := m.Value("level").(string); ok && (l == "product" || l == "os") {
			level = l
		}
		if b, ok := m.Value("build").(*pyyaml.Map); ok {
			build = b
		}
	}
	badge.mu.Lock()
	badge.at = time.Now()
	badge.level = level
	badge.build = build
	badge.mu.Unlock()
	return level
}

// ForgetBadge is updates_badge.forget.
func ForgetBadge() {
	badge.mu.Lock()
	badge.at = time.Time{}
	badge.level = nil
	badge.build = nil
	badge.mu.Unlock()
}

func (a *App) freshBadge() (any, any) {
	badge.mu.Lock()
	if !badge.at.IsZero() && time.Since(badge.at) < badgeTTL {
		l, b := badge.level, badge.build
		badge.mu.Unlock()
		return l, b
	}
	badge.mu.Unlock()
	result, err := a.UpdatedRequest(map[string]any{"action": "summary"}, badgeTimeout)
	if err == nil && truthy(result.Value("ok")) {
		RememberBadge(result)
	} else {
		RememberBadge(nil)
	}
	badge.mu.Lock()
	defer badge.mu.Unlock()
	return badge.level, badge.build
}

func (a *App) updatesBadge(c *Ctx) any {
	if !c.Superadmin() {
		return nil
	}
	l, _ := a.freshBadge()
	return l
}

func (a *App) readHAProxyVersion() any {
	reply, err := HAProxyRuntimeCommand("show info", SOCKET, 2*time.Second)
	if err != nil {
		return nil
	}
	for _, line := range pySplitlines(reply) {
		name, value, _ := strings.Cut(line, ":")
		if strings.TrimSpace(name) == "Version" {
			full := strings.TrimSpace(value)
			if !haproxyVersionRe.MatchString(full) {
				return nil
			}
			short := full
			if i := strings.IndexAny(full, "-+~"); i >= 0 {
				short = full[:i]
			}
			m := pyyaml.NewMap()
			m.Set("short", short)
			m.Set("full", full)
			return m
		}
	}
	return nil
}

func (a *App) haproxyVersion() any {
	haproxyVer.mu.Lock()
	if !haproxyVer.at.IsZero() && time.Since(haproxyVer.at) < haproxyVersionTTL {
		v := haproxyVer.value
		haproxyVer.mu.Unlock()
		return v
	}
	haproxyVer.mu.Unlock()
	v := a.readHAProxyVersion()
	haproxyVer.mu.Lock()
	haproxyVer.value = v
	haproxyVer.at = time.Now()
	haproxyVer.mu.Unlock()
	return v
}

func buildEntry(revision, committedAt, webTree any) any {
	rev := strings.ToLower(strings.TrimSpace(strOrEmpty(revision)))
	if !revisionRe.MatchString(rev) {
		return nil
	}
	tree := strings.ToLower(strings.TrimSpace(strOrEmpty(webTree)))
	if !treeRe.MatchString(tree) {
		tree = ""
	}
	m := pyyaml.NewMap()
	m.Set("revision", rev[:7])
	m.Set("when", FormatDatetime(committedAt))
	m.Set("web_tree", tree)
	return m
}

// strOrEmpty is str(value or "").
func strOrEmpty(v any) string {
	if !truthy(v) {
		return ""
	}
	return pyStr(v)
}

func (a *App) buildFooter(c *Ctx) any {
	panel := buildEntry(os.Getenv("EHP_BUILD_REVISION"), os.Getenv("EHP_BUILD_DATE"), os.Getenv("EHP_SOURCE_TREE"))
	_, reported := a.freshBadge()
	var host any
	rep, isMap := reported.(*pyyaml.Map)
	if isMap {
		// This panel's image is fingerprinted like the host's go_web_tree; a
		// broker that does not report it yet leaves the Flask web_tree.
		tree := rep.Value("go_web_tree")
		if !truthy(tree) {
			tree = rep.Value("web_tree")
		}
		host = buildEntry(rep.Value("revision"), rep.Value("committed_at"), tree)
	}
	var match any
	if pm, ok := panel.(*pyyaml.Map); ok {
		if hm, ok := host.(*pyyaml.Map); ok {
			pt, _ := pm.Value("web_tree").(string)
			ht, _ := hm.Value("web_tree").(string)
			if pt != "" && ht != "" {
				match = pt == ht
			}
		}
	}
	version := ""
	if isMap {
		v := strings.TrimSpace(strOrEmpty(rep.Value("version")))
		if versionRe.MatchString(v) {
			version = v
		}
	}
	out := pyyaml.NewMap()
	out.Set("panel", panel)
	out.Set("host", host)
	out.Set("match", match)
	out.Set("version", version)
	out.Set("haproxy", a.haproxyVersion())
	return out
}

// ServerLocation is server_time.timezone().
func ServerLocation() (*time.Location, string) {
	name := os.Getenv("EHP_SERVER_TIMEZONE")
	if name == "" {
		name = os.Getenv("TZ")
	}
	if name == "" {
		return time.UTC, "UTC"
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC, "UTC"
	}
	return loc, name
}

// FormatDatetime is server_time.format_datetime.
func FormatDatetime(value any) string {
	raw := strings.ReplaceAll(strOrEmpty(value), "Z", "+00:00")
	t, ok := parseISOAny(raw)
	if !ok {
		return ""
	}
	loc, _ := ServerLocation()
	return t.In(loc).Format("2006-01-02 15:04 MST")
}

// parseISOAny is datetime.fromisoformat; a naive value is taken as UTC.
func parseISOAny(raw string) (time.Time, bool) {
	layouts := []string{
		"2006-01-02T15:04:05.999999999-07:00", "2006-01-02T15:04:05-07:00", "2006-01-02T15:04-07:00",
		"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05-07:00", "2006-01-02 15:04-07:00",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, raw); err == nil {
			return t, true
		}
	}
	naive := []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"}
	for _, l := range naive {
		if t, err := time.ParseInLocation(l, raw, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

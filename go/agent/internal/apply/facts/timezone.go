package facts

import (
	"os"
	"path/filepath"
	"strings"
)

// Timezone is the first play's "Read the gateway's time zone" and "Remember
// the gateway's time zone": timedatectl, else /etc/timezone, else the zone
// /etc/localtime links to; anything that is not a plain zone name is UTC.
// root "" is /.
func Timezone(run Runner, root string) string {
	if root == "" {
		root = "/"
	}
	zone := ""
	if out, err := run("timedatectl", "show", "-p", "Timezone", "--value"); err == nil {
		zone = strings.TrimRight(out, "\n")
	}
	if zone == "" {
		if raw, err := os.ReadFile(filepath.Join(root, "etc", "timezone")); err == nil {
			zone = strings.TrimRight(strings.SplitN(string(raw), "\n", 2)[0], "\n")
		}
	}
	if zone == "" {
		if target, err := filepath.EvalSymlinks(filepath.Join(root, "etc", "localtime")); err == nil {
			if i := strings.LastIndex(target, "/zoneinfo/"); i >= 0 {
				target = target[i+len("/zoneinfo/"):]
			}
			target = strings.TrimPrefix(target, "posix/")
			zone = strings.TrimPrefix(target, "right/")
		}
	}
	if !plainZone(zone) {
		return "UTC"
	}
	return zone
}

// plainZone is the probe's case statement turned around: not empty, not
// absolute, no trailing slash, no "..", only [A-Za-z0-9_+/-].
func plainZone(zone string) bool {
	if zone == "" || strings.HasPrefix(zone, "/") || strings.HasSuffix(zone, "/") || strings.Contains(zone, "..") {
		return false
	}
	for _, r := range zone {
		ok := r == '_' || r == '+' || r == '/' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

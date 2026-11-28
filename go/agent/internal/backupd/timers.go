package backupd

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Read-only systemd calendar metadata for the backup schedule, with
// unambiguous Unix timestamps: the main backup timer and up to eight other
// active timers whose names say "backup".

const mainBackupTimer = "easy-ha-proxy-backup.timer"

var (
	timerName      = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,180}\.timer$`)
	timerDuration  = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(us|ms|min|s|h|d)`)
	timerCalendar  = regexp.MustCompile(`OnCalendar=([^;}]*)`)
	timerUSec      = regexp.MustCompile(`^t\s+([0-9]+)$`)
	backupTimerRef = regexp.MustCompile(`\b([A-Za-z0-9_.:@-]*backup[A-Za-z0-9_.:@-]*\.timer)\b`)
)

// timerRunner runs a read-only command and returns its output, "" when it
// failed or took longer than two seconds.
type timerRunner func(argv ...string) string

func runTimerCommand(argv ...string) string {
	rc, out, _, err := runCapture(2*time.Second, []byte{}, nil, argv[0], argv[1:]...)
	if err != nil || rc != 0 {
		return ""
	}
	if len(out) > 128*1024 {
		out = out[:128*1024]
	}
	return strings.TrimSpace(string(out))
}

// timerDurationSeconds reads a systemd duration ("1h 30min"); nil when it is
// not one.
func timerDurationSeconds(text string) any {
	if text == "0" {
		return 0
	}
	if text == "" || strings.TrimSpace(timerDuration.ReplaceAllString(text, "")) != "" {
		return nil
	}
	units := map[string]float64{"us": 0.000001, "ms": 0.001, "s": 1, "min": 60, "h": 3600, "d": 86400}
	total := 0.0
	for _, m := range timerDuration.FindAllStringSubmatch(text, -1) {
		count, _ := strconv.ParseFloat(m[1], 64)
		total += count * units[m[2]]
	}
	return total
}

// busPathEscape is systemd's object-path escaping of a unit name.
func busPathEscape(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x80 && (c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "_%02x", c)
		}
	}
	return b.String()
}

func readTimer(run timerRunner, name string) map[string]any {
	text := run("/usr/bin/systemctl", "show", name,
		"--property=ActiveState,TimersCalendar,NextElapseUSecRealtime,RandomizedDelayUSec,Description")
	props := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = v
		}
	}
	active := props["ActiveState"] == "active"
	calendar := []string{}
	for _, m := range timerCalendar.FindAllStringSubmatch(props["TimersCalendar"], -1) {
		calendar = append(calendar, m[1])
	}
	result := map[string]any{"unit": name, "active": active, "description": props["Description"], "next_run": "",
		"next_run_at": nil, "random_delay_seconds": timerDurationSeconds(props["RandomizedDelayUSec"]), "calendar": calendar}
	if active {
		result["next_run"] = props["NextElapseUSecRealtime"]
		// `systemctl show` keeps pretty timestamps even with --timestamp=unix;
		// D-Bus has the microsecond integer, daylight-saving folds included.
		value := run("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
			"/org/freedesktop/systemd1/unit/"+busPathEscape(name), "org.freedesktop.systemd1.Timer", "NextElapseUSecRealtime")
		if m := timerUSec.FindStringSubmatch(value); m != nil {
			if usec, err := strconv.ParseInt(m[1], 10, 64); err == nil && usec > 0 && usec < 1e18 {
				result["next_run_at"] = float64(usec) / 1e6
			}
		}
	}
	return result
}

// backupTimers is what the schedule page shows about the timers.
func backupTimers(run timerRunner, now time.Time) map[string]any {
	main := readTimer(run, mainBackupTimer)
	text := run("/usr/bin/systemctl", "list-units", "--all", "--type=timer", "--plain", "--no-legend", "--no-pager", "*backup*.timer")
	seen := map[string]bool{}
	var names []string
	for _, m := range backupTimerRef.FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	if len(names) > 16 {
		names = names[:16]
	}
	others := []any{}
	for _, name := range names {
		if name == mainBackupTimer || name == "dpkg-db-backup.timer" || !timerName.MatchString(name) {
			continue
		}
		if t := readTimer(run, name); t["active"] == true && len(others) < 8 {
			others = append(others, t)
		}
	}
	return map[string]any{"timer": main, "other_timers": others, "timer_checked_at": float64(now.UnixNano()) / 1e9}
}

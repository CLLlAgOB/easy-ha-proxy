package backupd

import (
	"strings"
	"testing"
	"time"
)

func TestBackupTimersReadTheCalendarAndTheExactNextRun(t *testing.T) {
	run := func(argv ...string) string {
		joined := strings.Join(argv, " ")
		switch {
		case strings.Contains(joined, "show easy-ha-proxy-backup.timer"):
			return "ActiveState=active\nDescription=Daily backup\nNextElapseUSecRealtime=Thu 2026-11-27 03:10:00 UTC\n" +
				"RandomizedDelayUSec=10min\nTimersCalendar={ OnCalendar=*-*-* 03:00:00 ; next_elapse=Thu 2026-11-27 03:00:00 UTC }"
		case strings.Contains(joined, "get-property") && strings.Contains(joined, "easy_2dha_2dproxy_2dbackup_2etimer"):
			return "t 1795835400000000"
		case strings.Contains(joined, "list-units"):
			return "easy-ha-proxy-backup.timer loaded active waiting\nvault-backup.timer loaded active waiting\n" +
				"old-backup.timer loaded inactive dead\ndpkg-db-backup.timer loaded active waiting"
		case strings.Contains(joined, "show vault-backup.timer"):
			return "ActiveState=active\nDescription=Vault\nRandomizedDelayUSec=0\nTimersCalendar={ OnCalendar=weekly ; }"
		case strings.Contains(joined, "show old-backup.timer"):
			return "ActiveState=inactive\nRandomizedDelayUSec=0"
		}
		return ""
	}
	got := backupTimers(run, time.Unix(1795800000, 0))
	main := got["timer"].(map[string]any)
	if main["active"] != true || main["next_run_at"] != 1795835400.0 || main["random_delay_seconds"] != 600.0 {
		t.Fatalf("main %v", main)
	}
	if cal := main["calendar"].([]string); len(cal) != 1 || strings.TrimSpace(cal[0]) != "*-*-* 03:00:00" {
		t.Fatalf("calendar %q", cal)
	}
	others := got["other_timers"].([]any)
	if len(others) != 1 || others[0].(map[string]any)["unit"] != "vault-backup.timer" {
		t.Fatalf("others %v", others)
	}
	if got["timer_checked_at"] != 1795800000.0 {
		t.Fatalf("checked at %v", got["timer_checked_at"])
	}
}

func TestATimerThatCannotBeReadIsInactive(t *testing.T) {
	got := backupTimers(func(...string) string { return "" }, time.Now())
	main := got["timer"].(map[string]any)
	if main["active"] != false || main["next_run_at"] != nil || main["random_delay_seconds"] != nil {
		t.Fatalf("main %v", main)
	}
	if len(got["other_timers"].([]any)) != 0 {
		t.Fatal("other timers from nothing")
	}
}

func TestSystemdDurations(t *testing.T) {
	for text, want := range map[string]any{"0": 0, "1h 30min": 5400.0, "250ms": 0.25, "": nil, "soon": nil} {
		if got := timerDurationSeconds(text); got != want {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
}

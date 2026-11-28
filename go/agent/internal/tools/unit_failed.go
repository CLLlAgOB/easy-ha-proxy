// Package tools implements native Go replacements for host oneshot and timer utilities
// (unit-failed, backup-run, server-state).
package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

type unitAlertRule struct {
	Rule  string
	Title string
}

// UnitFailureRules mirrors easy-ha-proxy-unit-failed.py RULES.
var UnitFailureRules = map[string]unitAlertRule{
	"easy-ha-proxy-backup.service": {Rule: "backup.failed", Title: "Scheduled backup failed"},
}

const (
	unitJournalLines   = 12
	unitMaxDetailChars = 1200
)

// UnitFailedOptions allows injecting commands and alert client for testing.
type UnitFailedOptions struct {
	Alerts       *alerts.Client
	SystemctlBin string
	Journalctl   string
	Stderr       io.Writer
}

// ParseJournalLastWords filters journalctl --output=json lines, dropping systemd boilerplate
// and binary MESSAGE arrays, matching easy-ha-proxy-unit-failed.py.
func ParseJournalLastWords(raw string) string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if id, _ := entry["SYSLOG_IDENTIFIER"].(string); id == "systemd" {
			continue
		}
		msg, ok := entry["MESSAGE"].(string)
		if !ok {
			continue // journald sends binary blobs as arrays
		}
		msg = strings.TrimSpace(msg)
		if msg != "" {
			lines = append(lines, msg)
		}
	}
	if len(lines) > unitJournalLines {
		lines = lines[len(lines)-unitJournalLines:]
	}
	joined := strings.Join(lines, " | ")
	return pyx.TruncRunes(joined, unitMaxDetailChars)
}

// RunUnitFailed reports a failed systemd unit to alertd, returning exact CLI exit codes.
func RunUnitFailed(ctx context.Context, unit string, opts UnitFailedOptions) int {
	stderr := opts.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	unit = strings.TrimSpace(unit)
	if unit == "" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent unit-failed <unit>")
		return 2
	}
	known, ok := UnitFailureRules[unit]
	if !ok {
		fmt.Fprintf(stderr, "no alert rule is defined for %s\n", unit)
		return 0
	}
	client := opts.Alerts
	if client == nil {
		client = alerts.FromEnv()
	}
	if !client.Enabled() {
		fmt.Fprintln(stderr, "the alert engine is not configured")
		return 0
	}

	systemctl := opts.SystemctlBin
	if systemctl == "" {
		systemctl = "systemctl"
	}
	journalctl := opts.Journalctl
	if journalctl == "" {
		journalctl = "journalctl"
	}

	props := queryUnitProps(ctx, systemctl, unit)
	result := props["Result"]
	detail := queryLastWords(ctx, journalctl, unit, props["InvocationID"])
	if detail == "" {
		detail = "see journalctl -u " + unit
	}
	summary := known.Title
	if result != "" {
		summary = fmt.Sprintf("%s (%s)", known.Title, result)
	}
	delivered := client.Observe(ctx, alerts.Observation{
		Rule:    known.Rule,
		Subject: unit,
		Summary: summary,
		Detail:  detail,
	})
	if !delivered {
		fmt.Fprintln(stderr, "the alert engine did not accept the report")
		return 1
	}
	return 0
}

func queryUnitProps(ctx context.Context, bin, unit string) map[string]string {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, bin, "show", unit, "--property=Result", "--property=InvocationID").Output()
	if err != nil {
		return map[string]string{}
	}
	res := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		k, v, found := strings.Cut(line, "=")
		if found {
			res[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return res
}

func queryLastWords(ctx context.Context, bin, unit, invocation string) string {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{}
	if invocation != "" {
		args = append(args, "_SYSTEMD_INVOCATION_ID="+invocation)
	} else {
		args = append(args, "--unit", unit)
	}
	args = append(args, "--lines", fmt.Sprintf("%d", unitJournalLines), "--no-pager", "--output", "json")
	out, err := exec.CommandContext(cmdCtx, bin, args...).Output()
	if err != nil {
		return ""
	}
	return ParseJournalLastWords(string(out))
}

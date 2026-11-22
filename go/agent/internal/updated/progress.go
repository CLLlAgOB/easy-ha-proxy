package updated

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	ComponentHeading = "=== Applying component:"
	MaxProgressTask  = 160
)

var (
	progressRe = regexp.MustCompile(`(?m)^EHP-PROGRESS (?:phase=([a-z-]{1,24})|(\d{1,6})/(\d{1,6})(?: ([^\n]{0,400}))?)[ \t]*$`)
	validPhases = map[string]struct{}{
		"checking": {}, "verifying": {}, "starting": {}, "source": {},
		"prepare": {}, "syntax": {}, "playbook": {}, "rechecking": {},
	}
)

// Progress describes the current step parsed from an update job's log tail.
type Progress struct {
	Phase string `json:"phase,omitempty"`
	Done  int    `json:"done,omitempty"`
	Total int    `json:"total,omitempty"`
	Task  string `json:"task,omitempty"`
}

// ParseProgress extracts the latest phase and task counter after the most recent
// "=== Applying component:" heading, matching updated/constants.py PROGRESS_RE.
func ParseProgress(logText string) Progress {
	scope := logText
	if idx := strings.LastIndex(logText, ComponentHeading); idx >= 0 {
		scope = logText[idx:]
	}
	var out Progress
	matches := progressRe.FindAllStringSubmatch(scope, -1)
	for _, m := range matches {
		if m[1] != "" {
			if _, ok := validPhases[m[1]]; ok {
				out.Phase = m[1]
			}
			continue
		}
		done, err1 := strconv.Atoi(m[2])
		total, err2 := strconv.Atoi(m[3])
		if err1 == nil && err2 == nil && total > 0 {
			if done > total {
				done = total
			}
			out.Done = done
			out.Total = total
			task := strings.TrimSpace(m[4])
			if len(task) > MaxProgressTask {
				task = task[:MaxProgressTask]
			}
			out.Task = task
		}
	}
	return out
}

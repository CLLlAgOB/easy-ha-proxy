package engine

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Command is a command task.
type Command struct {
	Argv []string
	// Changes is changed_when true (the default: running it is the change);
	// false is changed_when: false -- it still runs on every apply.
	Changes bool
	// IgnoreErrors is failed_when: false.
	IgnoreErrors bool
	// Retries and Delay are retries/delay/until: succeeded.
	Retries int
	Delay   time.Duration
	// Probe marks a read-only command: it runs in plan mode too, and its
	// output is kept for later steps' conditions.
	Probe bool
	// ChangedWhen is changed_when over the output (and exit code): the
	// command runs on apply and reports changed only when it holds.
	ChangedWhen func(out string, code int) bool
	// Dir and Env are chdir: and environment: (through env -C, so the
	// System's Exec needs nothing more).
	Dir string
	Env []string
	// MergeStderr keeps standard error in Output too (stderr: read by a
	// changed_when).
	MergeStderr bool
	Output      string
	Code        int

	changed bool
}

// Changed is the outcome of a command with ChangedWhen.
func (c *Command) Changed() bool { return c.changed }

func (c *Command) Describe() string { return "command " + strings.Join(c.Argv, " ") }

func (c *Command) Check(sys *System) (Change, error) {
	c.changed = false
	if c.Probe {
		return Change{Summary: "read"}, c.run(sys)
	}
	if c.Changes {
		return Change{Needed: true, Summary: "run"}, nil
	}
	return Change{Summary: "runs on apply", Run: true}, nil
}

func (c *Command) Apply(sys *System, _ Change) error {
	if err := c.run(sys); err != nil {
		return err
	}
	if c.ChangedWhen != nil {
		c.changed = c.ChangedWhen(c.Output, c.Code)
	}
	return nil
}

// argv is the command as it is executed: in its directory, with its
// environment, standard error merged when asked.
func (c *Command) argv() []string {
	argv := c.Argv
	if c.Dir != "" || len(c.Env) > 0 {
		prefix := []string{"env"}
		if c.Dir != "" {
			prefix = append(prefix, "-C", c.Dir)
		}
		argv = append(append(prefix, c.Env...), argv...)
	}
	if c.MergeStderr {
		argv = append([]string{"/bin/sh", "-c", `exec "$@" 2>&1`, "sh"}, argv...)
	}
	return argv
}

func (c *Command) run(sys *System) error {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			time.Sleep(c.Delay)
		}
		argv := c.argv()
		out, code, err := sys.Exec(argv[0], argv[1:]...)
		c.Output, c.Code = out, code
		switch {
		case err != nil:
			lastErr = err
		case code != 0:
			lastErr = fmt.Errorf("%s: exit %d %s", c.Argv[0], code, strings.TrimSpace(out))
		default:
			return nil
		}
	}
	if c.IgnoreErrors {
		return nil
	}
	return lastErr
}

// Sysctl is ansible.posix.sysctl with sysctl_file: the key's line in that
// file (every line rewritten as key=value, as the module rewrites them), and
// with Reload, sysctl -p on the file when it changed.
type Sysctl struct {
	Name, Value, File string
	Reload            bool

	lines []string
}

func (s *Sysctl) Describe() string { return "sysctl " + s.Name + " in " + s.File }

func (s *Sysctl) Check(sys *System) (Change, error) {
	raw, err := os.ReadFile(sys.Path(s.File))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Change{}, err
	}
	current, found := "", false
	s.lines = nil
	seen := map[string]bool{}
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		if line == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || !strings.Contains(line, "=") {
			s.lines = append(s.lines, line)
			continue
		}
		k, v, _ := strings.Cut(trimmed, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		if k == s.Name {
			current, found = v, true
			s.lines = append(s.lines, k+"="+s.Value+"\n")
		} else {
			s.lines = append(s.lines, k+"="+v+"\n")
		}
	}
	if !found {
		s.lines = append(s.lines, s.Name+"="+s.Value+"\n")
	}
	if found && strings.Join(strings.Fields(current), " ") == strings.Join(strings.Fields(s.Value), " ") {
		return Change{}, nil
	}
	return Change{Needed: true, Summary: fmt.Sprintf("%s=%s", s.Name, s.Value)}, nil
}

func (s *Sysctl) Apply(sys *System, _ Change) error {
	// root:root as the module leaves it, resolved like every other owner (a
	// test's System maps it to the user running the test).
	uid, gid, err := sys.ids("root", "root")
	if err != nil {
		return err
	}
	if err := writeAtomic(sys.Path(s.File), []byte(strings.Join(s.lines, "")), uid, gid, 0o644); err != nil {
		return err
	}
	if !s.Reload {
		return nil
	}
	out, code, err := sys.Exec("sysctl", "-p", s.File)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("sysctl -p %s: exit %d %s", s.File, code, strings.TrimSpace(out))
	}
	return nil
}

// Multi is a loop: one task over several items, changed if any item is.
type Multi struct {
	Desc  string
	Items []Resource

	changes []Change
}

func (m *Multi) Describe() string { return m.Desc }

func (m *Multi) Check(sys *System) (Change, error) {
	m.changes = make([]Change, len(m.Items))
	var notes []string
	out := Change{}
	for i, item := range m.Items {
		c, err := item.Check(sys)
		if err != nil {
			return Change{}, fmt.Errorf("%s: %w", item.Describe(), err)
		}
		m.changes[i] = c
		if c.Needed {
			out.Needed = true
			notes = append(notes, item.Describe()+": "+c.Summary)
		}
		out.Run = out.Run || c.Run
	}
	if len(m.Items) == 0 {
		out.Summary = "no items"
	} else {
		out.Summary = strings.Join(notes, "; ")
	}
	return out, nil
}

func (m *Multi) Apply(sys *System, _ Change) error {
	for i, item := range m.Items {
		if c := m.changes[i]; c.Needed || c.Run {
			if err := item.Apply(sys, c); err != nil {
				return fmt.Errorf("%s: %w", item.Describe(), err)
			}
		}
	}
	return nil
}

// CronAbsent is the cron module with state=absent: the "#Ansible: <Name>"
// line and the job under it leave the user's crontab.
type CronAbsent struct{ Name, User string }

func (c *CronAbsent) Describe() string { return "cron entry " + c.Name }

func (c *CronAbsent) lines(sys *System) ([]string, bool, error) {
	out, code, err := sys.Exec("crontab", "-l", "-u", c.User)
	if err != nil {
		return nil, false, err
	}
	if code != 0 {
		return nil, false, nil // no crontab at all
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for _, line := range lines {
		if line == "#Ansible: "+c.Name {
			return lines, true, nil
		}
	}
	return lines, false, nil
}

func (c *CronAbsent) Check(sys *System) (Change, error) {
	_, found, err := c.lines(sys)
	if err != nil || !found {
		return Change{}, err
	}
	return Change{Needed: true, Summary: "remove"}, nil
}

func (c *CronAbsent) Apply(sys *System, _ Change) error {
	lines, found, err := c.lines(sys)
	if err != nil || !found {
		return err
	}
	var kept []string
	for i := 0; i < len(lines); i++ {
		if lines[i] == "#Ansible: "+c.Name {
			i++ // and its job
			continue
		}
		kept = append(kept, lines[i])
	}
	tmp, err := os.CreateTemp("", "ehp-crontab-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.Join(kept, "\n") + "\n"); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	out, code, err := sys.Exec("crontab", "-u", c.User, tmp.Name())
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("crontab -u %s: exit %d %s", c.User, code, strings.TrimSpace(out))
	}
	return nil
}

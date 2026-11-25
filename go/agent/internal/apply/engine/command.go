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
	Probe  bool
	Output string
	Code   int
}

func (c *Command) Describe() string { return "command " + strings.Join(c.Argv, " ") }

func (c *Command) Check(sys *System) (Change, error) {
	if c.Probe {
		return Change{Summary: "read"}, c.run(sys)
	}
	if c.Changes {
		return Change{Needed: true, Summary: "run"}, nil
	}
	return Change{Summary: "runs on apply", Run: true}, nil
}

func (c *Command) Apply(sys *System, _ Change) error { return c.run(sys) }

func (c *Command) run(sys *System) error {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			time.Sleep(c.Delay)
		}
		out, code, err := sys.Exec(c.Argv[0], c.Argv[1:]...)
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
	if err := writeAtomic(sys.Path(s.File), []byte(strings.Join(s.lines, "")), 0, 0, 0o644); err != nil {
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

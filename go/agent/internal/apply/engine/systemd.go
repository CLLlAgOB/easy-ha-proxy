package engine

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Unit is the systemd module for one unit: enabled and/or a state, enabled
// handled first, as Ansible does.
type Unit struct {
	Name    string
	Enabled *bool  // nil leaves it
	State   string // "", started, stopped, restarted

	enable, disable bool
	action          string
}

// Bool is a helper for Unit.Enabled.
func Bool(b bool) *bool { return &b }

func (u *Unit) Describe() string { return "unit " + u.Name }

func (u *Unit) Check(sys *System) (Change, error) {
	u.enable, u.disable, u.action = false, false, ""
	var notes []string
	if u.Enabled != nil {
		out, code, err := sys.Exec("systemctl", "is-enabled", u.Name)
		if err != nil {
			return Change{}, err
		}
		// Ansible: enabled when is-enabled succeeds, unless it only says
		// "indirect" or "alias".
		state := strings.TrimSpace(out)
		enabled := code == 0 && state != "indirect" && state != "alias"
		if *u.Enabled && !enabled {
			u.enable = true
			notes = append(notes, "enable")
		}
		if !*u.Enabled && enabled {
			u.disable = true
			notes = append(notes, "disable")
		}
	}
	switch u.State {
	case "":
	case "restarted":
		u.action = "restart"
	case "started", "stopped":
		out, _, err := sys.Exec("systemctl", "show", u.Name, "--property=ActiveState", "--value")
		if err != nil {
			return Change{}, err
		}
		active := strings.TrimSpace(out)
		running := active == "active" || active == "activating"
		if u.State == "started" && !running {
			u.action = "start"
		}
		if u.State == "stopped" && running {
			u.action = "stop"
		}
	default:
		return Change{}, fmt.Errorf("unit %s: unknown state %q", u.Name, u.State)
	}
	if u.action != "" {
		notes = append(notes, u.action)
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (u *Unit) Apply(sys *System, _ Change) error {
	run := func(args ...string) error {
		out, code, err := sys.Exec("systemctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("systemctl %s: exit %d %s", strings.Join(args, " "), code, strings.TrimSpace(out))
		}
		return nil
	}
	if u.enable {
		if err := run("enable", u.Name); err != nil {
			return err
		}
	}
	if u.disable {
		if err := run("disable", u.Name); err != nil {
			return err
		}
	}
	if u.action != "" {
		return run(u.action, u.Name)
	}
	return nil
}

// DaemonReload is systemd daemon_reload: true. A stage runs it under the
// condition Ansible gives it ("if the unit changed"), so it always acts.
type DaemonReload struct{}

func (DaemonReload) Describe() string { return "systemd daemon-reload" }

func (DaemonReload) Check(*System) (Change, error) {
	return Change{Needed: true, Summary: "daemon-reload"}, nil
}

func (DaemonReload) Apply(sys *System, _ Change) error {
	out, code, err := sys.Exec("systemctl", "daemon-reload")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("systemctl daemon-reload: exit %d %s", code, strings.TrimSpace(out))
	}
	return nil
}

// Packages is the package module with state=present: install those missing.
type Packages struct {
	Names   []string
	missing []string
}

func (p *Packages) Describe() string { return "packages " + strings.Join(p.Names, " ") }

func (p *Packages) Check(sys *System) (Change, error) {
	p.missing = nil
	args := append([]string{"-W", "-f", "${Package}\t${db:Status-Abbrev}\n"}, p.Names...)
	out, _, err := sys.Exec("dpkg-query", args...)
	if err != nil {
		return Change{}, err
	}
	installed := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name, status, ok := strings.Cut(line, "\t")
		if ok && len(status) >= 2 && status[1] == 'i' {
			installed[strings.SplitN(name, ":", 2)[0]] = true
		}
	}
	for _, name := range p.Names {
		if !installed[name] {
			p.missing = append(p.missing, name)
		}
	}
	if len(p.missing) == 0 {
		return Change{}, nil
	}
	return Change{Needed: true, Summary: "install " + strings.Join(p.missing, " ")}, nil
}

func (p *Packages) Apply(sys *System, _ Change) error {
	args := append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q"}, p.missing...)
	out, code, err := sys.Exec("env", args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("apt-get install: exit %d %s", code, strings.TrimSpace(out))
	}
	return nil
}

// Func is a resource written out in the stage itself, for the one-off checks
// a task file does with stat and command.
type Func struct {
	Desc    string
	CheckFn func(sys *System) (Change, error)
	ApplyFn func(sys *System) error
}

func (f *Func) Describe() string                  { return f.Desc }
func (f *Func) Check(sys *System) (Change, error) { return f.CheckFn(sys) }
func (f *Func) Apply(sys *System, _ Change) error { return f.ApplyFn(sys) }

// ParseMode reads an Ansible mode string such as "0640" or "2750".
func ParseMode(s string) (os.FileMode, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32)
	if err != nil || n > 0o7777 {
		return 0, fmt.Errorf("mode %q is not an octal mode", s)
	}
	mode := os.FileMode(n & 0o777)
	if n&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if n&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if n&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode, nil
}

// Hold is dpkg_selections selection=hold for one package.
type Hold struct{ Name string }

func (h *Hold) Describe() string { return "dpkg hold " + h.Name }

func (h *Hold) Check(sys *System) (Change, error) {
	out, _, err := sys.Exec("dpkg", "--get-selections", h.Name)
	if err != nil {
		return Change{}, err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.SplitN(f[0], ":", 2)[0] == h.Name && f[1] == "hold" {
			return Change{}, nil
		}
	}
	return Change{Needed: true, Summary: "hold"}, nil
}

func (h *Hold) Apply(sys *System, _ Change) error {
	out, code, err := sys.Exec("apt-mark", "hold", h.Name)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("apt-mark hold %s: exit %d %s", h.Name, code, strings.TrimSpace(out))
	}
	return nil
}

package engine

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
)

// System is the host a run works on. Tests point Root at a temporary
// directory and replace the lookups and Exec.
type System struct {
	Root        string // prefix for every path; "" is /
	LookupUser  func(name string) (int, error)
	LookupGroup func(name string) (int, error)
	// Exec runs a command: its standard output and exit code; err only when it
	// could not run at all.
	Exec func(name string, args ...string) (stdout string, code int, err error)
	// ExecEnv is Exec with extra environment variables (a secret a check needs
	// stays out of the argument list). Nil falls back to Exec without them.
	ExecEnv func(env []string, name string, args ...string) (stdout string, code int, err error)
}

// RunEnv runs a command with extra environment variables.
func (s *System) RunEnv(env []string, name string, args ...string) (string, int, error) {
	if s.ExecEnv == nil {
		return s.Exec(name, args...)
	}
	return s.ExecEnv(env, name, args...)
}

// Host is the real system.
func Host() *System {
	return &System{LookupUser: lookupUser, LookupGroup: lookupGroup, Exec: execCommand, ExecEnv: execCommandEnv}
}

// Path maps a host path into Root.
func (s *System) Path(p string) string {
	if s.Root == "" {
		return p
	}
	return filepath.Join(s.Root, p)
}

func lookupUser(name string) (int, error) {
	if id, err := strconv.Atoi(name); err == nil {
		return id, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

func lookupGroup(name string) (int, error) {
	if id, err := strconv.Atoi(name); err == nil {
		return id, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

func execCommand(name string, args ...string) (string, int, error) {
	return execCommandEnv(nil, name, args...)
}

func execCommandEnv(env []string, name string, args ...string) (string, int, error) {
	cmd := exec.Command(name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return out.String(), 0, nil
}

// ids resolves an owner and group; an empty name keeps whatever is there (-1).
func (s *System) ids(owner, group string) (int, int, error) {
	uid, gid := -1, -1
	if owner != "" {
		id, err := s.LookupUser(owner)
		if err != nil {
			return 0, 0, err
		}
		uid = id
	}
	if group != "" {
		id, err := s.LookupGroup(group)
		if err != nil {
			return 0, 0, err
		}
		gid = id
	}
	return uid, gid, nil
}

func fileIDs(fi os.FileInfo) (int, int) {
	if st, ok := statT(fi); ok {
		return st.uid, st.gid
	}
	return -1, -1
}

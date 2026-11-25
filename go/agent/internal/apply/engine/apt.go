package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// AptCache is the apt module's update_cache with cache_valid_time: refresh
// the package lists when they are older than ValidTime (0 refreshes always).
type AptCache struct{ ValidTime time.Duration }

func (a *AptCache) Describe() string { return "apt update" }

// listsAge is how Ansible's apt module dates the cache: the update-success
// stamp, else the lists directory.
func listsAge(sys *System) (time.Duration, bool) {
	for _, p := range []string{"/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists"} {
		if fi, err := os.Stat(sys.Path(p)); err == nil {
			return time.Since(fi.ModTime()), true
		}
	}
	return 0, false
}

func (a *AptCache) Check(sys *System) (Change, error) {
	if age, ok := listsAge(sys); ok && a.ValidTime > 0 && age < a.ValidTime {
		return Change{}, nil
	}
	return Change{Needed: true, Summary: "refresh the package lists"}, nil
}

func (a *AptCache) Apply(sys *System, _ Change) error {
	out, code, err := sys.Exec("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-q")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("apt-get update: exit %d %s", code, strings.TrimSpace(out))
	}
	return nil
}

// AptInstall is the apt module installing packages, with optional version
// globs ("haproxy-awslc=3.4.*") and policy_rc_d (no service starts while
// it installs).
type AptInstall struct {
	Names     []string
	PolicyRcD int // 0 leaves services alone; 101 stops them from starting
	// UpdateCache and CacheValid are the task's update_cache and
	// cache_valid_time. A stale list is refreshed on apply, but as in the apt
	// module it is not a change by itself when the task names packages.
	UpdateCache bool
	CacheValid  time.Duration

	missing []string
	stale   bool
}

func (a *AptInstall) Describe() string { return "apt install " + strings.Join(a.Names, " ") }

func (a *AptInstall) Check(sys *System) (Change, error) {
	a.missing = nil
	versions := map[string]string{}
	out, _, err := sys.Exec("dpkg-query", "-W", "-f", "${Package}\t${db:Status-Abbrev}\t${Version}\n")
	if err != nil {
		return Change{}, err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 3 && len(f[1]) >= 2 && f[1][1] == 'i' {
			versions[strings.SplitN(f[0], ":", 2)[0]] = f[2]
		}
	}
	for _, spec := range a.Names {
		name, want, pinned := strings.Cut(spec, "=")
		have, ok := versions[name]
		if !ok {
			a.missing = append(a.missing, spec)
			continue
		}
		if pinned {
			if match, _ := path.Match(want, have); !match {
				a.missing = append(a.missing, spec)
			}
		}
	}
	if a.UpdateCache {
		age, ok := listsAge(sys)
		a.stale = !ok || a.CacheValid == 0 || age >= a.CacheValid
	}
	if len(a.missing) == 0 {
		if a.stale {
			return Change{Summary: "package lists refreshed on apply", Run: true}, nil
		}
		return Change{}, nil
	}
	return Change{Needed: true, Summary: "install " + strings.Join(a.missing, " ")}, nil
}

func (a *AptInstall) Apply(sys *System, _ Change) error {
	if a.stale {
		if err := (&AptCache{}).Apply(sys, Change{}); err != nil {
			return err
		}
	}
	if len(a.missing) == 0 {
		return nil
	}
	if a.PolicyRcD != 0 {
		policy := sys.Path("/usr/sbin/policy-rc.d")
		if _, err := os.Lstat(policy); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(policy, []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", a.PolicyRcD)), 0o755); err != nil {
				return err
			}
			defer os.Remove(policy)
		}
	}
	args := append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q"}, a.missing...)
	out, code, err := sys.Exec("env", args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("apt-get install: exit %d %s", code, strings.TrimSpace(out))
	}
	return nil
}

// AptRepository is apt_repository with filename: the repository line, its
// spaces collapsed as the module writes it, alone in sources.list.d/<File>.list.
type AptRepository struct {
	Line, File string
	Mode       os.FileMode
	file       *File
}

func (a *AptRepository) Describe() string { return "apt repository " + a.File }

func (a *AptRepository) path() string { return "/etc/apt/sources.list.d/" + a.File + ".list" }

func (a *AptRepository) Check(sys *System) (Change, error) {
	a.file = &File{Path: a.path(), Content: []byte(strings.Join(strings.Fields(a.Line), " ") + "\n"),
		Owner: "root", Group: "root", Mode: a.Mode}
	return a.file.Check(sys)
}

func (a *AptRepository) Apply(sys *System, c Change) error { return a.file.Apply(sys, c) }

// GetURL is get_url with a sha256 checksum: download only when the file is
// missing or differs, and never keep a download that does not match.
type GetURL struct {
	URL, Dest    string
	SHA256       string
	Owner, Group string
	Mode         os.FileMode
	Client       *http.Client
}

func (g *GetURL) Describe() string { return "download " + g.Dest }

func (g *GetURL) Check(sys *System) (Change, error) {
	raw, err := os.ReadFile(sys.Path(g.Dest))
	if errors.Is(err, os.ErrNotExist) {
		return Change{Needed: true, Summary: "download " + g.URL}, nil
	}
	if err != nil {
		return Change{}, err
	}
	sum := sha256.Sum256(raw)
	// Without a checksum an existing file is kept, as get_url (force: no) does.
	if g.SHA256 != "" && hex.EncodeToString(sum[:]) != strings.ToLower(g.SHA256) {
		return Change{Needed: true, Summary: "checksum differs, download " + g.URL}, nil
	}
	fi, err := os.Lstat(sys.Path(g.Dest))
	if err != nil {
		return Change{}, err
	}
	notes, err := attrNotes(sys, fi, g.Owner, g.Group, g.Mode)
	if err != nil {
		return Change{}, err
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (g *GetURL) Apply(sys *System, _ Change) error {
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Get(g.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", g.URL, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); g.SHA256 != "" && got != strings.ToLower(g.SHA256) {
		return fmt.Errorf("download %s: sha256 %s, want %s", g.URL, got, g.SHA256)
	}
	uid, gid, err := sys.ids(g.Owner, g.Group)
	if err != nil {
		return err
	}
	return writeAtomic(sys.Path(g.Dest), raw, uid, gid, g.Mode)
}

// Group is the group module with state=present, with its gid when GID is
// set (an existing group with another gid is given this one).
type Group struct {
	Name   string
	GID    string
	System bool

	exists bool
}

func (g *Group) Describe() string { return "group " + g.Name }

func (g *Group) Check(sys *System) (Change, error) {
	out, code, err := sys.Exec("getent", "group", g.Name)
	if err != nil {
		return Change{}, err
	}
	g.exists = code == 0
	if !g.exists {
		return Change{Needed: true, Summary: "create"}, nil
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if g.GID != "" && len(fields) > 2 && fields[2] != g.GID {
		return Change{Needed: true, Summary: "gid " + fields[2] + " -> " + g.GID}, nil
	}
	return Change{}, nil
}

func (g *Group) Apply(sys *System, _ Change) error {
	tool, args := "groupadd", []string{}
	if g.exists {
		tool = "groupmod"
	} else if g.System {
		args = append(args, "--system")
	}
	if g.GID != "" {
		args = append(args, "-g", g.GID)
	}
	args = append(args, g.Name)
	out, code, err := sys.Exec(tool, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s %s: exit %d %s", tool, g.Name, code, strings.TrimSpace(out))
	}
	return nil
}

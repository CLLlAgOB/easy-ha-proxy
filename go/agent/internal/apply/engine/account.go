package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Outcome is a resource whose change is known only once it ran: a command
// with changed_when over its output. Check reports Run; after Apply, Changed
// says whether it changed anything.
type Outcome interface {
	Resource
	Changed() bool
}

// User is the user module with state=present for a system account: created
// if missing, its primary group and shell kept as asked.
type User struct {
	Name, Group, Shell string
	UID                string // "" leaves it to useradd
	System, NoHome     bool

	create bool
}

func (u *User) Describe() string { return "user " + u.Name }

func (u *User) Check(sys *System) (Change, error) {
	u.create = false
	out, code, err := sys.Exec("getent", "passwd", u.Name)
	if err != nil {
		return Change{}, err
	}
	if code != 0 {
		u.create = true
		return Change{Needed: true, Summary: "create"}, nil
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 {
		return Change{}, fmt.Errorf("getent passwd %s: %q", u.Name, out)
	}
	var notes []string
	if u.Group != "" {
		gid, err := sys.LookupGroup(u.Group)
		if err != nil {
			return Change{}, err
		}
		if fields[3] != fmt.Sprint(gid) {
			notes = append(notes, fmt.Sprintf("group %s -> %d", fields[3], gid))
		}
	}
	if u.UID != "" && fields[2] != u.UID {
		notes = append(notes, "uid "+fields[2]+" -> "+u.UID)
	}
	if u.Shell != "" && fields[6] != u.Shell {
		notes = append(notes, "shell "+fields[6]+" -> "+u.Shell)
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (u *User) Apply(sys *System, _ Change) error {
	var args []string
	tool := "usermod"
	if u.create {
		tool = "useradd"
		if u.System {
			args = append(args, "--system")
		}
		if u.NoHome {
			args = append(args, "--no-create-home")
		}
	}
	if u.UID != "" {
		args = append(args, "-u", u.UID)
	}
	if u.Group != "" {
		args = append(args, "-g", u.Group)
	}
	if u.Shell != "" {
		args = append(args, "-s", u.Shell)
	}
	args = append(args, u.Name)
	out, code, err := sys.Exec(tool, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s %s: exit %d %s", tool, u.Name, code, strings.TrimSpace(out))
	}
	return nil
}

// Attrs is file state=file: an existing file's owner, group and mode; a
// missing file is an error, as in Ansible.
type Attrs struct {
	Path         string
	Owner, Group string
	Mode         os.FileMode
}

func (a *Attrs) Describe() string { return "attributes " + a.Path }

func (a *Attrs) Check(sys *System) (Change, error) {
	fi, err := os.Lstat(sys.Path(a.Path))
	if errors.Is(err, os.ErrNotExist) {
		return Change{}, fmt.Errorf("file (%s) is absent, cannot continue", a.Path)
	}
	if err != nil {
		return Change{}, err
	}
	notes, err := attrNotes(sys, fi, a.Owner, a.Group, a.Mode)
	if err != nil {
		return Change{}, err
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (a *Attrs) Apply(sys *System, _ Change) error {
	uid, gid, err := sys.ids(a.Owner, a.Group)
	if err != nil {
		return err
	}
	return setAttrs(sys.Path(a.Path), uid, gid, a.Mode)
}

// Tree is file state=directory recurse=true follow=false with an owner and
// group: the directory (created if missing) and everything below it, links
// themselves rather than what they point at.
type Tree struct {
	Path         string
	Owner, Group string

	create bool
	fix    []string
}

func (t *Tree) Describe() string { return "tree " + t.Path }

func (t *Tree) Check(sys *System) (Change, error) {
	t.create, t.fix = false, nil
	root := sys.Path(t.Path)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		t.create = true
		return Change{Needed: true, Summary: "create"}, nil
	} else if err != nil {
		return Change{}, err
	}
	uid, gid, err := sys.ids(t.Owner, t.Group)
	if err != nil {
		return Change{}, err
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		cu, cg := fileIDs(fi)
		if (uid >= 0 && cu != uid) || (gid >= 0 && cg != gid) {
			t.fix = append(t.fix, path)
		}
		return nil
	})
	if err != nil {
		return Change{}, err
	}
	if len(t.fix) == 0 {
		return Change{}, nil
	}
	return Change{Needed: true, Summary: fmt.Sprintf("owner of %d entries", len(t.fix))}, nil
}

func (t *Tree) Apply(sys *System, _ Change) error {
	uid, gid, err := sys.ids(t.Owner, t.Group)
	if err != nil {
		return err
	}
	if t.create {
		if err := os.MkdirAll(sys.Path(t.Path), 0o755); err != nil {
			return err
		}
		t.fix = []string{sys.Path(t.Path)}
	}
	for _, path := range t.fix {
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// LineInFile is lineinfile with regexp, line and insertafter: EOF on an
// existing file: the last line the expression finds becomes the line, or
// the line is added at the end; then the owner, group and mode.
type LineInFile struct {
	Path         string
	Regexp       *regexp.Regexp
	Line         string
	Owner, Group string
	Mode         os.FileMode
	// Same, when set, says an existing line already says what Line says in
	// other words (a YAML value quoted or not): it is then left as written.
	Same func(existing, want string) bool

	content []byte
	write   bool
}

func (l *LineInFile) Describe() string { return "line in " + l.Path }

func (l *LineInFile) Check(sys *System) (Change, error) {
	l.write = false
	if err := refuseSymlink(sys.Path(l.Path)); err != nil {
		return Change{}, err
	}
	raw, err := os.ReadFile(sys.Path(l.Path))
	if errors.Is(err, os.ErrNotExist) {
		return Change{}, fmt.Errorf("destination %s does not exist", l.Path)
	}
	if err != nil {
		return Change{}, err
	}
	lines := splitKeepEnds(raw)
	last := -1
	for i, line := range lines {
		if l.Regexp.Match(bytes.TrimRight(line, "\r\n")) {
			last = i
		}
	}
	want := []byte(l.Line + "\n")
	var notes []string
	switch {
	case last >= 0 && !bytes.Equal(lines[last], want) &&
		(l.Same == nil || !l.Same(string(bytes.TrimRight(lines[last], "\r\n")), l.Line)):
		lines[last] = want
		l.write = true
		notes = append(notes, "line replaced")
	case last < 0:
		if n := len(lines); n > 0 && !bytes.HasSuffix(lines[n-1], []byte("\n")) && !bytes.HasSuffix(lines[n-1], []byte("\r")) {
			lines = append(lines, []byte("\n"))
		}
		lines = append(lines, want)
		l.write = true
		notes = append(notes, "line added")
	}
	l.content = bytes.Join(lines, nil)
	fi, err := os.Lstat(sys.Path(l.Path))
	if err != nil {
		return Change{}, err
	}
	attrs, err := attrNotes(sys, fi, l.Owner, l.Group, l.Mode)
	if err != nil {
		return Change{}, err
	}
	notes = append(notes, attrs...)
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (l *LineInFile) Apply(sys *System, _ Change) error {
	uid, gid, err := sys.ids(l.Owner, l.Group)
	if err != nil {
		return err
	}
	if l.write {
		fi, err := os.Stat(sys.Path(l.Path))
		if err != nil {
			return err
		}
		// Like atomic_move, the new file keeps what it is not told to change.
		curUID, curGID := fileIDs(fi)
		if uid < 0 {
			uid = curUID
		}
		if gid < 0 {
			gid = curGID
		}
		mode := l.Mode
		if mode == 0 {
			mode = fi.Mode().Perm()
		}
		return writeAtomic(sys.Path(l.Path), l.content, uid, gid, mode)
	}
	return setAttrs(sys.Path(l.Path), uid, gid, l.Mode)
}

// splitKeepEnds is Python's splitlines(True) for \n endings.
func splitKeepEnds(raw []byte) [][]byte {
	var lines [][]byte
	for len(raw) > 0 {
		i := bytes.IndexByte(raw, '\n')
		if i < 0 {
			lines = append(lines, raw)
			break
		}
		lines = append(lines, raw[:i+1])
		raw = raw[i+1:]
	}
	return lines
}

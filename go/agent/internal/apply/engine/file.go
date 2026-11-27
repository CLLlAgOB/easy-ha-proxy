package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File is the template and copy modules: a regular file with this content,
// owner, group and mode.
type File struct {
	Path          string
	Content       []byte
	Owner, Group  string
	Mode          os.FileMode
	OnlyIfMissing bool // force: false -- write it if absent, never touch it after
	// Validate is the template module's validate: run on the new content in
	// a temporary file before it replaces the old one; an error keeps the old.
	Validate func(sys *System, tmpPath string) error

	writeContent, fixAttrs bool
}

func (f *File) Describe() string { return "file " + f.Path }

// RenderDir, when set, receives every file content a check compares (named
// after its path, mode 0600), so a plan's difference can be read on the host
// itself; "apply plan --render-to DIR" sets it.
var RenderDir string

func (f *File) Check(sys *System) (Change, error) {
	f.writeContent, f.fixAttrs = false, false
	if RenderDir != "" {
		name := strings.ReplaceAll(strings.TrimPrefix(f.Path, "/"), "/", "_")
		if err := os.WriteFile(filepath.Join(RenderDir, name), f.Content, 0o600); err != nil {
			return Change{}, err
		}
	}
	fi, err := os.Lstat(sys.Path(f.Path))
	if errors.Is(err, os.ErrNotExist) {
		f.writeContent = true
		return Change{Needed: true, Summary: fmt.Sprintf("create, %d bytes", len(f.Content))}, nil
	}
	if err != nil {
		return Change{}, err
	}
	if f.OnlyIfMissing {
		return Change{Summary: "exists, left as is (force: false)"}, nil
	}
	if !fi.Mode().IsRegular() {
		f.writeContent = true
		return Change{Needed: true, Summary: "replace a " + fi.Mode().Type().String() + " with a file"}, nil
	}
	var notes []string
	current, err := os.ReadFile(sys.Path(f.Path))
	if err != nil {
		return Change{}, err
	}
	if !bytes.Equal(current, f.Content) {
		f.writeContent = true
		notes = append(notes, fmt.Sprintf("content %d -> %d bytes", len(current), len(f.Content)))
	}
	attrs, err := attrNotes(sys, fi, f.Owner, f.Group, f.Mode)
	if err != nil {
		return Change{}, err
	}
	if len(attrs) > 0 {
		f.fixAttrs = true
		notes = append(notes, attrs...)
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (f *File) Apply(sys *System, _ Change) error {
	uid, gid, err := sys.ids(f.Owner, f.Group)
	if err != nil {
		return err
	}
	if f.writeContent {
		var check func(string) error
		if f.Validate != nil {
			check = func(tmp string) error { return f.Validate(sys, tmp) }
		}
		return writeAtomicChecked(sys.Path(f.Path), f.Content, uid, gid, f.Mode, check)
	}
	if f.fixAttrs {
		return setAttrs(sys.Path(f.Path), uid, gid, f.Mode)
	}
	return nil
}

// writeAtomic writes a temporary file beside the target, gives it its owner
// and mode before it is renamed into place (a reader that is not root must be
// able to read the new file at once), syncs it, and renames it.
func writeAtomic(path string, content []byte, uid, gid int, mode os.FileMode) error {
	return writeAtomicChecked(path, content, uid, gid, mode, nil)
}

// writeAtomicChecked is writeAtomic with a check of the temporary file
// before the rename.
func writeAtomicChecked(path string, content []byte, uid, gid int, mode os.FileMode, check func(string) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".ehp-")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return err
		}
	}
	if mode != 0 {
		if err := tmp.Chmod(mode); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if check != nil {
		if err := check(tmp.Name()); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	done = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// refuseSymlink errors if path is a symlink, so a primitive never reads,
// chmods or writes through a link planted in a container-writable directory
// (e.g. /opt/haproxy-admin/config/vars.yml -> /etc/easy-ha-proxy/daemons.env).
// A missing path is allowed: the create primitives handle it.
func refuseSymlink(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to follow it", path)
	}
	return nil
}

func setAttrs(path string, uid, gid int, mode os.FileMode) error {
	if err := refuseSymlink(path); err != nil {
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
	}
	if mode != 0 {
		return os.Chmod(path, mode)
	}
	return nil
}

// attrNotes lists the owner, group and mode differences; an empty owner or
// group, or a zero mode, means "leave it as it is", as in Ansible.
func attrNotes(sys *System, fi os.FileInfo, owner, group string, mode os.FileMode) ([]string, error) {
	uid, gid, err := sys.ids(owner, group)
	if err != nil {
		return nil, err
	}
	curUID, curGID := fileIDs(fi)
	var notes []string
	if uid >= 0 && uid != curUID {
		notes = append(notes, fmt.Sprintf("owner %d -> %d", curUID, uid))
	}
	if gid >= 0 && gid != curGID {
		notes = append(notes, fmt.Sprintf("group %d -> %d", curGID, gid))
	}
	if mode != 0 && fi.Mode().Perm()|fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != mode {
		notes = append(notes, fmt.Sprintf("mode %04o -> %04o", fi.Mode().Perm(), mode.Perm()))
	}
	return notes, nil
}

// Dir is file state=directory: the directory, its parents if missing, and
// its own owner, group and mode.
type Dir struct {
	Path         string
	Owner, Group string
	Mode         os.FileMode

	create bool
}

func (d *Dir) Describe() string { return "directory " + d.Path }

func (d *Dir) Check(sys *System) (Change, error) {
	d.create = false
	if err := refuseSymlink(sys.Path(d.Path)); err != nil {
		return Change{}, err
	}
	fi, err := os.Stat(sys.Path(d.Path))
	if errors.Is(err, os.ErrNotExist) {
		d.create = true
		return Change{Needed: true, Summary: "create"}, nil
	}
	if err != nil {
		return Change{}, err
	}
	if !fi.IsDir() {
		return Change{}, fmt.Errorf("%s exists and is not a directory", d.Path)
	}
	notes, err := attrNotes(sys, fi, d.Owner, d.Group, d.Mode)
	if err != nil {
		return Change{}, err
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (d *Dir) Apply(sys *System, _ Change) error {
	path := sys.Path(d.Path)
	if d.create {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	uid, gid, err := sys.ids(d.Owner, d.Group)
	if err != nil {
		return err
	}
	return setAttrs(path, uid, gid, d.Mode)
}

// Link is file state=link: a symbolic link to Target.
type Link struct{ Path, Target string }

func (l *Link) Describe() string { return "link " + l.Path }

func (l *Link) Check(sys *System) (Change, error) {
	current, err := os.Readlink(sys.Path(l.Path))
	if err == nil && current == l.Target {
		return Change{}, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		if fi, statErr := os.Lstat(sys.Path(l.Path)); statErr == nil && fi.Mode()&os.ModeSymlink == 0 {
			return Change{}, fmt.Errorf("%s exists and is not a link", l.Path)
		}
	}
	return Change{Needed: true, Summary: "link to " + l.Target}, nil
}

func (l *Link) Apply(sys *System, _ Change) error {
	path := sys.Path(l.Path)
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".ehp-link")
	os.Remove(tmp)
	if err := os.Symlink(l.Target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Absent is file state=absent.
type Absent struct{ Path string }

func (a *Absent) Describe() string { return "absent " + a.Path }

func (a *Absent) Check(sys *System) (Change, error) {
	if _, err := os.Lstat(sys.Path(a.Path)); errors.Is(err, os.ErrNotExist) {
		return Change{}, nil
	} else if err != nil {
		return Change{}, err
	}
	return Change{Needed: true, Summary: "remove"}, nil
}

func (a *Absent) Apply(sys *System, _ Change) error { return os.RemoveAll(sys.Path(a.Path)) }

// Touch is file state=touch: create if missing and set the times; Ansible
// reports it changed every time, and so does this. With Preserve
// (access_time and modification_time: preserve) an existing file keeps its
// times and changes only when its owner, group or mode do.
type Touch struct {
	Path         string
	Owner, Group string
	Mode         os.FileMode
	Preserve     bool
}

func (t *Touch) Describe() string { return "touch " + t.Path }

func (t *Touch) Check(sys *System) (Change, error) {
	if !t.Preserve {
		return Change{Needed: true, Summary: "touch"}, nil
	}
	fi, err := os.Lstat(sys.Path(t.Path))
	if errors.Is(err, os.ErrNotExist) {
		return Change{Needed: true, Summary: "create"}, nil
	}
	if err != nil {
		return Change{}, err
	}
	notes, err := attrNotes(sys, fi, t.Owner, t.Group, t.Mode)
	if err != nil {
		return Change{}, err
	}
	return Change{Needed: len(notes) > 0, Summary: strings.Join(notes, "; ")}, nil
}

func (t *Touch) Apply(sys *System, _ Change) error {
	path := sys.Path(t.Path)
	if err := refuseSymlink(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	uid, gid, err := sys.ids(t.Owner, t.Group)
	if err != nil {
		return err
	}
	return setAttrs(path, uid, gid, t.Mode)
}

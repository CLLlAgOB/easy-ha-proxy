package fullbackup

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const noFollow = syscall.O_NOFOLLOW

type usage struct{ free int64 }

// diskUsage is shutil.disk_usage's free: what an unprivileged user may use.
var diskUsage = func(p string) (usage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return usage{}, err
	}
	frsize := int64(st.Frsize)
	if frsize <= 0 {
		frsize = int64(st.Bsize)
	}
	return usage{free: int64(st.Bavail) * frsize}, nil
}

// deviceOf is the filesystem a path is on.
var deviceOf = func(p string) (uint64, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return uint64(fi.Sys().(*syscall.Stat_t).Dev), nil
}

// existingAncestor is the nearest existing path at or above p.
var existingAncestor = func(p string) (string, error) {
	candidate := p
	for {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", backupErrorf("Cannot find a filesystem for restore path: %s", p)
		}
		candidate = parent
	}
}

func executable(p string) bool {
	return unix.Access(p, unix.X_OK) == nil
}

// removePaths removes exact, already-authorized paths, deepest first,
// without following symbolic links, while keeping host control-plane subtrees
// listed in effectiveRestorePreservedPaths intact.
var removePaths = func(paths []string) error {
	preserved := effectiveRestorePreservedPaths()
	unique := map[string]bool{}
	for _, p := range paths {
		unique[p] = true
	}
	ordered := sortedKeys(unique)
	depth := func(p string) int {
		n := 0
		for _, c := range p {
			if c == '/' {
				n++
			}
		}
		return n
	}
	// Stable: deeper paths first, otherwise sorted (as Python's sorted set).
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && depth(ordered[j]) > depth(ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	for _, p := range ordered {
		if err := removeOnePreserving(p, preserved); err != nil {
			return err
		}
	}
	return nil
}

func removeOnePreserving(p string, preserved []string) error {
	clean := filepath.Clean(p)
	if pathIsPreserved(clean, preserved) {
		return nil
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return os.Remove(clean)
	}
	if !hasPreservedDescendant(clean, preserved) {
		return os.RemoveAll(clean)
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := removeOnePreserving(filepath.Join(clean, entry.Name()), preserved); err != nil {
			return err
		}
	}
	return nil
}

// copyTreeKeepingLinks is shutil.copytree(symlinks=True): modes and times
// kept, symbolic links copied as links.
func copyTreeKeepingLinks(source, destination string) error {
	if err := copyEntries(source, destination); err != nil {
		return err
	}
	return fixDirModes(source, destination)
}

func copyEntries(source, destination string) error {
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, p)
		target := filepath.Join(destination, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.IsDir():
			// Writable while it is filled; fixDirModes sets the real mode.
			return os.Mkdir(target, 0o700)
		default:
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			if err := os.Chmod(target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chtimes(target, info.ModTime(), info.ModTime())
		}
	})
}

// fixDirModes reapplies directory modes after their contents were written
// (a read-only directory is created writable first).
func fixDirModes(source, destination string) error {
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, p)
		target := filepath.Join(destination, rel)
		if err := os.Chmod(target, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
}

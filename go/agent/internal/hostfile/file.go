// Package hostfile contains filesystem operations used by the host daemons.
package hostfile

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenDirectory pins a directory and refuses symbolic links at every component.
// A nonzero createMode allows missing directories to be created.
func OpenDirectory(path string, createMode uint32) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	for name := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if name == "" {
			continue
		}
		next, err := unix.Openat(fd, name, flags, 0)
		if createMode != 0 && errors.Is(err, unix.ENOENT) {
			if err = unix.Mkdirat(fd, name, createMode); err == nil || errors.Is(err, unix.EEXIST) {
				next, err = unix.Openat(fd, name, flags, 0)
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			return nil, &os.PathError{Op: "open directory", Path: path, Err: err}
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ReadRegular reads only a regular file at path, with a hard limit even if
// its writer grows the file concurrently.
func ReadRegular(path string, maxBytes int64) ([]byte, error) {
	dir, err := OpenDirectory(filepath.Dir(path), 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes: %s", maxBytes, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes: %s", maxBytes, path)
	}
	return data, nil
}

// WriteAtomic publishes a complete file through a private, unique sibling.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir, err := OpenDirectory(filepath.Dir(path), 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	dirFD := int(dir.Fd())
	name := filepath.Base(path)
	tmp := "." + name + "-" + rand.Text()
	fd, err := unix.Openat(dirFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer unix.Unlinkat(dirFD, tmp, 0)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return unix.Renameat(dirFD, tmp, dirFD, name)
}

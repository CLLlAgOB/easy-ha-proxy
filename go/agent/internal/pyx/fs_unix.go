//go:build unix

package pyx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// StatInfo is the subset of os.stat_result the Python checks read.
type StatInfo struct {
	Mode    os.FileMode
	UID     int
	Nlink   uint64
	Dev     uint64
	Ino     uint64
	Size    int64
	MtimeNs int64
}

func toStat(fi os.FileInfo) StatInfo {
	st := StatInfo{Mode: fi.Mode(), Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), UID: -1}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.UID = int(sys.Uid)
		st.Nlink = uint64(sys.Nlink)
		st.Dev = uint64(sys.Dev) //nolint:unconvert
		st.Ino = sys.Ino
	}
	return st
}

// Lstat is os.lstat.
func Lstat(path string) (StatInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return StatInfo{}, err
	}
	return toStat(fi), nil
}

// Fstat is os.fstat.
func Fstat(f *os.File) (StatInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return StatInfo{}, err
	}
	return toStat(fi), nil
}

// NoFollow is os.O_NOFOLLOW.
const NoFollow = syscall.O_NOFOLLOW

// FlockTry takes an exclusive non-blocking flock.
func FlockTry(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }

// FlockRelease drops a flock.
func FlockRelease(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// SessionAttr starts a child in its own session (start_new_session=True).
func SessionAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

// KillGroup is os.killpg.
func KillGroup(pid int, sig syscall.Signal) { _ = syscall.Kill(-pid, sig) }

// GroupCommandContext bounds a command and the subprocesses it starts.
func GroupCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// FsyncDir fsyncs a directory.
func FsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

//go:build !unix

package pyx

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

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
	return StatInfo{Mode: fi.Mode(), Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), Nlink: 1}
}

func Lstat(path string) (StatInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return StatInfo{}, err
	}
	return toStat(fi), nil
}

func Fstat(f *os.File) (StatInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return StatInfo{}, err
	}
	return toStat(fi), nil
}

const NoFollow = 0

func FlockTry(_ *os.File) error         { return nil }
func FlockRelease(_ *os.File)           {}
func SessionAttr() *syscall.SysProcAttr { return nil }
func KillGroup(_ int, _ syscall.Signal) {}
func FsyncDir(_ string) error           { return nil }

func GroupCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

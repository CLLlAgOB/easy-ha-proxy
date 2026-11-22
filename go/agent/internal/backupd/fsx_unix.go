//go:build unix

package backupd

import (
	"os"
	"syscall"
)

// statInfo is the subset of os.stat_result the Python checks read.
type statInfo struct {
	Mode    os.FileMode
	UID     int
	Nlink   uint64
	Dev     uint64
	Ino     uint64
	Size    int64
	MtimeNs int64
}

func toStatInfo(fi os.FileInfo) statInfo {
	st := statInfo{Mode: fi.Mode(), Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), UID: -1}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.UID = int(sys.Uid)
		st.Nlink = uint64(sys.Nlink)
		st.Dev = uint64(sys.Dev) //nolint:unconvert
		st.Ino = sys.Ino
	}
	return st
}

func lstatInfo(path string) (statInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return statInfo{}, err
	}
	return toStatInfo(fi), nil
}

func fstatInfo(f *os.File) (statInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return statInfo{}, err
	}
	return toStatInfo(fi), nil
}

const oNoFollow = syscall.O_NOFOLLOW

func geteuid() int { return os.Geteuid() }

// setOwner is _set_owner: fatal only when running as root.
func setOwner(path string, uid, gid int) error {
	if err := os.Lchown(path, uid, gid); err != nil {
		if os.Geteuid() == 0 {
			return err
		}
	}
	return nil
}

func setOwnerFd(f *os.File, uid, gid int) error {
	if err := f.Chown(uid, gid); err != nil {
		if os.Geteuid() == 0 {
			return err
		}
	}
	return nil
}

func fsyncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type diskUsage struct {
	Total int64
	Free  int64
}

// statDisk is shutil.disk_usage: free counts the blocks an unprivileged user may use.
func statDisk(path string) (diskUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return diskUsage{}, err
	}
	frsize := int64(st.Bsize)
	if f := frsizeOf(&st); f > 0 {
		frsize = f
	}
	return diskUsage{Total: int64(st.Blocks) * frsize, Free: int64(st.Bavail) * frsize}, nil
}

func flockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func flockRelease(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func newSessionAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

func killGroup(pid int, sig syscall.Signal) { _ = syscall.Kill(-pid, sig) }

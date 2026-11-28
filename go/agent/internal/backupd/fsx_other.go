//go:build !unix

package backupd

import (
	"os"
	"syscall"
)

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
	return statInfo{Mode: fi.Mode(), Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), Nlink: 1}
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

const oNoFollow = 0

func geteuid() int                          { return 0 }
func setOwner(_ string, _, _ int) error     { return nil }
func setOwnerFd(_ *os.File, _, _ int) error { return nil }
func fsyncDirectory(_ string) error         { return nil }
func flockExclusive(_ *os.File) error       { return nil }
func flockRelease(_ *os.File)               {}
func newSessionAttr() *syscall.SysProcAttr  { return nil }
func killGroup(_ int, _ syscall.Signal)     {}

type diskUsage struct {
	Total int64
	Free  int64
}

func statDisk(_ string) (diskUsage, error) { return diskUsage{Total: 1 << 40, Free: 1 << 40}, nil }

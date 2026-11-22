//go:build unix

package backupd

import "syscall"

type diskUsage struct {
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	AvailBytes uint64 `json:"available_bytes"`
}

func statFilesystem(path string) (diskUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return diskUsage{}, err
	}
	bsize := uint64(st.Bsize)
	return diskUsage{
		TotalBytes: st.Blocks * bsize,
		FreeBytes:  st.Bfree * bsize,
		AvailBytes: st.Bavail * bsize,
	}, nil
}

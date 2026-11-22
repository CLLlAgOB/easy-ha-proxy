//go:build unix

package metricsd

import "syscall"

type fsStats struct {
	TotalBytes uint64
	AvailBytes uint64
}

func statFS(path string) (fsStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsStats{}, err
	}
	b := uint64(st.Bsize)
	return fsStats{
		TotalBytes: st.Blocks * b,
		AvailBytes: st.Bavail * b,
	}, nil
}

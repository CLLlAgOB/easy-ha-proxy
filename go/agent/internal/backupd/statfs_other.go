//go:build !unix

package backupd

type diskUsage struct {
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	AvailBytes uint64 `json:"available_bytes"`
}

func statFilesystem(_ string) (diskUsage, error) {
	return diskUsage{}, nil
}

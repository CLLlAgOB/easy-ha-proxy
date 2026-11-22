//go:build !unix

package metricsd

type fsStats struct {
	TotalBytes uint64
	AvailBytes uint64
}

func statFS(_ string) (fsStats, error) {
	return fsStats{TotalBytes: 100 << 30, AvailBytes: 50 << 30}, nil
}

package metricsd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CPUTotals captures raw jiffies from /proc/stat.
type CPUTotals struct {
	Idle  uint64
	Total uint64
}

// HostSample captures one point-in-time Linux host telemetry reading from /proc and /sys.
type HostSample struct {
	TS            int64   `json:"ts"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemTotalBytes uint64  `json:"mem_total_bytes"`
	MemUsedBytes  uint64  `json:"mem_used_bytes"`
	MemPercent    float64 `json:"mem_percent"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	NetRxBytes    uint64  `json:"net_rx_bytes"`
	NetTxBytes    uint64  `json:"net_tx_bytes"`
	TempCelsius   float64 `json:"temp_celsius,omitempty"`
}

// ParseProcStat extracts aggregate CPU jiffies from /proc/stat content.
func ParseProcStat(content string) (CPUTotals, bool) {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return CPUTotals{}, false
		}
		var total, idle uint64
		for i := 1; i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				continue
			}
			total += v
			// user(1), nice(2), system(3), idle(4), iowait(5)
			if i == 4 || i == 5 {
				idle += v
			}
		}
		return CPUTotals{Idle: idle, Total: total}, total > 0
	}
	return CPUTotals{}, false
}

// ParseProcMeminfo extracts MemTotal and MemAvailable (in bytes) from /proc/meminfo.
func ParseProcMeminfo(content string) (totalBytes uint64, usedBytes uint64, ok bool) {
	var totalKB, availKB, freeKB uint64
	var hasAvail bool
	for _, line := range strings.Split(content, "\n") {
		k, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "MemTotal":
			totalKB = v
		case "MemAvailable":
			availKB = v
			hasAvail = true
		case "MemFree":
			freeKB = v
		}
	}
	if totalKB == 0 {
		return 0, 0, false
	}
	avail := freeKB
	if hasAvail {
		avail = availKB
	}
	if avail > totalKB {
		avail = totalKB
	}
	return totalKB * 1024, (totalKB - avail) * 1024, true
}

// ParseProcLoadavg extracts 1m, 5m, 15m load averages from /proc/loadavg.
func ParseProcLoadavg(content string) (l1, l5, l15 float64, ok bool) {
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if l1, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return 0, 0, 0, false
	}
	if l5, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return 0, 0, 0, false
	}
	if l15, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return 0, 0, 0, false
	}
	return l1, l5, l15, true
}

// ParseProcNetDev sums non-loopback RX/TX byte counters from /proc/net/dev.
func ParseProcNetDev(content string) (rxBytes, txBytes uint64) {
	for _, line := range strings.Split(content, "\n") {
		iface, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name := strings.TrimSpace(iface)
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 10 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 == nil {
			rxBytes += rx
		}
		if err2 == nil {
			txBytes += tx
		}
	}
	return rxBytes, txBytes
}

// ReadHostSample reads live Linux metrics from /proc and /sys with zero subprocesses.
func ReadHostSample(ts int64, prevCPU *CPUTotals) (HostSample, *CPUTotals) {
	sample := HostSample{TS: ts}
	var nextCPU *CPUTotals

	if raw, err := os.ReadFile("/proc/stat"); err == nil {
		if cur, ok := ParseProcStat(string(raw)); ok {
			cp := cur
			nextCPU = &cp
			if prevCPU != nil && cur.Total > prevCPU.Total {
				dTotal := float64(cur.Total - prevCPU.Total)
				dIdle := float64(cur.Idle - prevCPU.Idle)
				if dTotal > 0 {
					pct := (1.0 - dIdle/dTotal) * 100.0
					if pct < 0 {
						pct = 0
					} else if pct > 100 {
						pct = 100
					}
					sample.CPUPercent = float64(int(pct*10+0.5)) / 10.0
				}
			}
		}
	}

	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		if total, used, ok := ParseProcMeminfo(string(raw)); ok {
			sample.MemTotalBytes = total
			sample.MemUsedBytes = used
			if total > 0 {
				pct := float64(used) * 100.0 / float64(total)
				sample.MemPercent = float64(int(pct*10+0.5)) / 10.0
			}
		}
	}

	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		if l1, l5, l15, ok := ParseProcLoadavg(string(raw)); ok {
			sample.Load1, sample.Load5, sample.Load15 = l1, l5, l15
		}
	}

	if raw, err := os.ReadFile("/proc/net/dev"); err == nil {
		sample.NetRxBytes, sample.NetTxBytes = ParseProcNetDev(string(raw))
	}

	if matches, err := filepath.Glob("/sys/class/thermal/thermal_zone*/temp"); err == nil {
		var maxMilli int64
		for _, path := range matches {
			if raw, err := os.ReadFile(path); err == nil {
				if v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && v > maxMilli && v < 150000 {
					maxMilli = v
				}
			}
		}
		if maxMilli > 0 {
			sample.TempCelsius = float64(maxMilli) / 1000.0
		}
	}

	return sample, nextCPU
}

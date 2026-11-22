package metricsd

import (
	"context"
	"fmt"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// EvaluateTrafficAlerts checks per-backend 1-minute totals against error-ratio and
// latency thresholds and reports http.error_ratio / response.slow observations to alertd.
func (c *Collector) EvaluateTrafficAlerts(ctx context.Context, minuteTS int64) {
	if c.Alerts == nil || !c.Alerts.Enabled() || c.Store == nil {
		return
	}
	minReqs := uint64(max(1, c.cfg.AlertMinRequests))
	buckets := c.Store.LatestBackendMinuteBuckets(minuteTS)
	for _, b := range buckets {
		if b.Requests < minReqs {
			continue
		}
		if c.cfg.AlertErrorRatioPercent > 0 {
			ratioPct := float64(b.Resp5xx) * 100.0 / float64(b.Requests)
			active := ratioPct >= float64(c.cfg.AlertErrorRatioPercent)
			summary := fmt.Sprintf("Backend %s 5xx ratio %.1f%% (%d/%d)", b.Proxy, ratioPct, b.Resp5xx, b.Requests)
			c.Alerts.Observe(ctx, alerts.Observation{
				Rule:    "http.error_ratio",
				Subject: b.Proxy,
				Active:  alerts.BoolPtr(active),
				Summary: summary,
			})
		}
		if c.cfg.AlertSlowResponseMS > 0 && b.RtimeCount > 0 {
			avgMS := float64(b.RtimeSum) / float64(b.RtimeCount)
			active := avgMS >= float64(c.cfg.AlertSlowResponseMS)
			summary := fmt.Sprintf("Backend %s mean response %.0f ms (threshold %d ms)", b.Proxy, avgMS, c.cfg.AlertSlowResponseMS)
			c.Alerts.Observe(ctx, alerts.Observation{
				Rule:    "response.slow",
				Subject: b.Proxy,
				Active:  alerts.BoolPtr(active),
				Summary: summary,
			})
		}
	}
}

// EvaluateStorageAlerts checks disk pressure and reports monitoring.storage / monitoring.paused.
func (c *Collector) EvaluateStorageAlerts(ctx context.Context, now int64) StorageStatus {
	st := c.Store.EvaluateStorage(now)
	if c.Alerts != nil && c.Alerts.Enabled() {
		c.Alerts.Observe(ctx, alerts.Observation{
			Rule:    "monitoring.storage",
			Subject: "metrics",
			Active:  alerts.BoolPtr(st.Pressure),
			Summary: fmt.Sprintf("Metrics storage pressure (free=%d MiB, db=%d KiB)", st.AvailableFreeBytes/(1024*1024), st.DatabaseBytes/1024),
		})
		c.Alerts.Observe(ctx, alerts.Observation{
			Rule:    "monitoring.paused",
			Subject: "metrics",
			Active:  alerts.BoolPtr(st.Paused),
			Summary: fmt.Sprintf("Metrics history writes paused (free=%d MiB < reserve=%d MiB)", st.AvailableFreeBytes/(1024*1024), st.ReservedFreeBytes/(1024*1024)),
		})
	}
	return st
}

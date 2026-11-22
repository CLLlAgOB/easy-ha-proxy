package controld

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// UDPForwardTarget describes one UDP forward with an optional backup backend.
type UDPForwardTarget struct {
	Name       string `json:"name"`
	Primary    string `json:"primary"`    // host:port
	Backup     string `json:"backup"`     // host:port
	ProbeProto string `json:"probe_proto"` // "tcp" or "udp"
}

// UDPForwardRuntime tracks failover state for one forward without flapping.
type UDPForwardRuntime struct {
	Name          string `json:"name"`
	Active        string `json:"active"` // "primary" or "backup"
	Target        string `json:"target"`
	FailStreak    int    `json:"fail_streak"`
	RecoverStreak int    `json:"recover_streak"`
	ChangedAt     int64  `json:"changed_at,omitempty"`
}

// UDPFailoverManager probes primary UDP backends and switches to backups after UDPFailAfter
// misses, recovering only after UDPRecoverAfter consecutive successes.
type UDPFailoverManager struct {
	mu        sync.Mutex
	statePath string
	states    map[string]*UDPForwardRuntime
	probeFn   func(ctx context.Context, proto, addr string) bool
	applyFn   func(ctx context.Context) error
	alerts    *alerts.Client
}

// NewUDPFailoverManager constructs a failover manager backed by statePath.
func NewUDPFailoverManager(statePath string, applyFn func(context.Context) error, alertClient *alerts.Client) *UDPFailoverManager {
	return &UDPFailoverManager{
		statePath: statePath,
		states:    make(map[string]*UDPForwardRuntime),
		probeFn:   defaultProbe,
		applyFn:   applyFn,
		alerts:    alertClient,
	}
}

func defaultProbe(ctx context.Context, proto, addr string) bool {
	if proto == "" {
		proto = "tcp"
	}
	var d net.Dialer
	d.Timeout = 2 * time.Second
	conn, err := d.DialContext(ctx, proto, addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Step evaluates one health probe round across targets, persisting state and calling applyFn on switch.
func (m *UDPFailoverManager) Step(ctx context.Context, targets []UDPForwardTarget, now int64) bool {
	if now <= 0 {
		now = time.Now().Unix()
	}
	switched := false

	m.mu.Lock()
	for _, t := range targets {
		if t.Backup == "" || t.Primary == "" {
			continue
		}
		st, ok := m.states[t.Name]
		if !ok {
			st = &UDPForwardRuntime{Name: t.Name, Active: "primary", Target: t.Primary}
			m.states[t.Name] = st
		}
		healthy := m.probeFn(ctx, t.ProbeProto, t.Primary)
		if st.Active == "primary" {
			if healthy {
				st.FailStreak = 0
			} else {
				st.FailStreak++
				if st.FailStreak >= UDPFailAfter {
					st.Active = "backup"
					st.Target = t.Backup
					st.RecoverStreak = 0
					st.ChangedAt = now
					switched = true
				}
			}
		} else {
			if healthy {
				st.RecoverStreak++
				if st.RecoverStreak >= UDPRecoverAfter {
					st.Active = "primary"
					st.Target = t.Primary
					st.FailStreak = 0
					st.ChangedAt = now
					switched = true
				}
			} else {
				st.RecoverStreak = 0
			}
		}
		if m.alerts != nil && m.alerts.Enabled() {
			onBackup := st.Active == "backup"
			summary := fmt.Sprintf("UDP forward %s returned to primary %s", t.Name, t.Primary)
			if onBackup {
				summary = fmt.Sprintf("UDP forward %s failed over to backup %s", t.Name, t.Backup)
			}
			m.alerts.Observe(ctx, alerts.Observation{
				Rule:    "udp.failover",
				Subject: t.Name,
				Active:  alerts.BoolPtr(onBackup),
				Summary: summary,
			})
		}
	}
	snapshot := m.publicStateLocked()
	m.mu.Unlock()

	if switched {
		if m.statePath != "" {
			_ = os.MkdirAll(filepath.Dir(m.statePath), 0o750)
			if raw, err := json.MarshalIndent(snapshot, "", "  "); err == nil {
				_ = writeFileAtomic(m.statePath, append(raw, '\n'), 0o644)
			}
		}
		if m.applyFn != nil {
			_ = m.applyFn(ctx)
		}
	}
	return switched
}

func (m *UDPFailoverManager) publicStateLocked() map[string]any {
	out := make(map[string]any, len(m.states))
	for k, v := range m.states {
		cp := *v
		out[k] = cp
	}
	return out
}

// PublicState returns a copy of all tracked UDP failover states.
func (m *UDPFailoverManager) PublicState() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publicStateLocked()
}

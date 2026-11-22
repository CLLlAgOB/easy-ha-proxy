package healthd

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CmdRunner executes a bounded host command (injectable for unit tests).
type CmdRunner interface {
	Run(ctx context.Context, argv ...string) (rc int, stdout string, stderr string)
}

// ExecRunner executes real system binaries without a shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv ...string) (int, string, string) {
	if len(argv) == 0 {
		return 1, "", "empty argv"
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return 124, outBuf.String(), "timeout"
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), outBuf.String(), errBuf.String()
		}
		return 127, outBuf.String(), err.Error()
	}
	return 0, outBuf.String(), errBuf.String()
}

// UnitStatus captures one systemd unit's health summary.
type UnitStatus struct {
	Name           string   `json:"name"`
	LoadState      string   `json:"load_state"`
	ActiveState    string   `json:"active_state"`
	SubState       string   `json:"sub_state"`
	UnitFileState  string   `json:"unit_file_state"`
	Description    string   `json:"description"`
	AllowedActions []string `json:"allowed_actions"`
}

// ContainerStatus captures one Docker container's health summary.
type ContainerStatus struct {
	Name           string   `json:"name"`
	State          string   `json:"state"`
	Health         string   `json:"health"`
	Image          string   `json:"image"`
	AllowedActions []string `json:"allowed_actions"`
}

// StateEvent records a state transition observed between snapshots.
type StateEvent struct {
	TS   int64  `json:"ts"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Snapshot represents one full point-in-time status report.
type Snapshot struct {
	TS         int64             `json:"ts"`
	Systemd    []UnitStatus      `json:"systemd"`
	Docker     []ContainerStatus `json:"docker"`
	EventsSize int               `json:"events_count"`
}

// Collector gathers cached systemd and Docker status and records state transitions.
type Collector struct {
	cfg      Config
	selfUnit string
	runner   CmdRunner

	mu             sync.Mutex
	cached         *Snapshot
	cachedAt       time.Time
	cachedUnits    []string
	unitsScannedAt time.Time
	prevStates     map[string]string
	events         []StateEvent
}

// NewCollector builds a Collector with the given config and command runner.
func NewCollector(cfg Config, selfUnit string, runner CmdRunner) *Collector {
	if selfUnit == "" {
		selfUnit = DefaultHealthUnit
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Collector{
		cfg:        cfg,
		selfUnit:   selfUnit,
		runner:     runner,
		prevStates: make(map[string]string),
	}
}

// Snapshot returns a cached or freshly collected Snapshot.
func (c *Collector) Snapshot(ctx context.Context, force bool) Snapshot {
	c.mu.Lock()
	if !force && c.cached != nil && c.cfg.CacheTTLSeconds > 0 &&
		time.Since(c.cachedAt) < time.Duration(c.cfg.CacheTTLSeconds)*time.Second {
		snap := *c.cached
		c.mu.Unlock()
		return snap
	}
	c.mu.Unlock()

	units := c.resolveUnits(ctx)
	sysList := c.inspectSystemd(ctx, units)
	docList := c.inspectDocker(ctx)
	now := time.Now().Unix()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range sysList {
		c.noteTransition(now, "systemd", u.Name, u.ActiveState)
	}
	for _, d := range docList {
		c.noteTransition(now, "docker", d.Name, d.State)
	}
	snap := Snapshot{
		TS:         now,
		Systemd:    sysList,
		Docker:     docList,
		EventsSize: len(c.events),
	}
	c.cached = &snap
	c.cachedAt = time.Now()
	return snap
}

// Events returns recent state-transition events (newest last).
func (c *Collector) Events() []StateEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]StateEvent, len(c.events))
	copy(out, c.events)
	return out
}

// IsAllowedTarget checks whether (kind, name) is within the configured allowlist.
func (c *Collector) IsAllowedTarget(ctx context.Context, kind, name string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "docker":
		for _, item := range c.cfg.DockerContainers {
			if item == name {
				return true
			}
		}
		return false
	case "systemd":
		for _, u := range c.resolveUnits(ctx) {
			if u == name {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (c *Collector) noteTransition(ts int64, kind, name, state string) {
	key := kind + ":" + name
	if prev, ok := c.prevStates[key]; ok && prev != state {
		c.events = append(c.events, StateEvent{
			TS:   ts,
			Kind: kind,
			Name: name,
			From: prev,
			To:   state,
		})
		if len(c.events) > c.cfg.EventsMax {
			c.events = c.events[len(c.events)-c.cfg.EventsMax:]
		}
	}
	c.prevStates[key] = state
}

func (c *Collector) resolveUnits(ctx context.Context) []string {
	c.mu.Lock()
	if len(c.cachedUnits) > 0 && time.Since(c.unitsScannedAt) < time.Duration(c.cfg.UnitsRescanSeconds)*time.Second {
		out := append([]string(nil), c.cachedUnits...)
		c.mu.Unlock()
		return out
	}
	c.mu.Unlock()

	seen := make(map[string]struct{}, len(c.cfg.SystemdUnits))
	var result []string
	for _, u := range c.cfg.SystemdUnits {
		seen[u] = struct{}{}
		result = append(result, u)
	}
	if len(c.cfg.SystemdUnitGlobs) > 0 {
		cmdCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		rc, out, _ := c.runner.Run(cmdCtx, "systemctl", "list-unit-files", "--no-legend", "--no-pager")
		cancel()
		if rc == 0 {
			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				name := fields[0]
				if _, ok := seen[name]; ok {
					continue
				}
				for _, pat := range c.cfg.SystemdUnitGlobs {
					if matched, _ := filepath.Match(pat, name); matched {
						seen[name] = struct{}{}
						result = append(result, name)
						break
					}
				}
			}
		}
	}
	sort.Strings(result)
	c.mu.Lock()
	c.cachedUnits = result
	c.unitsScannedAt = time.Now()
	c.mu.Unlock()
	return result
}

func (c *Collector) inspectSystemd(ctx context.Context, units []string) []UnitStatus {
	out := make([]UnitStatus, 0, len(units))
	if len(units) == 0 {
		return out
	}
	argv := []string{
		"systemctl", "show", "--no-pager",
		"--property=Id,LoadState,ActiveState,SubState,UnitFileState,Description",
	}
	argv = append(argv, units...)
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	rc, stdout, _ := c.runner.Run(cmdCtx, argv...)
	cancel()
	if rc != 0 && strings.TrimSpace(stdout) == "" {
		for _, u := range units {
			out = append(out, UnitStatus{
				Name:           u,
				ActiveState:    "unknown",
				AllowedActions: AllowedActions("systemd", u, c.selfUnit),
			})
		}
		return out
	}

	blocks := strings.Split(strings.TrimSpace(stdout), "\n\n")
	byName := make(map[string]UnitStatus, len(blocks))
	for _, block := range blocks {
		props := make(map[string]string)
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				props[k] = v
			}
		}
		id := strings.TrimSpace(props["Id"])
		if id == "" {
			continue
		}
		byName[id] = UnitStatus{
			Name:           id,
			LoadState:      props["LoadState"],
			ActiveState:    props["ActiveState"],
			SubState:       props["SubState"],
			UnitFileState:  props["UnitFileState"],
			Description:    props["Description"],
			AllowedActions: AllowedActions("systemd", id, c.selfUnit),
		}
	}
	for _, u := range units {
		if st, ok := byName[u]; ok {
			out = append(out, st)
		} else {
			out = append(out, UnitStatus{
				Name:           u,
				ActiveState:    "not-found",
				AllowedActions: AllowedActions("systemd", u, c.selfUnit),
			})
		}
	}
	return out
}

func (c *Collector) inspectDocker(ctx context.Context) []ContainerStatus {
	out := make([]ContainerStatus, 0, len(c.cfg.DockerContainers))
	for _, name := range c.cfg.DockerContainers {
		cmdCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		rc, stdout, _ := c.runner.Run(
			cmdCtx,
			"docker", "inspect",
			"--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Config.Image}}",
			name,
		)
		cancel()
		if rc != 0 {
			out = append(out, ContainerStatus{
				Name:           name,
				State:          "missing",
				AllowedActions: AllowedActions("docker", name, c.selfUnit),
			})
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(stdout), "|", 3)
		st := ContainerStatus{
			Name:           name,
			State:          "unknown",
			AllowedActions: AllowedActions("docker", name, c.selfUnit),
		}
		if len(parts) > 0 && parts[0] != "" {
			st.State = parts[0]
		}
		if len(parts) > 1 {
			st.Health = parts[1]
		}
		if len(parts) > 2 {
			st.Image = parts[2]
		}
		out = append(out, st)
	}
	return out
}

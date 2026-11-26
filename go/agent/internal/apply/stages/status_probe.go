package stages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// statusProbe is the status check's one pass over the host: each unit's
// is-active, the checksums of the daemons' version files and of the managed
// artifacts, the installed and candidate APT versions, the containers and the
// snaps. Every part has the shape of a loop's registered result
// ({"results": [{"item": ..., ...}]}), so the summaries that follow read the
// same fields they always read.
type statusProbe struct {
	spec   string // the probe's input, as JSON
	Output string // the report, as JSON
}

// probeSpec is what the status check asks the probe for.
type probeSpec struct {
	Units       []map[string]any `json:"units"`
	Retries     int              `json:"retries"`
	Delay       float64          `json:"delay"`
	DaemonFiles []map[string]any `json:"daemon_files"`
	Artifacts   []map[string]any `json:"artifacts"`
	Apt         []string         `json:"apt"`
	Docker      []map[string]any `json:"docker"`
	Snaps       []string         `json:"snaps"`
}

func (p *statusProbe) Describe() string { return "status probe" }

func (p *statusProbe) Check(sys *engine.System) (engine.Change, error) {
	var spec probeSpec
	if err := json.Unmarshal([]byte(p.spec), &spec); err != nil {
		return engine.Change{}, fmt.Errorf("status probe input: %w", err)
	}
	raw, err := json.Marshal(runStatusProbe(sys, spec))
	if err != nil {
		return engine.Change{}, err
	}
	p.Output = string(raw)
	return engine.Change{Summary: "read"}, nil
}

func (p *statusProbe) Apply(*engine.System, engine.Change) error { return nil }

// probeRun is a command's result as the command module reports it: the
// output without its trailing newline. The engine's Exec gives no standard
// error, so that field stays empty (the summaries default it).
func probeRun(sys *engine.System, argv ...string) map[string]any {
	out, code, err := sys.Exec(argv[0], argv[1:]...)
	if err != nil {
		return map[string]any{"rc": 2, "stdout": "", "stderr": err.Error()}
	}
	return map[string]any{"rc": code, "stdout": strings.TrimRight(out, "\r\n"), "stderr": ""}
}

func withItem(result map[string]any, item any) map[string]any {
	result["item"] = item
	return result
}

// probeUnits asks systemctl is-active, again for a unit until it answers
// "active": reconciliation and snapd may restart units moments before the
// check, and a unit in the middle of a reload answers "reloading" with exit
// code 0. Only a state that survives a few probes counts; the waits are
// shared, every unit still not active is asked again after the same delay.
func probeUnits(sys *engine.System, items []map[string]any, retries int, delay float64) map[string]any {
	ask := func(item map[string]any) map[string]any {
		return probeRun(sys, "systemctl", "is-active", fmt.Sprint(item["name"]))
	}
	active := func(state map[string]any) bool {
		return state["rc"] == 0 && strings.TrimSpace(fmt.Sprint(state["stdout"])) == "active"
	}
	states := make([]map[string]any, len(items))
	for i, item := range items {
		states[i] = ask(item)
	}
	for try := 0; try < retries; try++ {
		var pending []int
		for i, state := range states {
			if !active(state) {
				pending = append(pending, i)
			}
		}
		if len(pending) == 0 {
			break
		}
		if delay > 0 {
			time.Sleep(time.Duration(delay * float64(time.Second)))
		}
		for _, i := range pending {
			states[i] = ask(items[i])
		}
	}
	results := make([]any, len(items))
	for i, state := range states {
		results[i] = withItem(state, items[i])
	}
	return map[string]any{"results": results}
}

// probeStat is the part of the stat module's result the summaries read.
func probeStat(sys *engine.System, path string) map[string]any {
	fi, err := os.Stat(sys.Path(path))
	if err != nil {
		return map[string]any{"exists": false}
	}
	if !fi.Mode().IsRegular() {
		return map[string]any{"exists": true}
	}
	f, err := os.Open(sys.Path(path))
	if err != nil {
		return map[string]any{"exists": true}
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return map[string]any{"exists": true}
	}
	return map[string]any{"exists": true, "checksum": hex.EncodeToString(sum.Sum(nil))}
}

func probeStats(sys *engine.System, items []map[string]any, key string) map[string]any {
	results := make([]any, len(items))
	for i, item := range items {
		results[i] = map[string]any{"item": item, "stat": probeStat(sys, fmt.Sprint(item[key]))}
	}
	return map[string]any{"results": results}
}

var aptPolicyHeader = regexp.MustCompile(`^(\S+):$`)

// probeAptPolicy runs apt-cache policy once for every package and splits the
// answer per package.
func probeAptPolicy(sys *engine.System, packages []string) map[string]any {
	sections := map[string][]string{}
	if len(packages) > 0 {
		current := ""
		out := probeRun(sys, append([]string{"apt-cache", "policy"}, packages...)...)["stdout"].(string)
		for _, line := range strings.Split(out, "\n") {
			if m := aptPolicyHeader.FindStringSubmatch(line); m != nil {
				current = m[1]
				sections[current] = []string{line}
			} else if current != "" {
				sections[current] = append(sections[current], line)
			}
		}
	}
	results := make([]any, len(packages))
	for i, name := range packages {
		results[i] = map[string]any{"item": name, "stdout": strings.Join(sections[name], "\n")}
	}
	return map[string]any{"results": results}
}

func probeContainers(sys *engine.System, items []map[string]any) map[string]any {
	found := map[string]any{}
	if len(items) > 0 {
		argv := []string{"docker", "inspect", "--type", "container"}
		for _, item := range items {
			argv = append(argv, fmt.Sprint(item["name"]))
		}
		var containers []map[string]any
		if json.Unmarshal([]byte(probeRun(sys, argv...)["stdout"].(string)), &containers) == nil {
			for _, c := range containers {
				found[strings.TrimPrefix(fmt.Sprint(c["Name"]), "/")] = c
			}
		}
	}
	results := make([]any, len(items))
	for i, item := range items {
		c, ok := found[fmt.Sprint(item["name"])]
		if !ok {
			c = map[string]any{}
		}
		results[i] = map[string]any{"item": item, "exists": ok, "container": c}
	}
	return map[string]any{"results": results}
}

func probeSnaps(sys *engine.System, names []string) map[string]any {
	results := make([]any, len(names))
	for i, name := range names {
		state := probeRun(sys, "snap", "list", name)
		lines := []string{}
		if out := state["stdout"].(string); out != "" {
			lines = strings.Split(out, "\n")
		}
		state["stdout_lines"] = lines
		results[i] = withItem(state, name)
	}
	return map[string]any{"results": results}
}

func runStatusProbe(sys *engine.System, spec probeSpec) map[string]any {
	installed := make([]any, len(spec.Apt))
	for i, name := range spec.Apt {
		installed[i] = withItem(probeRun(sys, "dpkg-query", "--show", "--showformat=${Version}", name), name)
	}
	return map[string]any{
		"systemd":         probeUnits(sys, spec.Units, spec.Retries, spec.Delay),
		"daemon_versions": probeStats(sys, spec.DaemonFiles, "version_file"),
		"artifacts":       probeStats(sys, spec.Artifacts, "path"),
		"apt_installed":   map[string]any{"results": installed},
		"apt_candidate":   probeAptPolicy(sys, spec.Apt),
		"docker":          probeContainers(sys, spec.Docker),
		"snaps":           probeSnaps(sys, spec.Snaps),
	}
}

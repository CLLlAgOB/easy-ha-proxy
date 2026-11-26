package stages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The status check's one-pass probe, against stand-ins for systemctl,
// dpkg-query, apt-cache, docker and snap.
func TestTheStatusProbeAnswersInTheShapeTheSummariesRead(t *testing.T) {
	version := filepath.Join(t.TempDir(), "version")
	os.WriteFile(version, []byte("v1\n"), 0o644)
	asked := map[string]int{}
	var calls []string
	sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch name {
		case "systemctl":
			unit := args[1]
			asked[unit]++
			switch unit {
			case "ok":
				return "active\n", 0, nil
			case "flaky": // turns active on its second probe, as a unit restarted moments before
				if asked[unit] > 1 {
					return "active\n", 0, nil
				}
				return "activating\n", 3, nil
			case "reloading": // exit code 0 while HAProxy reloads
				if asked[unit] > 1 {
					return "active\n", 0, nil
				}
				return "reloading\n", 0, nil
			}
			return "inactive\n", 3, nil
		case "dpkg-query":
			if args[len(args)-1] == "haproxy" {
				return "3.2.1-1", 0, nil
			}
			return "", 1, nil
		case "apt-cache":
			return "haproxy:\n  Installed: 3.2.1-1\n  Candidate: 3.2.2-1\nipset:\n  Installed: (none)\n  Candidate: 7.15-1\n", 0, nil
		case "docker":
			return `[{"Name": "/authelia", "State": {"Status": "running", "Health": {"Status": "healthy"}}}]`, 1, nil
		case "snap":
			if args[1] == "certbot" {
				return "Name Version\ncertbot 5.1.0\n", 0, nil
			}
			return "", 1, nil
		}
		t.Fatalf("unexpected %s %v", name, args)
		return "", 0, nil
	}}
	spec, _ := json.Marshal(map[string]any{
		"units":   []any{map[string]any{"name": "ok", "label": "OK"}, map[string]any{"name": "flaky"}, map[string]any{"name": "gone"}, map[string]any{"name": "reloading"}},
		"retries": 2, "delay": 0,
		"daemon_files": []any{map[string]any{"name": "ok", "version_file": version}},
		"artifacts":    []any{map[string]any{"name": "missing", "path": "/nonexistent/file"}},
		"apt":          []any{"haproxy", "ipset"},
		"docker":       []any{map[string]any{"name": "authelia"}, map[string]any{"name": "redis"}},
		"snaps":        []any{"certbot", "lego"},
	})
	probe := &statusProbe{spec: string(spec)}
	if _, err := probe.Check(sys); err != nil {
		t.Fatal(err)
	}
	var report map[string]map[string][]map[string]any
	if err := json.Unmarshal([]byte(probe.Output), &report); err != nil {
		t.Fatal(err)
	}

	units := map[string]string{}
	for _, r := range report["systemd"]["results"] {
		item := r["item"].(map[string]any)
		units[item["name"].(string)] = strings.TrimSpace(r["stdout"].(string))
		if item["name"] == "ok" && item["label"] != "OK" {
			t.Errorf("the item lost its fields: %v", item)
		}
	}
	if units["ok"] != "active" || units["flaky"] != "active" || units["reloading"] != "active" || units["gone"] != "inactive" {
		t.Errorf("units %v", units)
	}
	// Only units not yet active are asked again, at most `retries` times.
	if asked["ok"] != 1 || asked["flaky"] != 2 || asked["reloading"] != 2 || asked["gone"] != 3 {
		t.Errorf("asked %v", asked)
	}

	sum := sha256.Sum256([]byte("v1\n"))
	if got := report["daemon_versions"]["results"][0]["stat"].(map[string]any)["checksum"]; got != hex.EncodeToString(sum[:]) {
		t.Errorf("checksum %v", got)
	}
	if got := report["artifacts"]["results"][0]["stat"].(map[string]any); got["exists"] != false {
		t.Errorf("missing artifact %v", got)
	}

	installed := report["apt_installed"]["results"]
	if installed[0]["item"] != "haproxy" || installed[0]["rc"] != 0.0 || installed[0]["stdout"] != "3.2.1-1" || installed[1]["rc"] != 1.0 {
		t.Errorf("installed %v", installed)
	}
	policy := map[string]string{}
	for _, r := range report["apt_candidate"]["results"] {
		policy[r["item"].(string)] = r["stdout"].(string)
	}
	if !strings.Contains(policy["haproxy"], "Candidate: 3.2.2-1") || strings.Contains(policy["haproxy"], "7.15-1") ||
		!strings.Contains(policy["ipset"], "Candidate: 7.15-1") {
		t.Errorf("policy %v", policy)
	}
	if strings.Count(strings.Join(calls, "\n"), "apt-cache policy") != 1 {
		t.Error("apt-cache asked more than once")
	}

	containers := map[string]map[string]any{}
	for _, r := range report["docker"]["results"] {
		containers[r["item"].(map[string]any)["name"].(string)] = r
	}
	health := containers["authelia"]["container"].(map[string]any)["State"].(map[string]any)["Health"].(map[string]any)["Status"]
	if containers["authelia"]["exists"] != true || health != "healthy" || containers["redis"]["exists"] != false {
		t.Errorf("containers %v", containers)
	}

	snaps := map[string]map[string]any{}
	for _, r := range report["snaps"]["results"] {
		snaps[r["item"].(string)] = r
	}
	lines := snaps["certbot"]["stdout_lines"].([]any)
	if snaps["certbot"]["rc"] != 0.0 || lines[len(lines)-1] != "certbot 5.1.0" || snaps["lego"]["rc"] == 0.0 {
		t.Errorf("snaps %v", snaps)
	}
}

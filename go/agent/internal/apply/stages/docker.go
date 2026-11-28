package stages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The Docker stage: roles/docker/tasks/docker.yml (the role's main.yml hands
// it to the agent or includes it), live_restore.yml it imports, and
// mirror.yml it includes when Docker Hub cannot be reached.
func init() {
	register(Stage{Name: "docker", Parts: []Part{
		{Name: "docker/docker", Role: "docker", File: "docker", Build: dockerInstall},
	}})
}

// dockerRepo is the copy task's content:, word for word.
const dockerRepo = "deb [arch={{ docker_arch }} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/{{ ansible_distribution | lower }} {{ ansible_distribution_release }} stable\n"

var restoreNet = []string{"restore-network"}

func dockerInstall(b *Builder) []engine.Step {
	debian := b.S("{{ ansible_os_family }}") == "Debian"
	onDebian := func(*engine.Run) bool { return debian }
	keyring := "/etc/apt/keyrings/docker.gpg"
	hadKeyring := false
	noKeyring := func(*engine.Run) bool { return debian && !hadKeyring }
	valid := b.aptValid()
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[b.S("{{ ansible_architecture }}")]
	if arch == "" {
		arch = b.S("{{ ansible_architecture }}")
	}
	pull := &engine.Command{Argv: []string{"timeout", "20", "docker", "pull", "hello-world:latest"}, IgnoreErrors: true}
	pulled := false
	steps := []engine.Step{
		{Name: "Ensure required packages for Docker are installed", When: onDebian, Tags: restoreNet,
			Resource: &engine.AptInstall{Names: []string{"ca-certificates", "curl", "gnupg", "lsb-release"}, UpdateCache: true, CacheValid: valid}},
		{Name: "Ensure keyrings dir exists", When: onDebian, Resource: b.Dir("/etc/apt/keyrings", "", "", "0755")},
		{Name: "Download Docker GPG key (ASCII)", Tags: restoreNet,
			When: func(r *engine.Run) bool { hadKeyring = b.Exists(keyring, false); return noKeyring(r) },
			Resource: &engine.GetURL{URL: "https://download.docker.com/linux/" + strings.ToLower(b.S("{{ ansible_distribution }}")) + "/gpg",
				Dest: keyring + ".asc", Mode: 0o644}},
		{Name: "Convert Docker GPG key to keyring (dearmor)", When: func(r *engine.Run) bool { return noKeyring(r) && !b.Exists(keyring, false) },
			Resource: &engine.Command{Argv: []string{"gpg", "--dearmor", "-o", keyring, keyring + ".asc"}, Changes: true}},
		{Name: "Ensure permissions on Docker GPG key", When: onDebian, Resource: &engine.Attrs{Path: keyring, Mode: 0o644}},
		fact("Map ansible_architecture to Docker arch", onDebian, func() error {
			b.Set.SetFact("docker_arch", arch)
			return nil
		}),
		{Name: "Add Docker APT repository", When: onDebian, Register: "docker_repo_added",
			Build: b.CopyContent(dockerRepo, "/etc/apt/sources.list.d/docker.list", "", "", "0644")},
		{Name: "Refresh APT cache after adding the Docker repository", When: andWhen(onDebian, Changed("docker_repo_added")), Tags: restoreNet,
			Resource: &engine.AptCache{ValidTime: 0}},
		{Name: "Install Docker Engine and plugins", When: onDebian, Tags: restoreNet,
			Resource: &engine.AptInstall{Names: []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"},
				UpdateCache: true, CacheValid: valid}},
		{Name: "Ensure Docker service is enabled and running", When: onDebian, Resource: Unit("docker", engine.Bool(true), "started")},
	}
	steps = append(steps, dockerLiveRestore(b)...)
	steps = append(steps, engine.Step{Name: "Test connectivity to Docker Hub with hello-world image", Tags: restoreNet,
		Resource: &engine.Func{Desc: "docker pull hello-world",
			CheckFn: func(*engine.System) (engine.Change, error) {
				return engine.Change{Summary: "runs on apply", Run: true}, nil
			},
			ApplyFn: func(sys *engine.System) error {
				pulled = pull.Apply(sys, engine.Change{}) == nil && pull.Code == 0
				return nil
			}}})
	mirror := dockerMirror(b)
	for i := range mirror {
		mirror[i].When = andWhen(func(r *engine.Run) bool { return r.Mode == engine.Apply && !pulled }, mirror[i].When)
	}
	return append(steps, withTags(mirror, "restore-network")...)
}

// dockerMirrors is mirror.yml's docker_registry_mirrors.
var dockerMirrors = []any{"https://mirror.gcr.io/", "https://dockerhub.timeweb.cloud"}

func dockerMirror(b *Builder) []engine.Step {
	var config map[string]any
	written := false
	retry := &engine.Command{Argv: []string{"timeout", "20", "docker", "pull", "hello-world:latest"}, IgnoreErrors: true}
	return []engine.Step{
		{Name: "Show info that Docker Hub is not reachable", Resource: report("Docker Hub is NOT reachable (hello-world pull failed), configuring registry mirrors.")},
		fact("Read existing /etc/docker/daemon.json", nil, func() error {
			config = map[string]any{}
			raw, err := os.ReadFile(b.Sys.Path("/etc/docker/daemon.json"))
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return decodeJSON(raw, &config)
		}),
		fact("Parse existing daemon.json or init empty", nil, func() error { return nil }),
		fact("Set desired registry mirrors fact", nil, func() error { return nil }),
		fact("Merge / set registry mirrors in daemon.json", nil, func() error {
			config["registry-mirrors"] = dockerMirrors
			return nil
		}),
		{Name: "Write updated /etc/docker/daemon.json with registry mirrors", Register: "docker_daemon_json_written",
			Build: func(*engine.Run) (engine.Resource, error) {
				return &engine.File{Path: "/etc/docker/daemon.json", Content: []byte(pyNiceJSON(config, 0)), Mode: 0o644}, nil
			}},
		// The play flushes the handler here: Docker restarts at once.
		{Name: "Apply Docker registry mirror configuration immediately", When: Changed("docker_daemon_json_written"),
			Resource: &engine.Command{Argv: []string{"systemctl", "restart", "docker"}, Changes: true}},
		{Name: "Wait for Docker restart to complete", When: func(r *engine.Run) bool { written = r.Changed("docker_daemon_json_written"); return written },
			Resource: &engine.Func{Desc: "pause 3 s", CheckFn: func(*engine.System) (engine.Change, error) {
				time.Sleep(3 * time.Second)
				return engine.Change{}, nil
			}}},
		{Name: "Re-test connectivity to Docker Hub after enabling mirrors", Resource: retry},
		{Name: "Show final result after retry", Build: func(*engine.Run) (engine.Resource, error) {
			if retry.Code == 0 {
				return report("After configuring mirrors: SUCCESS — Docker can pull images."), nil
			}
			return report("After configuring mirrors: FAILED — Docker STILL cannot reach any registry, even via mirrors."), nil
		}},
	}
}

// report is a debug task: its message in the journal, nothing changed.
func report(msg string) engine.Resource {
	return &engine.Func{Desc: "debug", CheckFn: func(*engine.System) (engine.Change, error) { return engine.Change{Summary: msg}, nil }}
}

var (
	activeState  = regexp.MustCompile(`(?m)^ActiveState=\S+$`)
	activeNow    = regexp.MustCompile(`(?m)^ActiveState=active$`)
	liveRestoreC = regexp.MustCompile(`--live-restore(?:=|\s|;|$)`)
	configFileC  = regexp.MustCompile(`--config-file(?:=|\s+)([^\s;]+)`)
)

// dockerLiveRestore transcribes live_restore.yml: live-restore in the
// standard daemon.json (other settings kept), checked by dockerd, reloaded
// and verified; a failure puts the previous file back.
func dockerLiveRestore(b *Builder) []engine.Step {
	enabled := b.Bool("{{ docker_live_restore_enabled | bool }}")
	installed := func(*engine.Run) bool { return b.Exists("/usr/bin/dockerd", false) }
	unit := &engine.Command{Argv: []string{"systemctl", "show", "docker.service", "--property=ExecStart,ActiveState"}, Probe: true}
	info := &engine.Command{Argv: []string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "info", "--format", "{{json .}}"}, Probe: true}
	var running, cli bool
	runtime := map[string]any{}
	path := "/etc/docker/daemon.json"
	var existed bool
	var original []byte
	var origInfo os.FileInfo
	config := map[string]any{}
	liveEnabled := func() bool { v, _ := runtime["LiveRestoreEnabled"].(bool); return v }
	inCLI := func(r *engine.Run) bool { return installed(r) && cli }
	inFile := func(r *engine.Run) bool { return installed(r) && !cli }
	apply := func(r *engine.Run) bool { return inFile(r) && running && r.Mode == engine.Apply }
	// rescue is the block's rescue: the previous file back (or none), Docker
	// reloaded onto it if the new one was applied, and the failure reported.
	rescue := func(sys *engine.System, r *engine.Run, cause error) error {
		if existed {
			if err := os.WriteFile(sys.Path(path), original, origInfo.Mode().Perm()); err == nil {
				uid, gid := fileOwner(origInfo)
				os.Chown(sys.Path(path), uid, gid)
			}
		} else {
			os.Remove(sys.Path(path))
		}
		if running && r.Mode == engine.Apply && r.Changed("docker_live_restore_written") {
			sys.Exec("systemctl", "reload", "docker.service")
		}
		return fmt.Errorf("Docker live-restore could not be applied. The previous configuration was restored. No Docker restart was attempted. (%v)", cause)
	}
	steps := []engine.Step{
		{Name: "Read Docker service configuration and state", When: installed, Resource: unit},
		assertStep("Require an explicit Docker service state", func(r *engine.Run) bool { return !installed(r) || activeState.MatchString(unit.Output) },
			"Docker service state could not be determined; its configuration was not changed."),
		fact("Remember whether Docker is running and configured on the command line", installed, func() error {
			running, cli = activeNow.MatchString(unit.Output), liveRestoreC.MatchString(unit.Output)
			return nil
		}),
		assertStep("Require the managed Docker configuration file", func(r *engine.Run) bool {
			for _, m := range configFileC.FindAllStringSubmatch(unit.Output, -1) {
				if installed(r) && m[1] != path {
					return false
				}
			}
			return true
		}, "Docker uses a custom configuration-file argument. Configure live-restore there before upgrading packages; the standard file was not changed."),
		{Name: "Read the running Docker configuration", When: func(r *engine.Run) bool { return installed(r) && running }, Resource: info},
		fact("Remember the current Docker live-restore setting", installed, func() error {
			runtime = map[string]any{}
			if running {
				return decodeJSON([]byte(info.Output), &runtime)
			}
			return nil
		}),
		assertStep("Require standalone Docker when enabling live restore", func(r *engine.Run) bool {
			if !installed(r) || !enabled {
				return true
			}
			swarm, _ := runtime["Swarm"].(map[string]any)
			state, _ := swarm["LocalNodeState"].(string)
			return state != "active"
		}, "Docker Swarm is active. Live-restore applies to standalone containers. Set docker_live_restore_enabled=false to keep Swarm's service lifecycle."),
		assertStep("Verify live restore when it is managed through Docker service arguments", func(r *engine.Run) bool {
			return !inCLI(r) || (running && liveEnabled() == enabled)
		}, "Docker already manages live-restore through its service arguments. Adjust that setting to match docker_live_restore_enabled; no duplicate daemon.json option was written."),
		assertStep("Require a regular Docker configuration file", func(r *engine.Run) bool {
			if !inFile(r) {
				return true
			}
			fi, err := os.Lstat(b.Sys.Path(path))
			existed, origInfo = err == nil, fi
			return err != nil || fi.Mode().IsRegular()
		}, "Docker daemon.json must be a regular file; it was not changed."),
		fact("Read the existing Docker configuration", inFile, func() error {
			original = nil
			if !existed {
				return nil
			}
			raw, err := os.ReadFile(b.Sys.Path(path))
			original = raw
			return err
		}),
		fact("Preserve existing Docker settings", inFile, func() error {
			config = map[string]any{}
			if !existed {
				return nil
			}
			var v any
			if err := decodeJSON(original, &v); err != nil {
				return err
			}
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("Docker daemon.json must contain a JSON object; it was not changed.")
			}
			config = m
			return nil
		}),
		assertStep("Require a Docker configuration object", func(*engine.Run) bool { return config != nil },
			"Docker daemon.json must contain a JSON object; it was not changed."),
		{Name: "Ensure the Docker configuration directory exists", When: inFile, Resource: b.Dir("/etc/docker", "root", "root", "0755")},
		{Name: "Validate and write Docker live restore while preserving other settings", When: inFile, Register: "docker_live_restore_written",
			Build: func(r *engine.Run) (engine.Resource, error) {
				merged := map[string]any{}
				for k, v := range config {
					merged[k] = v
				}
				merged["live-restore"] = enabled
				owner, group, mode := "0", "0", os.FileMode(0o644)
				if existed {
					uid, gid := fileOwner(origInfo)
					owner, group, mode = strconv.Itoa(uid), strconv.Itoa(gid), origInfo.Mode().Perm()
				}
				return &rescuedFile{File: engine.File{Path: path, Content: []byte(pyNiceJSON(merged, 0) + "\n"), Owner: owner, Group: group, Mode: mode,
					Validate: func(sys *engine.System, tmp string) error {
						out, code, err := sys.Exec("/bin/sh", "-c", `exec /usr/bin/dockerd --validate --config-file "$1" 2>&1`, "dockerd-validate", tmp)
						if err == nil && code != 0 {
							err = fmt.Errorf("dockerd --validate: exit %d %s", code, strings.TrimSpace(out))
						}
						return err
					}}, rescue: func(sys *engine.System, cause error) error { return rescue(sys, r, cause) }}, nil
			}},
		{Name: "Reload Docker configuration without stopping containers",
			When: func(r *engine.Run) bool {
				return apply(r) && (r.Changed("docker_live_restore_written") || liveEnabled() != enabled)
			},
			Build: func(r *engine.Run) (engine.Resource, error) {
				return &engine.Func{Desc: "systemctl reload docker.service",
					CheckFn: func(*engine.System) (engine.Change, error) { return engine.Change{Needed: true, Summary: "run"}, nil },
					ApplyFn: func(sys *engine.System) error {
						out, code, err := sys.Exec("systemctl", "reload", "docker.service")
						if err == nil && code != 0 {
							err = fmt.Errorf("systemctl reload docker.service: exit %d %s", code, strings.TrimSpace(out))
						}
						if err != nil {
							return rescue(sys, r, err)
						}
						return nil
					}}, nil
			}},
		{Name: "Verify that the running Docker daemon applied live restore", When: apply,
			Build: func(r *engine.Run) (engine.Resource, error) {
				return &engine.Func{Desc: "docker info LiveRestoreEnabled", CheckFn: func(sys *engine.System) (engine.Change, error) {
					want := strconv.FormatBool(enabled)
					var last string
					for attempt := 0; attempt <= 5; attempt++ {
						if attempt > 0 {
							time.Sleep(time.Second)
						}
						out, code, err := sys.Exec("/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "info", "--format", "{{.LiveRestoreEnabled}}")
						last = strings.TrimSpace(out)
						if err == nil && code == 0 && strings.ToLower(last) == want {
							return engine.Change{Summary: "live-restore " + want}, nil
						}
					}
					return engine.Change{}, rescue(sys, r, fmt.Errorf("LiveRestoreEnabled is %q, not %s", last, want))
				}}, nil
			}},
	}
	return steps
}

// rescuedFile is a File whose failed write goes through the block's rescue.
type rescuedFile struct {
	engine.File
	rescue func(sys *engine.System, cause error) error
}

func (f *rescuedFile) Apply(sys *engine.System, c engine.Change) error {
	if err := f.File.Apply(sys, c); err != nil {
		return f.rescue(sys, err)
	}
	return nil
}

// decodeJSON is from_json: numbers kept as json.Number so they print back
// as they were read.
func decodeJSON(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(into)
}

// pyNiceJSON is Ansible's to_nice_json: json.dumps(indent=4, sort_keys=True,
// separators=(',', ': ')), ensure_ascii.
func pyNiceJSON(v any, depth int) string {
	pad := strings.Repeat("    ", depth+1)
	end := strings.Repeat("    ", depth)
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			return "{}"
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, pad+pyJSON(k)+": "+pyNiceJSON(x[k], depth+1))
		}
		return "{\n" + strings.Join(parts, ",\n") + "\n" + end + "}"
	case []any:
		if len(x) == 0 {
			return "[]"
		}
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = pad + pyNiceJSON(item, depth+1)
		}
		return "[\n" + strings.Join(parts, ",\n") + "\n" + end + "]"
	case string:
		return pyJSON(x)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return "null"
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return strconv.FormatInt(n, 10)
		}
		f, _ := x.Float64()
		return pyFloat(f)
	case float64:
		return pyFloat(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return pyJSON(fmt.Sprint(v))
}

// pyFloat is Python's float repr, as json.dumps writes a float.
func pyFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case math.IsNaN(f):
		return "NaN"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expText, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expText)
	if exp < -4 || exp >= 16 {
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		return fmt.Sprintf("%se%s%02d", mant, sign, exp)
	}
	out := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(out, ".") {
		out += ".0"
	}
	return out
}

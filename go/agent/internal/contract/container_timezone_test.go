package contract

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// The panel and Authelia containers keep the gateway's time. Both roles
// defaulted their containers to Europe/Moscow whatever the host said; on a
// gateway in another zone every time the panel wrote itself was hours off.
// The playbook now reads the gateway's zone, and a container takes it unless
// the operator chose one.

// containerTimezoneRender mirrors the Python suite's environment(): a plain
// Jinja Environment (no autoescape, no whitespace control) with the Ansible
// filters these templates use (dirname, bool), rendering from the source.
func containerTimezoneRender(t *testing.T, rel string, vars map[string]any) string {
	t.Helper()
	dir := filepath.Dir(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	env := jinja.NewEnvironment(func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		return string(raw), err
	})
	env.Autoescape = false
	env.TrimBlocks = false
	env.LstripBlocks = false
	jinja.AddAnsibleFilters(env)
	tmpl, err := env.FromString(filepath.Base(rel), read(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	out, err := env.RenderTemplate(tmpl, vars)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func containerTimezoneLoad(t *testing.T, text string) any {
	t.Helper()
	v, err := pyyaml.Load([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func containerTimezoneMapping(t *testing.T, v any, what string) *pyyaml.Map {
	t.Helper()
	m, ok := v.(*pyyaml.Map)
	if !ok {
		t.Fatalf("%s is %T, not a mapping", what, v)
	}
	return m
}

// containerTimezoneAdminTZ is admin_tz: the rendered admin compose's panel
// container TZ.
func containerTimezoneAdminTZ(t *testing.T, vars map[string]any) string {
	t.Helper()
	out := containerTimezoneRender(t, "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2", vars)
	compose := containerTimezoneMapping(t, containerTimezoneLoad(t, out), "compose")
	services := containerTimezoneMapping(t, compose.Value("services"), "services")
	admin := containerTimezoneMapping(t, services.Value("haproxy-admin"), "haproxy-admin")
	environment := containerTimezoneMapping(t, admin.Value("environment"), "environment")
	tz, ok := environment.Value("TZ").(string)
	if !ok {
		t.Fatalf("admin TZ is %v, not a string", environment.Value("TZ"))
	}
	return tz
}

// containerTimezoneAutheliaZones is authelia_tz: the set of TZ values across
// every rendered Authelia service.
func containerTimezoneAutheliaZones(t *testing.T, vars map[string]any) map[string]bool {
	t.Helper()
	merged := map[string]any{
		"authelia_container_name": "authelia",
		"authelia_docker_network": "authelia_net",
	}
	for k, v := range vars {
		merged[k] = v
	}
	out := containerTimezoneRender(t, "ansible/roles/authelia/templates/docker-compose.yml.j2", merged)
	compose := containerTimezoneMapping(t, containerTimezoneLoad(t, out), "compose")
	services := containerTimezoneMapping(t, compose.Value("services"), "services")
	zones := map[string]bool{}
	services.Each(func(_, service any) {
		svc := containerTimezoneMapping(t, service, "service")
		entries, _ := svc.Value("environment").([]any)
		for _, entry := range entries {
			if s, ok := entry.(string); ok && strings.HasPrefix(s, "TZ=") {
				zones[s[3:]] = true
			}
		}
	})
	return zones
}

func containerTimezoneZonesAre(t *testing.T, got map[string]bool, want []string, label string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: zones %v, want %v", label, got, want)
		return
	}
	for _, zone := range want {
		if !got[zone] {
			t.Errorf("%s: zones %v, want %v", label, got, want)
			return
		}
	}
}

// containerTimezonePlaybookTask is playbook_task: the named pre_task of the
// first play.
func containerTimezonePlaybookTask(t *testing.T, name string) *pyyaml.Map {
	t.Helper()
	plays, ok := containerTimezoneLoad(t, read(t, "ansible/easy-ha-proxy.yml")).([]any)
	if !ok || len(plays) == 0 {
		t.Fatal("the playbook is not a list of plays")
	}
	play := containerTimezoneMapping(t, plays[0], "play")
	tasks, ok := play.Value("pre_tasks").([]any)
	if !ok {
		t.Fatal("no pre_tasks in the first play")
	}
	for _, task := range tasks {
		if m, ok := task.(*pyyaml.Map); ok && m.Value("name") == name {
			return m
		}
	}
	t.Fatalf("no pre_task named %q", name)
	return nil
}

func TestNoRoleNamesAZoneOfItsOwn(t *testing.T) {
	// Both roles default to the empty choice, and no template hardcodes the
	// old Moscow zone.
	admin := containerTimezoneMapping(t,
		containerTimezoneLoad(t, read(t, "ansible/roles/haproxy-admin/defaults/main.yml")), "admin defaults")
	authelia := containerTimezoneMapping(t,
		containerTimezoneLoad(t, read(t, "ansible/roles/authelia/defaults/main.yml")), "authelia defaults")
	if got := admin.Value("haproxy_admin_timezone"); got != "" {
		t.Errorf("haproxy_admin_timezone %v, want empty", got)
	}
	if got := authelia.Value("authelia_timezone"); got != "" {
		t.Errorf("authelia_timezone %v, want empty", got)
	}
	for _, rel := range []string{
		"ansible/roles/haproxy-admin/templates/docker-compose.yml.j2",
		"ansible/roles/authelia/templates/docker-compose.yml.j2",
	} {
		if strings.Contains(read(t, rel), "Europe/Moscow") {
			t.Errorf("%s names Europe/Moscow", rel)
		}
	}
}

func TestThePanelTakesTheGatewaysZone(t *testing.T) {
	got := containerTimezoneAdminTZ(t, map[string]any{
		"haproxy_admin_timezone":      "",
		"easy_ha_proxy_host_timezone": "Europe/Warsaw",
	})
	if got != "Europe/Warsaw" {
		t.Errorf("admin TZ %q, want Europe/Warsaw", got)
	}
}

func TestAnOperatorsChoiceWins(t *testing.T) {
	got := containerTimezoneAdminTZ(t, map[string]any{
		"haproxy_admin_timezone":      "Asia/Tokyo",
		"easy_ha_proxy_host_timezone": "Europe/Warsaw",
	})
	if got != "Asia/Tokyo" {
		t.Errorf("admin TZ %q, want Asia/Tokyo", got)
	}
}

func TestNothingKnownIsUtc(t *testing.T) {
	if got := containerTimezoneAdminTZ(t, map[string]any{}); got != "UTC" {
		t.Errorf("admin TZ %q, want UTC", got)
	}
}

func TestEveryAutheliaContainerTakesTheSameZone(t *testing.T) {
	// Redis, the mail relay and Authelia itself must agree on one zone.
	containerTimezoneZonesAre(t, containerTimezoneAutheliaZones(t, map[string]any{
		"authelia_timezone":           "",
		"easy_ha_proxy_host_timezone": "Europe/Warsaw",
		"mail_notify_enabled":         true,
	}), []string{"Europe/Warsaw"}, "gateway zone")
	containerTimezoneZonesAre(t, containerTimezoneAutheliaZones(t, map[string]any{
		"authelia_timezone":           "Asia/Tokyo",
		"easy_ha_proxy_host_timezone": "Europe/Warsaw",
	}), []string{"Asia/Tokyo"}, "operator choice")
	containerTimezoneZonesAre(t, containerTimezoneAutheliaZones(t, map[string]any{}),
		[]string{"UTC"}, "nothing known")
}

func TestOnEveryRunWithoutCountingAsAChange(t *testing.T) {
	probe := containerTimezonePlaybookTask(t, "Read the gateway's time zone")
	remember := containerTimezonePlaybookTask(t, "Remember the gateway's time zone")
	// A shell task runs on the gateway; a lookup would read the machine
	// the playbook was started from.
	if _, ok := probe.Get("ansible.builtin.shell"); !ok {
		t.Error("the probe is not an ansible.builtin.shell task")
	}
	if got := probe.Value("changed_when"); got != false {
		t.Errorf("probe changed_when %v, want false", got)
	}
	if got := probe.Value("check_mode"); got != false {
		t.Errorf("probe check_mode %v, want false", got)
	}
	if got := probe.Value("tags"); got != "always" {
		t.Errorf("probe tags %v, want always", got)
	}
	if got := remember.Value("tags"); got != "always" {
		t.Errorf("remember tags %v, want always", got)
	}
	fact := containerTimezoneMapping(t, remember.Value("ansible.builtin.set_fact"), "set_fact")
	if _, ok := fact.Get("easy_ha_proxy_host_timezone"); !ok {
		t.Error("the remember task does not set easy_ha_proxy_host_timezone")
	}
}

func TestItTakesWhatTimedatectlSaysAndNothingOdd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX host")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	script, ok := containerTimezonePlaybookTask(t, "Read the gateway's time zone").
		Value("ansible.builtin.shell").(string)
	if !ok {
		t.Fatal("the probe has no shell script")
	}
	directory := t.TempDir()
	fake := filepath.Join(directory, "timedatectl")
	zone := func(said string) string {
		body := "#!/bin/sh\nprintf '%s\\n' '" + said + "'\n"
		if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("timedatectl said %q: %v\n%s", said, err, stderr.String())
		}
		return strings.TrimSpace(stdout.String())
	}
	for _, said := range []string{"Europe/Warsaw", "America/Argentina/Buenos_Aires", "Etc/GMT+3"} {
		if got := zone(said); got != said {
			t.Errorf("zone(%q) = %q, want it unchanged", said, got)
		}
	}
	for _, odd := range []string{"Europe/Warsaw x", "../../etc/passwd", "/etc/localtime", "Europe/"} {
		if got := zone(odd); got != "UTC" {
			t.Errorf("zone(%q) = %q, want UTC", odd, got)
		}
	}
}

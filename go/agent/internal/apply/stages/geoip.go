package stages

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
)

// The GeoIP stage: roles/geoip_acl/tasks/geoip.yml (the role's main.yml
// hands it to the agent or includes it).
func init() {
	register(Stage{Name: "geoip", Parts: []Part{
		{Name: "geoip_acl/geoip", Role: "geoip_acl", File: "geoip", Build: geoip},
	}})
}

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

func geoip(b *Builder) []engine.Step {
	dbOn := b.Bool("{{ geoip_database_enabled | default(true) | bool }}")
	filterOn := b.Bool("{{ enable_geoip | default(false) | bool }}")
	db := func(*engine.Run) bool { return dbOn }
	syncManaged := b.Bool("{{ haproxy_admin_sync_managed_config | default(false) | bool }}")
	defaultCountries, _ := b.Set.Template("{{ geoip_country_codes | default([]) }}")
	defaultEnabled, _ := b.Set.Template("{{ enable_geoip | default(false) }}")
	runtimeVars := "/opt/haproxy-admin/config/vars.yml"

	var runtime *pyyaml.Map
	var countries []string
	var selectionOn bool
	update := &engine.Command{Argv: []string{"systemctl", "start", "easy-ha-proxy-geoip-update.service"}, Changes: true, IgnoreErrors: true}
	updateFailed := func(*engine.Run) bool { return update.Code != 0 }
	journal := &engine.Command{Argv: []string{"journalctl", "-u", "easy-ha-proxy-geoip-update.service", "-n", "50", "--no-pager"},
		Probe: true, IgnoreErrors: true}

	return []engine.Step{
		assertStep("Validate local GeoIP database settings", func(*engine.Run) bool { return !filterOn || dbOn },
			"HAProxy GeoIP access filtering requires the local GeoIP database. Set geoip_database_enabled=true or disable enable_geoip."),
		{Name: "Install local GeoIP database dependencies", When: db, Tags: restoreNetwork,
			Resource: &engine.Packages{Names: []string{"ca-certificates"}}},
		{Name: "Ensure the GeoIP directory exists", Resource: b.Dir("/etc/haproxy/geoip", "root", "haproxy", "0755")},
		{Name: "Remove the former Python GeoIP updater and its environment", Resource: &engine.Multi{Desc: "former updater",
			Items: []engine.Resource{&engine.Absent{Path: "/usr/local/lib/easy-ha-proxy/update_geoip.py"},
				&engine.Absent{Path: "/usr/local/lib/easy-ha-proxy/geoip-venv"}}}},
		{Name: "Copy the static GeoIP bypass list",
			Build: b.CopyFile("whitelist.geo", "/etc/haproxy/geoip/whitelist.geo", "haproxy", "haproxy", "0664", NoForce)},
		{Name: "Read the HAProxy Admin runtime variables for GeoIP selection",
			When: func(*engine.Run) bool { return b.Exists(runtimeVars, false) && !syncManaged },
			Resource: &engine.Func{Desc: "read " + runtimeVars, CheckFn: func(sys *engine.System) (engine.Change, error) {
				raw, err := os.ReadFile(sys.Path(runtimeVars))
				if err != nil {
					return engine.Change{}, err
				}
				doc, err := pyyaml.Load(raw)
				if err != nil {
					return engine.Change{}, fmt.Errorf("%s: %w", runtimeVars, err)
				}
				runtime, _ = doc.(*pyyaml.Map)
				return engine.Change{Summary: "read"}, nil
			}}},
		{Name: "Select the effective runtime GeoIP settings", Build: func(*engine.Run) (engine.Resource, error) {
			chosen := defaultCountries
			enabled := defaultEnabled
			if runtime != nil {
				if v, ok := runtime.Get("geoip_country_codes"); ok {
					chosen = v
				}
				if v, ok := runtime.Get("enable_geoip"); ok {
					enabled = v
				}
			}
			list, ok := chosen.([]any)
			if !ok && chosen != nil {
				return nil, errors.New("geoip_country_codes is not a list")
			}
			seen := map[string]bool{}
			countries = nil
			for _, item := range list {
				code := strings.ToUpper(jinja.Str(item))
				if !seen[code] {
					seen[code] = true
					countries = append(countries, code)
				}
			}
			sort.Strings(countries)
			on, err := jinja.AnsibleBool(nil, enabled, nil, nil)
			if err != nil {
				return nil, err
			}
			selectionOn = on.(bool)
			return nil, nil
		}},
		assertStep("Validate the effective runtime GeoIP settings", func(*engine.Run) bool {
			for _, c := range countries {
				if !countryCode.MatchString(c) {
					return false
				}
			}
			return !selectionOn || len(countries) > 0
		}, "Runtime GeoIP filtering requires one or more valid ISO 3166-1 alpha-2 country codes."),
		{Name: "Synchronize the runtime GeoIP country selection", Register: "geoip_selection_sync",
			Build: func(*engine.Run) (engine.Resource, error) {
				list := countries
				if list == nil {
					list = []string{}
				}
				// The form controld and the updater write: Ansible's to_nice_json
				// (indent 4, no final newline) made every update after a panel apply
				// rewrite the file and rebuild the GeoIP release for nothing.
				return &engine.File{Path: "/etc/haproxy/geoip/selection.json", Content: tools.SelectionJSON(list, selectionOn),
					Owner: "root", Group: "haproxy", Mode: 0o644}, nil
			}},
		{Name: "Install the GeoIP update command", Register: "geoip_update_command",
			Build: b.Template("update-geoip.sh.j2", "/usr/local/bin/update-geoip.sh", "root", "root", "0755")},
		{Name: "Install the GeoIP update service", Register: "geoip_update_service",
			Build: b.Template("easy-ha-proxy-geoip-update.service.j2", "/etc/systemd/system/easy-ha-proxy-geoip-update.service", "root", "root", "0644")},
		{Name: "Install the GeoIP update timer", Register: "geoip_update_timer",
			Build: b.Template("easy-ha-proxy-geoip-update.timer.j2", "/etc/systemd/system/easy-ha-proxy-geoip-update.timer", "root", "root", "0644")},
		{Name: "Remove the legacy GeoIP cron entry", When: func(*engine.Run) bool { return b.Exists("/usr/bin/crontab", false) },
			Resource: &engine.CronAbsent{Name: "Update HAProxy GeoIP lists", User: "root"}},
		{Name: "Reload systemd after GeoIP unit changes", When: Changed("geoip_update_service", "geoip_update_timer"),
			Resource: engine.DaemonReload{}},
		{Name: "Build the current local GeoIP release through its systemd unit", Tags: restoreNetwork,
			When: func(r *engine.Run) bool {
				return dbOn && (!b.Exists("/etc/haproxy/geoip/current", false) ||
					r.ChangedAny("geoip_selection_sync", "geoip_update_service", "geoip_update_timer", "geoip_update_command"))
			}, Resource: update},
		{Name: "Read the GeoIP updater journal after an initial failure",
			When: func(r *engine.Run) bool { return dbOn && updateFailed(r) }, Resource: journal},
		{Name: "Enable or disable the local GeoIP update timer", Tags: restoreNetwork,
			Resource: Unit("easy-ha-proxy-geoip-update.timer", engine.Bool(dbOn), map[bool]string{true: "started", false: "stopped"}[dbOn])},
		{Name: "Report a deferred UI-only GeoIP database update",
			When: func(r *engine.Run) bool { return dbOn && !filterOn && updateFailed(r) },
			Build: func(*engine.Run) (engine.Resource, error) {
				return &engine.Func{Desc: "report", CheckFn: func(*engine.System) (engine.Change, error) {
					return engine.Change{Summary: "The local GeoIP database could not be downloaded. HAProxy country filtering is " +
						"disabled, so installation continues and the UI will show unknown countries until the timer succeeds: " +
						strings.TrimSpace(journal.Output)}, nil
				}}, nil
			}},
		{Name: "Stop when an enabled GeoIP access filter has no valid local database",
			When: func(r *engine.Run) bool { return dbOn && filterOn && updateFailed(r) },
			Build: func(*engine.Run) (engine.Resource, error) {
				return nil, fmt.Errorf("The local GeoIP release could not be prepared, so enabling the HAProxy country filter "+
					"would be unsafe. The previous release was preserved and the update timer remains enabled. Details: %s",
					strings.TrimSpace(journal.Output))
			}},
	}
}

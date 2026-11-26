package contract

import (
	"fmt"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Guards against the "every apply runs a full apt update" slowdown. Several
// roles run apt with update_cache to ensure packages are present; a
// play-wide cache_valid_time default makes only the first such task refresh
// the index and the rest reuse it, turning many minutes of repeated network
// refreshes into one. The Docker repository is the single third-party
// source, so it must force a refresh when newly added, and a deliberate OS
// upgrade must always refresh.

func TestPlaySetsACacheValidTimeDefault(t *testing.T) {
	v, err := pyyaml.Load([]byte(read(t, "ansible/easy-ha-proxy.yml")))
	if err != nil {
		t.Fatal(err)
	}
	plays, ok := v.([]any)
	if !ok || len(plays) == 0 {
		t.Fatal("the playbook is not a non-empty list of plays")
	}
	play, ok := plays[0].(*pyyaml.Map)
	if !ok {
		t.Fatal("the first play is not a mapping")
	}
	// .get("module_defaults", {}).get("ansible.builtin.apt", {}): a nil
	// *Map reads as the empty dict.
	defaults, _ := play.Value("module_defaults").(*pyyaml.Map)
	aptDefaults, _ := defaults.Value("ansible.builtin.apt").(*pyyaml.Map)
	if _, ok := aptDefaults.Get("cache_valid_time"); !ok {
		t.Error("module_defaults for ansible.builtin.apt lack cache_valid_time")
	}
	// Overridable and non-zero by default: the variable name must appear
	// in the defaults' string form, as str(apt_defaults) carried it.
	var repr strings.Builder
	aptDefaults.Each(func(key, value any) {
		fmt.Fprintf(&repr, "%v: %v; ", key, value)
	})
	if !strings.Contains(repr.String(), "easy_ha_proxy_apt_cache_valid_time") {
		t.Errorf("apt module defaults are not overridable via easy_ha_proxy_apt_cache_valid_time: %s", repr.String())
	}
}

package contract

import (
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// The HAProxy protection order. APT metadata freshness, the HAProxy version
// status and the OS package isolation are tested in the host agent
// (tools/apt_metadata_test.go and updateplan); what remains here is the
// playbook's protection pre-task.

// The existing core is protected before the first package install, and a
// status-only play stays read-only: the pre-task is the installer agent's
// haproxy/protection part, tagged for both the install and the upgrade so
// no path installs a shared library before the protection is in place.
func TestExistingCoreIsProtectedBeforeTheFirstPackageInstallAndStatusStaysReadOnly(t *testing.T) {
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
	preTasks, ok := play.Value("pre_tasks").([]any)
	if !ok {
		t.Fatal("the first play has no pre_tasks")
	}
	var protection *pyyaml.Map
	for _, task := range preTasks {
		m, ok := task.(*pyyaml.Map)
		if !ok {
			continue
		}
		// .get('ansible.builtin.import_role', {}).get('tasks_from'): a nil
		// *Map reads as the empty dict.
		role, _ := m.Value("ansible.builtin.import_role").(*pyyaml.Map)
		if role.Value("tasks_from") == "protection" {
			protection = m
			break
		}
	}
	if protection == nil {
		t.Fatal("no pre-task imports the protection tasks")
	}
	role, _ := protection.Value("ansible.builtin.import_role").(*pyyaml.Map)
	if got := role.Value("name"); got != "haproxy" {
		t.Errorf("the protection pre-task imports role %v, want haproxy", got)
	}
	tags, ok := protection.Value("tags").([]any)
	if !ok {
		t.Fatalf("the protection tags are not a list: %v", protection.Value("tags"))
	}
	got := map[string]bool{}
	for _, tag := range tags {
		s, ok := tag.(string)
		if !ok {
			t.Fatalf("protection tag %v is not a string", tag)
		}
		got[s] = true
	}
	want := map[string]bool{"ha-install": true, "upgrade": true}
	for tag := range want {
		if !got[tag] {
			t.Errorf("the protection pre-task lacks tag %q", tag)
		}
	}
	for tag := range got {
		if !want[tag] {
			t.Errorf("the protection pre-task has unexpected tag %q", tag)
		}
	}
}

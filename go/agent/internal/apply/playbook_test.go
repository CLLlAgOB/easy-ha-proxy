package apply

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Ansible's tag evaluation: always runs unless skipped by name, never runs
// only when one of its other tags is asked for, skip wins.
func TestSelectedFollowsAnsiblesTagRules(t *testing.T) {
	for _, c := range []struct {
		tags       []string
		only, skip string
		want       bool
	}{
		{[]string{"ha-cfg", "addsite"}, "all", "", true},
		{[]string{"never", "aut-cfg"}, "all", "", false},
		{[]string{"never", "aut-cfg"}, "aut-cfg", "", true},
		{[]string{"always"}, "status", "", true},
		{[]string{"always"}, "status", "always", false},
		{[]string{"ha-cfg"}, "status", "", false},
		{[]string{"ha-cfg"}, "ha-cfg,status", "ha-cfg", false},
		{[]string{"upgrade"}, "all", "restore-network", true},
		{nil, "all", "", true},
		{nil, "tagged", "", false},
	} {
		if got := selected(c.tags, splitTags(c.only), splitTags(c.skip)); got != c.want {
			t.Errorf("tags %v --tags %q --skip-tags %q: got %v", c.tags, c.only, c.skip, got)
		}
	}
}

func root(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

// Every entry of the playbook runs through parts, but for the ones run by
// hand that are not moved yet; a new entry fails here until it has parts.
func TestEveryPlaybookEntryHasParts(t *testing.T) {
	entries, err := readEntries(root(t))
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, e := range entries {
		if e.parts == nil {
			missing = append(missing, e.label)
		}
	}
	sort.Strings(missing)
	var want []string
	if strings.Join(missing, ",") != strings.Join(want, ",") {
		t.Errorf("entries without parts: %v, want %v", missing, want)
	}
	if entries[0].label != "pre_tasks: Protect existing HAProxy before host or system updates" || entries[0].parts[0] != "haproxy/protection" {
		t.Errorf("the protection pre-task comes first: %+v", entries[0])
	}
	last := entries[len(entries)-1]
	if last.play != 1 || last.parts[0] != "healthcheck/status" {
		t.Errorf("the status check is the second play's: %+v", last)
	}
}

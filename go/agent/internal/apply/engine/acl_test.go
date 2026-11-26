package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file whose group entry is wider than its mask (an old chmod) answers
// "setfacl --test -x" with a recalculated mask even when the named entry is
// gone; the role's absent ACL then "changed" on every run and widened the
// mode the file task had just set. The removal keeps the mask (-n).
func TestAnAbsentACLKeepsTheMaskAndSeesNothingToRemove(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	var calls []string
	sys := &System{Root: root, Exec: func(name string, args ...string) (string, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "-n -x user:reader") {
			// Without -n setfacl would recalculate the mask: a "change".
			return root + "/compose.yml: u::rw-,g::r-x,m::r-x,o::---,*\n", 0, nil
		}
		return root + "/compose.yml: *,*\n", 0, nil
	}}
	acl := &ACL{Path: "/compose.yml", User: "reader", Absent: true}
	change, err := acl.Check(sys)
	if err != nil {
		t.Fatal(err)
	}
	if change.Needed {
		t.Fatalf("an entry that is not there needs removing: %+v (%q)", change, calls)
	}
}

func TestAnAbsentACLStillRemovesAnEntryThatIsThere(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	var applied []string
	sys := &System{Root: root, Exec: func(name string, args ...string) (string, int, error) {
		if args[0] == "--test" {
			return root + "/f: u::rw-,g::r--,m::r-x,o::---,*\n", 0, nil
		}
		applied = append(applied, strings.Join(args, " "))
		return "", 0, nil
	}}
	acl := &ACL{Path: "/f", User: "reader", Absent: true, Default: false}
	change, err := acl.Check(sys)
	if err != nil || !change.Needed {
		t.Fatalf("change %+v err %v", change, err)
	}
	if err := acl.Apply(sys, change); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "-n -x user:reader "+filepath.Join(root, "f") {
		t.Fatalf("applied %q", applied)
	}
}

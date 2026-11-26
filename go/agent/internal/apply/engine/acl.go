package engine

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ACL is ansible.posix.acl for one named user's entry (etype: user): present
// with Perms, or absent; Default for the directory's default ACL. Whether it
// changes anything is asked of setfacl --test, as the module asks it: any
// line of the resulting ACL not marked "*,*" is a change.
type ACL struct {
	Path, User string
	Perms      string
	Default    bool
	Absent     bool
}

func (a *ACL) Describe() string { return "acl " + a.Path + " user:" + a.User }

func (a *ACL) args(test bool) []string {
	args := []string{}
	if test {
		args = append(args, "--test")
	}
	if a.Default {
		args = append(args, "-d")
	}
	if a.Absent {
		// -n: removing an entry leaves the mask as it is. Recalculated, the
		// mask widened to a group entry an earlier chmod had masked, so a
		// file the role keeps at 0640 showed 0650 after every removal -- and
		// --test reported that recalculation as a change even when the entry
		// was long gone, flipping the file's mode on every run.
		args = append(args, "-n", "-x", "user:"+a.User)
	} else {
		args = append(args, "-m", "user:"+a.User+":"+a.Perms)
	}
	return append(args, a.Path)
}

func (a *ACL) Check(sys *System) (Change, error) {
	if _, err := os.Lstat(sys.Path(a.Path)); errors.Is(err, os.ErrNotExist) {
		return Change{}, fmt.Errorf("path %s does not exist", a.Path)
	}
	args := a.args(true)
	args[len(args)-1] = sys.Path(a.Path)
	out, code, err := sys.Exec("setfacl", args...)
	if err != nil {
		return Change{}, err
	}
	if code != 0 {
		return Change{}, fmt.Errorf("setfacl --test: exit %d %s", code, strings.TrimSpace(out))
	}
	// The module's acl_changed: a line ending in "*,*" means nothing would
	// change; anything else (no such line) is a change.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(strings.TrimRight(line, "\r"), "*,*") {
			return Change{}, nil
		}
	}
	if a.Absent {
		return Change{Needed: true, Summary: "remove user:" + a.User}, nil
	}
	return Change{Needed: true, Summary: "user:" + a.User + ":" + a.Perms}, nil
}

func (a *ACL) Apply(sys *System, _ Change) error {
	args := a.args(false)
	args[len(args)-1] = sys.Path(a.Path)
	out, code, err := sys.Exec("setfacl", args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("setfacl: exit %d %s", code, strings.TrimSpace(out))
	}
	return nil
}

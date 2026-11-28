package hostsec

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const DefaultRebootMarker = "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"

var rebootUnitRe = regexp.MustCompile(`^easy-ha-proxy-web-reboot-[0-9a-f]{12}$`)

func readAutoRebootPolicy(p string) (map[string]any, error) {
	val, err := ReadJSON(p)
	if err != nil {
		return nil, err
	}
	_, okE := boolVal(val["enabled"])
	tm, okT := val["time"].(string)
	_, okU := numVal(val["updated_at"])
	if att, present := val["attempt"]; present && att != nil {
		if _, ok := att.(map[string]any); !ok {
			return nil, secErr("The automatic reboot policy is invalid")
		}
	}
	if allow, present := val["allow_service_reboot"]; present {
		if _, ok := boolVal(allow); !ok {
			return nil, secErr("The automatic reboot policy is invalid")
		}
	}
	if !okE || !okT || !hhmmRe.MatchString(tm) || !hex32Re.MatchString(strVal(val["id"])) || !okU {
		return nil, secErr("The automatic reboot policy is invalid")
	}
	return val, nil
}

// FireAutoReboot performs the final root-owned verification before issuing systemctl reboot.
func FireAutoReboot(root, lockPath, markerPath, requiredPath, unit string, now *time.Time, stdout io.Writer) (string, error) {
	if !rebootUnitRe.MatchString(unit) {
		return "", secErr("Invalid automatic reboot unit")
	}
	lock, err := acquireFlock(lockPath, true)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if !lexists(markerPath) {
		return "canceled", nil
	}
	owned, err := ReadJSON(markerPath)
	if err != nil {
		return "", err
	}
	automatic, _ := owned["automatic"].(map[string]any)
	if strVal(owned["unit"]) != unit || len(automatic) == 0 {
		return "obsolete", nil
	}
	policyFile := "reboot-policy.json"
	if automatic["unified"] == true {
		policyFile = "maintenance-reboot.json"
	}
	policyPath := filepath.Join(root, policyFile)
	var policy map[string]any
	result := "deferred"
	errText := ""
	defer func() {
		if result != "triggered" {
			if policy != nil && strVal(policy["id"]) == strVal(automatic["policy_revision"]) {
				policy["attempt"] = map[string]any{
					"window": automatic["window"],
					"state":  result,
					"at":     unixSeconds(nowFunc()),
					"error":  errText,
				}
				_ = AtomicWrite(policyPath, policy, 0o600)
			}
			_ = os.Remove(markerPath)
		}
	}()

	err = func() error {
		var rerr error
		policy, rerr = readAutoRebootPolicy(policyPath)
		if rerr != nil {
			return rerr
		}
		bootID, rerr := readBootID()
		if rerr != nil {
			return rerr
		}
		attempt, _ := policy["attempt"].(map[string]any)
		if strVal(owned["boot_id"]) != bootID || policy["enabled"] != true ||
			strVal(policy["id"]) != strVal(automatic["policy_revision"]) ||
			strVal(attempt["window"]) != strVal(automatic["window"]) ||
			strVal(attempt["state"]) != "scheduled" {
			result = "canceled"
			return nil
		}
		local := localTimeFunc()
		if now != nil {
			local = *now
		}
		permitted := false
		if automatic["unified"] == true {
			consent, cerr := readMWPolicy(root)
			if cerr != nil {
				return cerr
			}
			active := currentMWWindow(consent, local)
			permitted = active != nil && consent.ID == strVal(policy["id"]) && active.Key == strVal(automatic["window"])
		} else {
			anchor, key, werr := dailyWindow(local, strVal(policy["time"]))
			if werr != nil {
				return werr
			}
			diff := unixSeconds(local) - unixSeconds(anchor)
			permitted = key == strVal(automatic["window"]) && diff >= 0 && diff < 3600
		}
		if !permitted {
			result = "missed"
			return nil
		}
		allowService, _ := boolVal(policy["allow_service_reboot"])
		serviceReason := strVal(automatic["reason"]) == "services" && allowService
		if !lexists(requiredPath) && !serviceReason {
			result = "not_required"
			return nil
		}
		managed, rerr := ReadJSON(filepath.Join(root, "policy.json"))
		if rerr != nil {
			return rerr
		}
		if rerr = assertOSManaged(managed, false); rerr != nil {
			return rerr
		}
		if rerr = maintenanceGuard(true); rerr != nil {
			return rerr
		}
		return withPackageLocks(func() error {
			if !lexists(requiredPath) {
				rp, rperr := readRestartPolicy(root)
				if rperr != nil {
					return rperr
				}
				svcs, fberr := fallbackServices(root, &local, nil)
				if fberr != nil {
					return fberr
				}
				if !serviceReason || rp.ID != strVal(automatic["restart_policy_revision"]) || len(svcs) == 0 {
					result = "not_required"
					return nil
				}
			}
			if attempt == nil {
				attempt = map[string]any{}
				policy["attempt"] = attempt
			}
			attempt["state"] = "triggered"
			attempt["at"] = unixSeconds(nowFunc())
			attempt["error"] = nil
			if werr := AtomicWrite(policyPath, policy, 0o600); werr != nil {
				return werr
			}
			if _, _, cerr := runCommand([]string{"/usr/bin/systemctl", "reboot"}, cmdOpts{timeout: 30 * time.Second, check: true}); cerr != nil {
				return cerr
			}
			result = "triggered"
			return nil
		})
	}()
	if err != nil {
		errText = truncStr(err.Error(), 500)
		if stdout != nil {
			_, _ = fmt.Fprintln(stdout, errText)
		}
		return result, nil
	}
	return result, nil
}

// RunAutoRebootCLI implements "easy-ha-proxy-agent auto-reboot fire [flags]".
func RunAutoRebootCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "fire" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent auto-reboot fire --unit <unit> [flags]")
		return 2
	}
	fs := flag.NewFlagSet("auto-reboot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateRoot := fs.String("state-root", DefaultStateRoot, "")
	lockPath := fs.String("maintenance-lock", DefaultLockPath, "")
	rebootMarker := fs.String("reboot-marker", DefaultRebootMarker, "")
	requiredMarker := fs.String("required-marker", varRunRebootRequired, "")
	unit := fs.String("unit", "", "")
	if err := fs.Parse(args[1:]); err != nil || *unit == "" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent auto-reboot fire --unit <unit> [flags]")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Scheduled reboots require root")
		return 2
	}
	syscall.Umask(0o077)
	res, err := FireAutoReboot(*stateRoot, *lockPath, *rebootMarker, *requiredMarker, *unit, nil, stdout)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	fmt.Fprintln(stdout, res)
	return 0
}

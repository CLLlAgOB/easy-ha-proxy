package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// MaintenanceLockHeldEnv marks that this process (or its parent broker)
	// already holds the shared maintenance lock.
	MaintenanceLockHeldEnv = "EASY_HA_PROXY_MAINTENANCE_LOCK_HELD"
	// UpdatedJobUnitPrefix is the systemd transient unit prefix used by updated.
	UpdatedJobUnitPrefix = "easy-ha-proxy-updated-job-"
	// RebootDelaySeconds is the grace period before a CLI-scheduled reboot runs.
	RebootDelaySeconds = 30
	// RebootSystemdUnitPrefix is the transient unit prefix for CLI reboots.
	RebootSystemdUnitPrefix = "easy-ha-proxy-reboot"
)

var (
	rebootRequiredPath      = "/var/run/reboot-required"
	rebootScheduleMarker    = "/run/easy-ha-proxy/reboot-scheduled"
	webRebootScheduleMarker = "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"
	maintenanceLockPath     = ""
	maintenanceLockFD       = -1
	cgroupSelfPath          = "/proc/self/cgroup"
	rebootUnitRe            = regexp.MustCompile(`^` + regexp.QuoteMeta(RebootSystemdUnitPrefix) + `-[0-9]{14}-[0-9]+-[0-9a-f]{8}$`)
	startedByUpdateBrokerFn = defaultStartedByUpdateBroker
	rebootRequiredFn        = defaultRebootRequired
	scheduleServerRebootFn  = defaultScheduleServerReboot
	offerPendingRebootFn    = defaultOfferPendingReboot
)

func effectiveMaintenanceLockPath() string {
	if maintenanceLockPath != "" {
		return maintenanceLockPath
	}
	if v := os.Getenv("EASY_HA_PROXY_MAINTENANCE_LOCK"); v != "" {
		return v
	}
	return "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"
}

// StartedByUpdateBroker reports whether this process runs inside a job unit of
// the update broker, which already holds the maintenance lock for the job.
func StartedByUpdateBroker(cgroupPath string) bool {
	if cgroupPath == "" {
		cgroupPath = cgroupSelfPath
	}
	raw, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		idx := strings.LastIndex(line, ":")
		path := line
		if idx >= 0 {
			path = line[idx+1:]
		}
		for _, part := range strings.Split(path, "/") {
			if strings.HasPrefix(part, UpdatedJobUnitPrefix) && strings.HasSuffix(part, ".service") {
				return true
			}
		}
	}
	return false
}

func defaultStartedByUpdateBroker() bool {
	return StartedByUpdateBroker(cgroupSelfPath)
}

// HoldMaintenanceLock acquires the non-blocking exclusive maintenance lock for
// this CLI invocation, or returns an InstallerError if another operation holds it.
func HoldMaintenanceLock(path string) error {
	if os.Getenv(MaintenanceLockHeldEnv) != "" || startedByUpdateBrokerFn() {
		return nil
	}
	target := path
	if target == "" {
		target = effectiveMaintenanceLockPath()
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return installerErrorf("Cannot open the maintenance lock %s: %v", target, err)
	}
	fd, err := unix.Open(target, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return installerErrorf("Cannot open the maintenance lock %s: %v", target, err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return installerErrorf("Another maintenance operation -- an update, a backup or a restore, possibly started from the panel -- is running. Wait for it to finish and try again.")
	}
	maintenanceLockFD = fd
	_ = os.Setenv(MaintenanceLockHeldEnv, "cli")
	return nil
}

// ReleaseMaintenanceLock closes the lock fd if held by this process (used by tests).
func ReleaseMaintenanceLock() {
	if maintenanceLockFD >= 0 {
		_ = unix.Close(maintenanceLockFD)
		maintenanceLockFD = -1
	}
	_ = os.Unsetenv(MaintenanceLockHeldEnv)
}

// RebootRequired reports whether the OS indicates a pending reboot.
func RebootRequired() bool {
	return rebootRequiredFn()
}

func defaultRebootRequired() bool {
	_, err := os.Stat(rebootRequiredPath)
	return err == nil
}

// RebootScheduleIsActive checks whether a web or CLI reboot timer is still active.
func RebootScheduleIsActive() bool {
	if _, err := os.Lstat(webRebootScheduleMarker); err == nil {
		return true
	}
	raw, err := os.ReadFile(rebootScheduleMarker)
	if err != nil {
		return false
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			values[k] = v
		}
	}
	unitName := values["unit"]
	if !rebootUnitRe.MatchString(unitName) {
		_ = os.Remove(rebootScheduleMarker)
		return false
	}
	systemctl, err := lookPath("systemctl")
	if err == nil && systemctl != "" {
		for _, suffix := range []string{"timer", "service"} {
			res := runSubprocess(systemctl, "is-active", "--quiet", unitName+"."+suffix)
			if res.Err != nil {
				break
			}
			if res.ExitCode == 0 {
				return true
			}
		}
	}
	_ = os.Remove(rebootScheduleMarker)
	return false
}

// ScheduleServerReboot schedules a delayed systemd-run reboot so SSH sessions exit cleanly.
func ScheduleServerReboot(out io.Writer) error {
	return scheduleServerRebootFn(out)
}

func defaultScheduleServerReboot(out io.Writer) error {
	if RebootScheduleIsActive() {
		fmt.Fprintln(out, T("A reboot is already scheduled; the current session will close."))
		fmt.Fprintln(out, "EASY_HA_PROXY_REBOOT_SCHEDULED=1")
		return nil
	}
	systemdRun, err1 := lookPath("systemd-run")
	systemctl, err2 := lookPath("systemctl")
	if err1 != nil || systemdRun == "" || err2 != nil || systemctl == "" {
		return installerErrorf("Cannot schedule a controlled reboot: systemd-run or systemctl is missing.")
	}
	var tok [4]byte
	_, _ = rand.Read(tok[:])
	now := time.Now().UTC()
	unitName := fmt.Sprintf("%s-%s-%d-%s",
		RebootSystemdUnitPrefix,
		now.Format("20060102150405"),
		os.Getpid(),
		hex.EncodeToString(tok[:]),
	)
	if err := os.MkdirAll(filepath.Dir(rebootScheduleMarker), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("unit=%s\nscheduled_at=%s\n", unitName, now.Format(time.RFC3339Nano))
	if err := os.WriteFile(rebootScheduleMarker, []byte(content), 0o644); err != nil {
		return err
	}
	_ = os.Chmod(rebootScheduleMarker, 0o644)
	err := runCommand(out, []string{
		systemdRun,
		"--unit=" + unitName,
		"--description=easy-ha-proxy controlled reboot",
		fmt.Sprintf("--on-active=%ds", RebootDelaySeconds),
		"--timer-property=AccuracySec=1s",
		systemctl,
		"reboot",
	}, nil)
	if err != nil {
		_ = os.Remove(rebootScheduleMarker)
		return err
	}
	msg := strings.ReplaceAll(
		T("A server reboot has been scheduled in {seconds} seconds. The current session will close cleanly."),
		"{seconds}",
		fmt.Sprintf("%d", RebootDelaySeconds),
	)
	fmt.Fprintf(out, "\n%s\n", msg)
	fmt.Fprintln(out, "EASY_HA_PROXY_REBOOT_SCHEDULED=1")
	return nil
}

// OfferPendingReboot prompts for a required reboot, defaulting safely to defer.
func OfferPendingReboot(ctx *Context, assumeYes bool) (bool, error) {
	return offerPendingRebootFn(ctx, assumeYes)
}

func defaultOfferPendingReboot(ctx *Context, assumeYes bool) (bool, error) {
	if !RebootRequired() {
		return false, nil
	}
	fmt.Fprintf(ctx.Stdout, "\n%s\n", T("The operating system requires a reboot to finish applying updates."))
	decision := strings.ToLower(strings.TrimSpace(os.Getenv("EASY_HA_PROXY_REBOOT_DECISION")))
	rebootNow := false
	switch {
	case assumeYes || decision == "y" || decision == "yes" || decision == "1" || decision == "true" || decision == "д" || decision == "да":
		rebootNow = true
	case decision == "n" || decision == "no" || decision == "0" || decision == "false" || decision == "н" || decision == "нет":
		rebootNow = false
	case ctx.isTTY():
		var err error
		rebootNow, err = ctx.promptBool("Reboot the server now", false)
		if err != nil {
			return false, err
		}
	default:
		rebootNow = false
	}
	if rebootNow {
		if err := ScheduleServerReboot(ctx.Stdout); err != nil {
			return false, err
		}
		return true, nil
	}
	fmt.Fprintln(ctx.Stdout, T("Reboot deferred. Run 'sudo systemctl reboot' manually or choose 'Reboot server' in the assistant."))
	return false, nil
}

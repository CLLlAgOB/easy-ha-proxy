package fullbackup

import "strings"

// quiescer stops what writes the archived state while a backup or restore
// works, and starts it again afterwards.
type quiescer interface {
	enter() error
	resumeUnits()
	exit()
}

// quiesce: units are stopped; containers are paused for a backup and
// stopped for a restore.
type quiesce struct {
	enabled, stopContainers bool
	units, containers       []string
}

// newQuiesce is replaced by the tests.
var newQuiesce = func(enabled, stopContainers bool) quiescer {
	return &quiesce{enabled: enabled, stopContainers: stopContainers}
}

func (q *quiesce) enter() (err error) {
	if !q.enabled {
		return nil
	}
	defer func() {
		// A failure half-way must not leave the installation stopped when
		// no backup or restore work has begun.
		if err != nil {
			q.exit()
		}
	}()
	if which("systemctl") {
		for _, unit := range quiesceUnits {
			r, err := run([]string{"systemctl", "is-active", "--quiet", unit}, runOptions{})
			if err != nil || r.Code != 0 {
				continue
			}
			if _, err := run([]string{"systemctl", "stop", unit}, runOptions{check: true}); err != nil {
				return err
			}
			q.units = append(q.units, unit)
		}
	}
	if which("docker") {
		_, _ = run([]string{"docker", "exec", "authelia-redis", "redis-cli", "SAVE"}, runOptions{})
		for _, container := range quiesceContainers {
			if strings.TrimSpace(commandOutput("docker", "inspect", "-f", "{{.State.Running}}", container)) != "true" {
				continue
			}
			verb := "pause"
			if q.stopContainers {
				verb = "stop"
			}
			if _, err := run([]string{"docker", verb, container}, runOptions{check: true}); err != nil {
				return err
			}
			q.containers = append(q.containers, container)
		}
	}
	return nil
}

// resumeUnits restarts the stopped units before their state is inspected:
// restore reconciliation runs its status check while the quiesce is still
// open, and timers stopped here must be active again by then.
func (q *quiesce) resumeUnits() {
	units := q.units
	q.units = nil
	for i := len(units) - 1; i >= 0; i-- {
		_, _ = run([]string{"systemctl", "start", units[i]}, runOptions{})
	}
}

func (q *quiesce) exit() {
	containers := q.containers
	q.containers = nil
	verb := "unpause"
	if q.stopContainers {
		verb = "start"
	}
	for i := len(containers) - 1; i >= 0; i-- {
		_, _ = run([]string{"docker", verb, containers[i]}, runOptions{})
	}
	q.resumeUnits()
}

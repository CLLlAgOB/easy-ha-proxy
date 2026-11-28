// Package engine runs the Go installer's stages: an ordered list of steps,
// each a resource that knows how to tell whether the host already matches it
// (Check) and how to make it match (Apply).
//
// A stage reads like the Ansible task file it replaces: steps run in order,
// a step may register its result, and a later step's condition may read
// whether a registered step changed something -- "restart if the unit or the
// config changed". In plan mode nothing is applied: each step reports what it
// would change, and conditions see those would-be changes, so a plan shows
// the restarts an apply would do.
package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Mode says whether a run changes the host.
type Mode int

const (
	// Plan checks every step and changes nothing.
	Plan Mode = iota
	// Apply makes the host match.
	Apply
)

// Change is what a resource found: whether the host differs, and how.
type Change struct {
	Needed  bool
	Summary string // one line: "content 1832 -> 1840 bytes", "would restart"
	// Run asks for Apply even though nothing is reported changed: a command
	// task with changed_when: false still runs on every apply.
	Run bool
}

// Resource is one thing on the host a step manages.
type Resource interface {
	// Describe names it for the journal: "file /etc/systemd/system/x.service".
	Describe() string
	// Check compares the host with the resource, changing nothing.
	Check(sys *System) (Change, error)
	// Apply makes the host match what Check found different.
	Apply(sys *System, c Change) error
}

// Step is one task of a stage.
type Step struct {
	Name     string                         // the Ansible task's name, so a log reads the same
	Register string                         // when set, later conditions can ask Changed(Register)
	When     func(r *Run) bool              // nil runs always
	Resource Resource                       // what the step manages
	Build    func(r *Run) (Resource, error) // or builds it when it runs (from earlier results)
	Tags     []string                       // the task's own tags; a run can skip them
	// Notify names the handlers the step notifies when it changes something.
	// During the hybrid period they are handed back to Ansible, which runs
	// its own handlers at the end of the play, as it always has.
	Notify []string
}

// Result is one step's outcome, as the journal records it.
type Result struct {
	Stage    string  `json:"stage"`
	Step     string  `json:"step"`
	Resource string  `json:"resource,omitempty"`
	Status   string  `json:"status"` // ok | changed | would_change | skipped | failed
	Summary  string  `json:"summary,omitempty"`
	Error    string  `json:"error,omitempty"`
	Seconds  float64 `json:"seconds"`
}

// Run is one installer run: its mode, the host it works on, what earlier
// steps changed, and the journal.
type Run struct {
	Mode    Mode
	Sys     *System
	Journal io.Writer // JSON lines, one per step; nil writes none
	Results []Result
	// SkipTags are Ansible's --skip-tags for the steps' own tags.
	SkipTags map[string]bool
	// OnStep, when set, is told each step before it runs (a progress bar).
	OnStep func(stage, step string)

	changed   map[string]bool
	registers map[string]bool // every register this run reached, changed or not
	notified  []string        // handlers notified, in order, each once
}

// NewRun starts a run. seed names steps of earlier stages (or of Ansible,
// during the hybrid period) that changed something, so their dependents here
// still restart.
func NewRun(mode Mode, sys *System, journal io.Writer, seed ...string) *Run {
	r := &Run{Mode: mode, Sys: sys, Journal: journal, SkipTags: map[string]bool{},
		changed: map[string]bool{}, registers: map[string]bool{}}
	for _, name := range seed {
		r.changed[name] = true
	}
	return r
}

// Changed says whether the registered step changed something (or, in plan
// mode, would).
func (r *Run) Changed(register string) bool { return r.changed[register] }

// ChangedAny is Changed for any of the names.
func (r *Run) ChangedAny(registers ...string) bool {
	for _, name := range registers {
		if r.changed[name] {
			return true
		}
	}
	return false
}

// MarkChanged records a change made outside a step's resource.
func (r *Run) MarkChanged(register string) { r.changed[register] = true }

// Notified lists the handlers the run's steps notified, in order, each once.
func (r *Run) Notified() []string { return append([]string(nil), r.notified...) }

func (r *Run) notify(names []string) {
	for _, name := range names {
		seen := false
		for _, n := range r.notified {
			if n == name {
				seen = true
				break
			}
		}
		if !seen {
			r.notified = append(r.notified, name)
		}
	}
}

// Registers is every register the run's steps reached, with whether it
// changed: what Ansible would have registered, skipped steps included.
func (r *Run) Registers() map[string]bool {
	out := make(map[string]bool, len(r.registers))
	for k, v := range r.registers {
		out[k] = v
	}
	return out
}

// Do runs a stage's steps in order and stops at the first failure.
func (r *Run) Do(stage string, steps []Step) error {
	for _, step := range steps {
		if r.OnStep != nil {
			r.OnStep(stage, step.Name)
		}
		start := time.Now()
		res := Result{Stage: stage, Step: step.Name}
		err := r.do(step, &res)
		res.Seconds = time.Since(start).Seconds()
		if err != nil {
			res.Status, res.Error = "failed", err.Error()
		}
		r.record(res)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", stage, step.Name, err)
		}
	}
	return nil
}

func (r *Run) do(step Step, res *Result) error {
	if step.Register != "" && !r.registers[step.Register] {
		r.registers[step.Register] = false
	}
	for _, tag := range step.Tags {
		if r.SkipTags[tag] {
			res.Status, res.Summary = "skipped", "tag "+tag+" skipped"
			return nil
		}
	}
	if step.When != nil && !step.When(r) {
		res.Status = "skipped"
		return nil
	}
	resource := step.Resource
	if step.Build != nil {
		built, err := step.Build(r)
		if err != nil {
			return err
		}
		resource = built
	}
	if resource == nil {
		res.Status = "ok"
		return nil
	}
	res.Resource = resource.Describe()
	c, err := resource.Check(r.Sys)
	if err != nil {
		return err
	}
	res.Summary = c.Summary
	if !c.Needed {
		res.Status = "ok"
		if c.Run && r.Mode == Apply {
			if err := resource.Apply(r.Sys, c); err != nil {
				return err
			}
			if o, ok := resource.(Outcome); ok && o.Changed() {
				res.Status, res.Summary = "changed", "ran, changed"
				if step.Register != "" {
					r.changed[step.Register] = true
					r.registers[step.Register] = true
				}
				r.notify(step.Notify)
			}
		}
		return nil
	}
	if step.Register != "" {
		r.changed[step.Register] = true
		r.registers[step.Register] = true
	}
	r.notify(step.Notify)
	if r.Mode == Plan {
		res.Status = "would_change"
		return nil
	}
	if err := resource.Apply(r.Sys, c); err != nil {
		return err
	}
	res.Status = "changed"
	return nil
}

func (r *Run) record(res Result) {
	r.Results = append(r.Results, res)
	if r.Journal != nil {
		line, _ := json.Marshal(res)
		fmt.Fprintf(r.Journal, "%s\n", line)
	}
}

// Counts sums the run's results by status.
func (r *Run) Counts() map[string]int {
	out := map[string]int{}
	for _, res := range r.Results {
		out[res.Status]++
	}
	return out
}

// TakeNotified returns the handlers notified since the last call and
// forgets them, as a flush does.
func (r *Run) TakeNotified() []string {
	out := r.notified
	r.notified = nil
	return out
}

// Notify adds handlers to the notified list (a handler notifying others).
func (r *Run) Notify(names ...string) { r.notify(names) }

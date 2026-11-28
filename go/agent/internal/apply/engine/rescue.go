package engine

import "fmt"

// Rescued runs a resource inside a block whose rescue only reports: a failure
// becomes the summary instead of an error, and Failed says it happened, so
// the block's later steps can be skipped.
type Rescued struct {
	Inner  Resource
	Failed *bool
	Note   string // what the rescue reports
}

func (r *Rescued) Describe() string { return r.Inner.Describe() }

func (r *Rescued) Check(sys *System) (Change, error) {
	c, err := r.Inner.Check(sys)
	if err != nil {
		*r.Failed = true
		return Change{Summary: fmt.Sprintf("%s (%v)", r.Note, err)}, nil
	}
	return c, nil
}

func (r *Rescued) Apply(sys *System, c Change) error {
	if err := r.Inner.Apply(sys, c); err != nil {
		*r.Failed = true
		return nil
	}
	return nil
}

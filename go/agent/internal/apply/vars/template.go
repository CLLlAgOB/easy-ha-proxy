package vars

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TemplateOptions are the template module's per-task Jinja options.
type TemplateOptions struct {
	// LstripBlocks is the task's lstrip_blocks; trim_blocks is always on,
	// as the template module defaults it and no task here turns it off.
	LstripBlocks bool
}

// RenderFile renders a template file the way the template module does:
// trim_blocks on, the source's trailing newlines kept, no conversion of the
// result (convert_data=False), undefined names an error. local are the task's
// own variables (a loop item), above everything else.
func (s *Set) RenderFile(path string, local map[string]any, opts TemplateOptions) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	src := string(raw)
	if strings.HasPrefix(src, "#jinja2:") {
		return "", fmt.Errorf("%s: a #jinja2: header is not supported by the Go installer yet", path)
	}
	env := newEnv(s.resolve)
	env.LstripBlocks = opts.LstripBlocks
	tpl, err := env.FromString(filepath.Base(path), src)
	if err != nil {
		return "", err
	}
	outer := s.failure
	s.failure = nil
	out, err := env.RenderTemplate(tpl, local)
	if s.failure != nil {
		err = s.failure
	}
	s.failure = outer
	if err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if want, have := trailingNewlines(src), trailingNewlines(out); want > have {
		out += strings.Repeat("\n", want-have)
	}
	return out, nil
}

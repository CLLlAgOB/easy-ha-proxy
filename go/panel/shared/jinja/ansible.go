package jinja

import (
	"fmt"
	"strings"
)

// UndefinedError is printing a name nothing defines, under StrictUndefined.
type UndefinedError struct{ Name string }

func (e *UndefinedError) Error() string { return fmt.Sprintf("'%s' is undefined", e.Name) }

// AnsibleBool is Ansible's bool filter (ansible.plugins.filter.core.to_bool):
// a bool stays itself, None is false, and only "yes", "on", "1", "true" (any
// case) or the number 1 are true.
func AnsibleBool(_ *Environment, v any, _ []any, _ *Map) (any, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case nil:
		return false, nil
	case Undefined:
		return nil, &UndefinedError{Name: x.Name}
	case string:
		switch strings.ToLower(x) {
		case "yes", "on", "1", "true":
			return true, nil
		}
		return false, nil
	case Markup:
		return AnsibleBool(nil, string(x), nil, nil)
	case int64:
		return x == 1, nil
	case int:
		return x == 1, nil
	case float64:
		return x == 1, nil
	}
	return false, nil
}

// AddAnsibleFilters registers the Ansible filters this project's templates
// and role defaults use beyond Jinja's own.
func AddAnsibleFilters(env *Environment) {
	env.Filters["bool"] = AnsibleBool
	env.Filters["regex_replace"] = RegexReplaceFilter
	env.Filters["combine"] = CombineFilter
}

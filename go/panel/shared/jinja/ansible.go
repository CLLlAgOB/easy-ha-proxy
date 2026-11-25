package jinja

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
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

// AnsibleHash is Ansible's hash filter: the hex digest of the value's text,
// sha1 unless named; an unknown algorithm gives None, as hashlib.new fails.
func AnsibleHash(_ *Environment, v any, args []any, kwargs *Map) (any, error) {
	if u, ok := v.(Undefined); ok {
		return nil, &UndefinedError{Name: u.Name}
	}
	name := "sha1"
	if len(args) > 0 {
		name = Str(args[0])
	} else if kwargs != nil {
		if h, ok := kwargs.Get("hashtype"); ok {
			name = Str(h)
		}
	}
	var h hash.Hash
	switch strings.ToLower(name) {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return nil, nil
	}
	h.Write([]byte(Str(v)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AnsibleDirname and AnsibleBasename are os.path.dirname and basename.
func AnsibleDirname(_ *Environment, v any, _ []any, _ *Map) (any, error) {
	s := Str(v)
	i := strings.LastIndex(s, "/") + 1
	head := s[:i]
	if head != "" && strings.Trim(head, "/") != "" {
		head = strings.TrimRight(head, "/")
	}
	return head, nil
}

func AnsibleBasename(_ *Environment, v any, _ []any, _ *Map) (any, error) {
	s := Str(v)
	return s[strings.LastIndex(s, "/")+1:], nil
}

// AddAnsibleFilters registers the Ansible filters this project's templates
// and role defaults use beyond Jinja's own.
func AddAnsibleFilters(env *Environment) {
	env.Filters["bool"] = AnsibleBool
	env.Filters["hash"] = AnsibleHash
	env.Filters["dirname"] = AnsibleDirname
	env.Filters["basename"] = AnsibleBasename
	env.Filters["regex_replace"] = RegexReplaceFilter
	env.Filters["combine"] = CombineFilter
}

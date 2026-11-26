package stages

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

func init() {
	register(Stage{Name: "authelia-users", Parts: []Part{
		{Name: "authelia/users_apply", Role: "authelia", File: "users_apply", Build: autheliaUsersApply},
	}})
}

func mapOf(v any) *pyyaml.Map {
	if m, ok := v.(*pyyaml.Map); ok {
		return m
	}
	return pyyaml.NewMap()
}

func strOr(m *pyyaml.Map, key, fallback string) string {
	if v, ok := m.Get(key); ok && v != nil {
		return jinja.Str(v)
	}
	return fallback
}

// applyUserOps is the two set_fact loops of users_apply.yml: the deletions
// first, then each add or replace, every field chosen as the task's
// expressions choose it (a user an op replaces keeps only displayname,
// password, email and groups, as combine(recursive=False) leaves it).
func applyUserOps(users, ops *pyyaml.Map) *pyyaml.Map {
	out := pyyaml.NewMap()
	users.Each(func(k, v any) { out.Set(k, v) })
	ops.Each(func(k, v any) {
		if strOr(mapOf(v), "user_action", "add") == "delete" {
			out.Delete(k)
		}
	})
	ops.Each(func(k, v any) {
		name := jinja.Str(k)
		op := mapOf(v)
		action := strOr(op, "user_action", "add")
		if action != "add" && action != "replace" {
			return
		}
		existing, exists := out.Get(k)
		user := mapOf(existing)
		if !exists {
			user = pyyaml.NewMap()
		}
		_, opDisplay := op.Get("displayname")
		_, opHash := op.Get("password_hash")
		_, opEmail := op.Get("email")
		var display string
		switch {
		case exists && action == "add":
			display = strOr(user, "displayname", name)
		case strOr(op, "displayname_action", "") == "replace" && opDisplay:
			display = jinja.Str(op.Value("displayname"))
		case exists:
			display = strOr(user, "displayname", name)
		default:
			display = strOr(op, "displayname", name)
		}
		var password string
		switch {
		case strOr(op, "password_action", "") == "replace" && opHash:
			password = jinja.Str(op.Value("password_hash"))
		case exists:
			password = jinja.Str(user.Value("password"))
		default:
			password = strOr(op, "password_hash", "")
		}
		var email string
		switch {
		case strOr(op, "email_action", "") == "replace" && opEmail:
			email = jinja.Str(op.Value("email"))
		case exists:
			email = strOr(user, "email", "")
		default:
			email = strOr(op, "email", "")
		}
		existingGroups, _ := user.Value("groups").([]any)
		opGroups, _ := op.Value("groups").([]any)
		var groups []any
		switch strOr(op, "groups_action", "") {
		case "replace":
			groups = opGroups
		case "add":
			seen := map[string]bool{}
			for _, g := range append(append([]any{}, existingGroups...), opGroups...) {
				if s := jinja.Str(g); !seen[s] {
					seen[s] = true
					groups = append(groups, g)
				}
			}
		case "delete":
			groups = []any{}
		default:
			groups = existingGroups
		}
		if groups == nil {
			groups = []any{}
		}
		updated := pyyaml.NewMap()
		updated.Set("displayname", strings.TrimSpace(display))
		updated.Set("password", strings.TrimSpace(password))
		updated.Set("email", strings.TrimSpace(email))
		updated.Set("groups", groups)
		out.Set(k, updated)
	})
	return out
}

// autheliaUsersApply transcribes users_apply.yml (aut-users): the operations
// file read, the users file backed up beside the playbook, the operations
// applied, the file written, the log reader's ACL put back.
func autheliaUsersApply(b *Builder) []engine.Step {
	opsFile := b.S("{{ authelia_users_ops_file | default('') }}")
	usersPath := b.S("{{ authelia_users_host_path }}")
	cache := b.S("{{ authelia_cache_dir | default(playbook_dir + '/cache/authelia-users') }}")
	host := b.S("{{ inventory_hostname }}")
	reader := b.S("{{ authelia_log_reader_user | default('') }}")
	var ops, users *pyyaml.Map
	var current []byte
	return []engine.Step{
		assertStep("Authelia | users_apply | ensure ops file defined", func(*engine.Run) bool { return opsFile != "" },
			"authelia_users_ops_file (the file of operations) is not set."),
		fact("Authelia | users_apply | load ops from controller", nil, func() error {
			raw, err := os.ReadFile(opsFile)
			if err != nil {
				return err
			}
			doc, err := pyyaml.Load(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", opsFile, err)
			}
			ops = mapOf(mapOf(doc).Value("authelia_users_ops"))
			return nil
		}),
		fact("Authelia | users_apply | set ops var", nil, func() error { return nil }),
		assertStep("Authelia | users_apply | fail if no ops", func(*engine.Run) bool { return ops != nil && ops.Len() > 0 },
			"authelia_users_ops holds no operations."),
		assertStep("Authelia | users_apply | fail if users file missing", func(*engine.Run) bool { return b.Exists(usersPath, false) },
			usersPath+" not found. Run the ordinary deploy (config) first."),
		fact("Authelia | users_apply | slurp current users file", nil, func() error {
			raw, err := os.ReadFile(b.Sys.Path(usersPath))
			current = raw
			return err
		}),
		{Name: "Authelia | users_apply | ensure local backup dir", Resource: &engine.Dir{Path: cache, Mode: 0o700}},
		{Name: "Authelia | users_apply | save backup to controller", Build: func(*engine.Run) (engine.Resource, error) {
			return &engine.File{Path: filepath.Join(cache, host+"-users_database.before.yml"), Content: current, Mode: 0o644}, nil
		}},
		fact("Authelia | users_apply | parse current users yaml", nil, func() error {
			doc, err := pyyaml.Load(current)
			if err != nil {
				return err
			}
			users = mapOf(mapOf(doc).Value("users"))
			return nil
		}),
		fact("Authelia | users_apply | extract users dict", nil, func() error { return nil }),
		fact("Authelia | users_apply | init working dict", nil, func() error { return nil }),
		fact("Authelia | users_apply | delete users by ops", nil, func() error { return nil }),
		fact("Authelia | users_apply | add/replace users by ops", nil, func() error {
			users = applyUserOps(users, ops)
			return nil
		}),
		fact("Authelia | users_apply | build new yaml content", nil, func() error { return nil }),
		{Name: "Authelia | users_apply | write updated users file", Register: "authelia_users_write",
			Build: func(*engine.Run) (engine.Resource, error) {
				out, err := b.Set.RenderLocal("{{ {'users': users} | to_nice_yaml(indent=2) }}\n", map[string]any{"users": users})
				if err != nil {
					return nil, err
				}
				return &engine.File{Path: usersPath, Content: []byte(out), Owner: "authelia", Group: "authelia", Mode: 0o640}, nil
			}},
		{Name: "Authelia | users_apply | restore read ACL for log reader", When: func(*engine.Run) bool { return reader != "" },
			Resource: &engine.ACL{Path: usersPath, User: reader, Perms: "r"}},
		{Name: "Authelia | users_apply | fetch updated file to controller", When: Changed("authelia_users_write"),
			Build: func(*engine.Run) (engine.Resource, error) {
				raw, err := os.ReadFile(b.Sys.Path(usersPath))
				if err != nil && b.Sys.Path(usersPath) != "" {
					return nil, err
				}
				return &engine.File{Path: filepath.Join(cache, host+"-users_database.after.yml"), Content: raw, Mode: 0o644}, nil
			}},
	}
}

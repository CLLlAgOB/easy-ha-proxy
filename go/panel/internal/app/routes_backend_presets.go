package app

// Port of routes_backend_presets.py.

import (
	"fmt"
	"net/http"
	"strings"
)

// FormList is request.form.getlist(name).
func (c *Ctx) FormList(name string) []string {
	c.Form(name)
	return c.R.PostForm[name]
}

func (c *Ctx) formPreset() *Map {
	hosts := c.FormList("server_host")
	roles := c.FormList("server_role")
	weights := c.FormList("server_weight")
	notes := c.FormList("server_note")
	servers := []any{}
	for i, host := range hosts {
		if i >= maxServers+4 {
			break
		}
		role, weight, note := "primary", "", ""
		if i < len(roles) {
			role = roles[i]
		}
		if i < len(weights) {
			weight = strings.TrimSpace(weights[i])
		}
		if i < len(notes) {
			note = notes[i]
		}
		servers = append(servers, newMap("host", strings.TrimSpace(host), "role", role, "weight", weight, "note", note))
	}
	return newMap("name", c.FormStrip("name"), "servers", servers)
}

func (a *App) registerBackendPresetRoutes() {
	a.Handle("routes.backend_presets_page", func(c *Ctx) error {
		var errMsg, formPreset, originalName, revision any
		op := c.op()
		if c.R.Method == http.MethodPost {
			action := strings.TrimSpace(orStr(orValue(c.FormStr("action"), "save")))
			if action == "delete" {
				name := c.FormStrip("name")
				ok, msg := DeletePreset(op, name)
				c.RecordRequest("backend_set.delete", AuditEntry{ObjectType: "backend_set", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, msg)})
				if ok {
					c.Flash(msg, "success")
					return c.Redirect(c.URLFor("routes.backend_presets_page"), 302)
				}
				errMsg = msg
			} else {
				orig := c.FormStrip("original_name")
				originalName = noneIfEmpty(orig)
				rev := c.FormStrip("revision")
				revision = noneIfEmpty(rev)
				fp := c.formPreset()
				formPreset = fp
				ok, msg := SavePreset(op, fp, orig, rev)
				summary := ""
				if ok {
					var parts []string
					for _, s := range fp.Value("servers").([]any) {
						sm := s.(*Map)
						if pyStr(sm.Value("host")) != "" {
							parts = append(parts, fmt.Sprintf("%s (%s)", pyStr(sm.Value("host")), pyStr(sm.Value("role"))))
						}
					}
					summary = truncRunes(strings.Join(parts, ", "), 500)
				}
				act := "backend_set.create"
				if orig != "" {
					act = "backend_set.update"
				}
				c.RecordRequest(act, AuditEntry{ObjectType: "backend_set", ObjectID: pyStr(fp.Value("name")), Result: recordResult(ok), Summary: summary, Detail: detailIfFailed(ok, msg)})
				if ok {
					c.Flash(msg, "success")
					return c.Redirect(c.URLFor("routes.backend_presets_page"), 302)
				}
				errMsg = msg
			}
		}
		presets, err := loadPresets()
		if err != nil {
			return err
		}
		if c.R.Method == http.MethodGet {
			orig := strings.TrimSpace(c.QueryStr("edit"))
			originalName = noneIfEmpty(orig)
			if orig != "" {
				if p := findPreset(presets, orig); p == nil {
					errMsg = fmt.Sprintf("Backend set %s was not found", pyRepr(orig))
					originalName = nil
				} else {
					formPreset = p
					revision = EntryRevision(p)
				}
			}
		}
		used, err := PresetUsage(nil, nil, nil, presets, true)
		if err != nil {
			return err
		}
		if formPreset == nil {
			formPreset = newMap("name", "", "servers", []any{})
		}
		presetList := make([]any, len(presets))
		for i, p := range presets {
			presetList[i] = p
		}
		return c.Render("backend_presets.html", map[string]any{"presets": presetList, "used": used, "error": errMsg,
			"form_preset": formPreset, "original_name": originalName, "revision": revision, "max_servers": int64(maxServers)})
	})
}

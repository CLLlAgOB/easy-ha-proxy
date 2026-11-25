package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// staticVersion is _static_version: sha256("size:mtime_ns")[:12] of a regular file.
func (a *App) staticVersion(filename string) string {
	a.staticMu.Lock()
	defer a.staticMu.Unlock()
	if v, ok := a.staticVersions[filename]; ok {
		return v
	}
	if a.Cfg.StaticDir == "" {
		return ""
	}
	info, err := os.Stat(filepath.Join(a.Cfg.StaticDir, filepath.FromSlash(filename)))
	if err != nil {
		return ""
	}
	if !info.Mode().IsRegular() {
		a.staticVersions[filename] = ""
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())))
	v := hex.EncodeToString(sum[:])[:12]
	a.staticVersions[filename] = v
	return v
}

// URLFor is flask.url_for for this request ("." names are blueprint-relative).
func (c *Ctx) URLFor(endpoint string, values ...any) string {
	kw := pyyaml.NewMap()
	for i := 0; i+1 < len(values); i += 2 {
		kw.Set(values[i], values[i+1])
	}
	u, err := c.urlFor(endpoint, kw)
	if err != nil {
		panic(err)
	}
	return u
}

func (c *Ctx) urlFor(endpoint string, kw *pyyaml.Map) (string, error) {
	if strings.HasPrefix(endpoint, ".") {
		bp := ""
		if i := strings.LastIndex(c.Endpoint, "."); i >= 0 {
			bp = c.Endpoint[:i]
		}
		if bp != "" {
			endpoint = bp + endpoint
		} else {
			endpoint = endpoint[1:]
		}
	}
	argNames := map[string]bool{}
	for _, n := range c.App.Router.ArgNames(endpoint) {
		argNames[n] = true
	}
	path := map[string]string{}
	var query []QueryValue
	anchor := ""
	hasV := false
	kw.Each(func(k, v any) {
		key := jinja.Str(k)
		switch key {
		case "_anchor":
			anchor = jinja.Str(v)
			return
		case "_external", "_scheme", "_method":
			return
		}
		if argNames[key] {
			path[key] = jinja.Str(v)
			return
		}
		if v == nil {
			return
		}
		if key == "v" {
			hasV = true
		}
		if items, ok := v.([]any); ok {
			for _, it := range items {
				query = append(query, QueryValue{Key: key, Value: jinja.Str(it)})
			}
			return
		}
		query = append(query, QueryValue{Key: key, Value: jinja.Str(v)})
	})
	if endpoint == "static" && !hasV {
		if ver := c.App.staticVersion(path["filename"]); ver != "" {
			query = append(query, QueryValue{Key: "v", Value: ver})
		}
	}
	u, ok := c.App.Router.Build(endpoint, path, query)
	if !ok {
		return "", fmt.Errorf("Could not build url for endpoint %q", endpoint)
	}
	if anchor != "" {
		u += "#" + quotePath(anchor)
	}
	return u, nil
}

// serverTime is server_time.context().
func (a *App) serverTime() *pyyaml.Map {
	name := os.Getenv("EHP_SERVER_TIMEZONE")
	if name == "" {
		name = os.Getenv("TZ")
	}
	loc, err := time.LoadLocation(name)
	if name == "" || err != nil {
		name, loc = "UTC", time.UTC
	}
	now := time.Now().In(loc)
	abbr, off := now.Zone()
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	m := pyyaml.NewMap()
	m.Set("zone", name)
	m.Set("abbreviation", abbr)
	m.Set("offset", fmt.Sprintf("UTC%s%02d:%02d", sign, off/3600, (off%3600)/60))
	m.Set("now", float64(now.UnixNano()/1000)/1000)
	return m
}

func (c *Ctx) requestObj() jinja.Obj {
	args := pyyaml.NewMap()
	q := c.R.URL.Query()
	for _, kv := range strings.Split(c.R.URL.RawQuery, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k == "" {
			continue
		}
		key := q.Get(k)
		_ = key
	}
	for k, vals := range q {
		if len(vals) > 0 {
			args.Set(k, vals[0])
		}
	}
	var endpoint any
	if c.Endpoint != "" {
		endpoint = c.Endpoint
	}
	blueprint := any(nil)
	if i := strings.LastIndex(c.Endpoint, "."); i >= 0 {
		blueprint = c.Endpoint[:i]
	}
	return jinja.Obj{
		"endpoint":  endpoint,
		"blueprint": blueprint,
		"path":      c.R.URL.Path,
		"full_path": c.R.URL.Path + "?" + c.R.URL.RawQuery,
		"method":    c.R.Method,
		"args":      args,
		"view_args": c.Args,
	}
}

func (c *Ctx) gObj() jinja.Obj {
	groups := make([]any, 0, len(c.ID.Groups))
	for gname := range c.ID.Groups {
		groups = append(groups, gname)
	}
	return jinja.Obj{
		"remote_user":   c.ID.User,
		"remote_groups": groups,
		"is_superadmin": c.ID.IsSuperadmin,
		"csp_nonce":     c.ID.CSPNonce,
		"language":      c.Lang,
		"access_portal": c.ID.AccessPortal,
	}
}

// Render is flask.render_template with the app's context processors.
func (c *Ctx) Render(name string, vars map[string]any) error {
	html, err := c.RenderString(name, vars)
	if err != nil {
		return err
	}
	return c.HTML(200, html)
}

// RenderString renders a template to a string.
func (c *Ctx) RenderString(name string, vars map[string]any) (string, error) {
	ctx := map[string]any{}
	langs := []any{}
	if c.App.Catalog != nil {
		for _, l := range c.App.Catalog.SupportedLanguages() {
			m := pyyaml.NewMap()
			m.Set("code", l.Code)
			m.Set("label", l.Label)
			langs = append(langs, m)
		}
	}
	i18nCfg := pyyaml.NewMap()
	i18nCfg.Set("language", c.Lang)
	i18nCfg.Set("languages", langs)
	messagesURL := ""
	if c.App.Catalog != nil {
		messagesURL = c.App.Catalog.MessagesURL(c.Lang)
	}
	ctx["request"] = c.requestObj()
	ctx["g"] = c.gObj()
	ctx["session"] = jinja.Obj{}
	ctx["config"] = jinja.Obj{}
	ctx["url_for"] = jinja.Func(func(args []any, kwargs *jinja.Map) (any, error) {
		if len(args) == 0 {
			return nil, fmt.Errorf("url_for needs an endpoint")
		}
		if kwargs == nil {
			kwargs = pyyaml.NewMap()
		}
		return c.urlFor(jinja.Str(args[0]), kwargs)
	})
	ctx["get_flashed_messages"] = jinja.Func(func(args []any, kwargs *jinja.Map) (any, error) {
		withCategories := false
		if len(args) > 0 {
			withCategories = jinja.Truthy(args[0])
		}
		var filter []any
		if kwargs != nil {
			if v, ok := kwargs.Get("with_categories"); ok {
				withCategories = jinja.Truthy(v)
			}
			if v, ok := kwargs.Get("category_filter"); ok {
				filter, _ = v.([]any)
			}
		}
		out := []any{}
		for _, f := range c.popFlashes() {
			if len(filter) > 0 {
				keep := false
				for _, cat := range filter {
					if jinja.Str(cat) == f.Category {
						keep = true
					}
				}
				if !keep {
					continue
				}
			}
			if withCategories {
				out = append(out, jinja.Tuple{f.Category, f.Message})
			} else {
				out = append(out, f.Message)
			}
		}
		return out, nil
	})
	ctx["csrf_token"] = jinja.Func(func([]any, *jinja.Map) (any, error) { return c.ID.CSRFToken, nil })
	ctx["server_time"] = c.App.serverTime()
	ctx["csp_nonce"] = c.ID.CSPNonce
	ctx["updates_badge"] = c.App.updatesBadge(c)
	ctx["build"] = c.App.buildFooter(c)
	ctx["_"] = jinja.Func(func(args []any, kwargs *jinja.Map) (any, error) {
		if len(args) == 0 {
			return "", nil
		}
		return c.T(jinja.Str(args[0])), nil
	})
	ctx["backend_presets_list"] = jinja.Func(func([]any, *jinja.Map) (any, error) {
		presets, err := loadPresets()
		out := make([]any, len(presets))
		for i, p := range presets {
			out[i] = p
		}
		return out, err
	})
	ctx["current_language"] = c.Lang
	ctx["supported_languages"] = langs
	ctx["i18n_config"] = i18nCfg
	ctx["i18n_messages_url"] = messagesURL
	for k, v := range vars {
		ctx[k] = v
	}
	return c.App.Env.Render(name, ctx)
}

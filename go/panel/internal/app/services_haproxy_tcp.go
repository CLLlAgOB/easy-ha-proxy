package app

// Port of services_haproxy_tcp.py and routes_haproxy_tcp.py.

import (
	"fmt"
	"log"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func tcpProxiesOf(data *Map) any {
	p := data.Value("tcp_proxies")
	if p == nil {
		p = data.Value("tcp")
	}
	return p
}

// GetTCPProxiesList is get_tcp_proxies_list.
func GetTCPProxiesList() ([]any, error) {
	data, err := loadYAML(TCPYAML)
	if err != nil {
		return nil, err
	}
	list, ok := asList(tcpProxiesOf(data))
	if !ok {
		return []any{}, nil
	}
	return list, nil
}

func normalizeTCPEntry(rawV any) (bool, string, *Map) {
	raw, ok := asMap(rawV)
	if !ok {
		return false, "Invalid TCP proxy format (expected a JSON object)", nil
	}
	out := copyMap(raw)
	name, err := validateIdentifier(out.Value("name"), "name")
	if err != nil {
		return false, err.Error(), nil
	}
	out.Set("name", name)
	bindIP, err := validateHost(orValue(out.Value("bind_ip"), "0.0.0.0"), "bind_ip")
	if err != nil {
		return false, err.Error(), nil
	}
	out.Set("bind_ip", bindIP)
	port, err := validatePort(out.Value("bind_port"), "bind_port")
	if err != nil {
		return false, err.Error(), nil
	}
	out.Set("bind_port", port)
	getDef := func(key string, def any) any {
		if v, has := out.Get(key); has {
			return v
		}
		return def
	}
	out.Set("zero_trust", truthy(getDef("zero_trust", false)))
	out.Set("ban_check", truthy(getDef("ban_check", true)))
	balance := orStr(out.Value("balance"))
	if balance == "" {
		balance = "source"
	}
	if !balanceValues[balance] {
		return false, "Unsupported balance algorithm", nil
	}
	out.Set("balance", balance)
	if inter := out.Value("inter"); inter != nil {
		s := strip(inter)
		if s != "" {
			if !intervalRe.MatchString(s) {
				return false, "inter must look like 500ms, 5s, 2m, or 1h", nil
			}
			out.Set("inter", s)
		} else {
			out.Delete("inter")
		}
	}
	out.Set("ssl_check", truthy(getDef("ssl_check", false)))
	presets, err := loadPresets()
	if err != nil {
		return false, err.Error(), nil
	}
	if err := ApplyPresetToTCP(out, presets); err != nil {
		return false, err.Error(), nil
	}
	var cleaned []any
	if servers, ok := asList(out.Value("servers")); ok {
		for i, s := range servers {
			idx := i + 1
			srv, ok := asMap(s)
			if !ok {
				continue
			}
			host := orStr(srv.Value("host"))
			if host == "" {
				continue
			}
			host, err := validateHost(host, fmt.Sprintf("servers[%d].host", idx))
			if err != nil {
				return false, err.Error(), nil
			}
			p, err := validatePort(srv.Value("port"), fmt.Sprintf("servers[%d].port", idx))
			if err != nil {
				return false, err.Error(), nil
			}
			sname := orStr(srv.Value("name"))
			if sname == "" {
				sname = fmt.Sprintf("srv%d", idx)
			}
			sname, err = validateIdentifier(sname, fmt.Sprintf("servers[%d].name", idx))
			if err != nil {
				return false, err.Error(), nil
			}
			so := newMap("name", sname, "host", host, "port", p)
			if truthy(srv.Value("backup")) {
				so.Set("backup", true)
			}
			cleaned = append(cleaned, so)
		}
	}
	if len(cleaned) > 0 {
		out.Set("servers", cleaned)
	} else {
		out.Delete("servers")
	}
	bh := orStr(out.Value("backend_host"))
	bp := out.Value("backend_port")
	if bh != "" && bp != nil {
		h, err := validateHost(bh, "backend_host")
		if err != nil {
			return false, err.Error(), nil
		}
		p, err := validatePort(bp, "backend_port")
		if err != nil {
			return false, err.Error(), nil
		}
		out.Set("backend_host", h)
		out.Set("backend_port", p)
	} else {
		out.Delete("backend_host")
		out.Delete("backend_port")
	}
	if l, ok := asList(out.Value("servers")); ok && len(l) > 1 {
		out.Delete("backend_host")
		out.Delete("backend_port")
	}
	return true, "", out
}

// TCPRevision is tcp_revision ("" when absent).
func TCPRevision(name string) string {
	list, _ := GetTCPProxiesList()
	for _, p := range list {
		if m, ok := asMap(p); ok && pyEqual(m.Value("name"), name) {
			return EntryRevision(m)
		}
	}
	return ""
}

func without(list []any, idx int) []any {
	out := make([]any, 0, len(list))
	out = append(out, list[:idx]...)
	return append(out, list[idx+1:]...)
}

// SaveTCPFromJSON is save_tcp_from_json; a StaleEntry error when the
// revision no longer matches.
func SaveTCPFromJSON(op *Op, tcp any, originalName string, expectedRevision any) (bool, string, error) {
	release, err := op.Lock("tcp")
	if err != nil {
		return false, "", err
	}
	defer release()
	ok, msg, out := normalizeTCPEntry(tcp)
	if !ok || out == nil {
		return false, msg, nil
	}
	data, err := loadYAML(TCPYAML)
	if err != nil {
		return false, "", err
	}
	proxies, ok := asList(tcpProxiesOf(data))
	if !ok {
		proxies = []any{}
	}
	if originalName != "" {
		idx := -1
		for i, t := range proxies {
			if pyEqual(get(t, "name"), originalName) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return false, fmt.Sprintf("TCP proxy with name=%s not found", pyRepr(originalName)), nil
		}
		if err := CheckEntryRevision(proxies[idx], expectedRevision, "This TCP proxy"); err != nil {
			return false, "", err
		}
		if c := TCPIdentityConflict(out, without(proxies, idx)); c != "" {
			return false, c, nil
		}
		proxies[idx] = out
	} else {
		if c := TCPIdentityConflict(out, proxies); c != "" {
			return false, c, nil
		}
		proxies = append(proxies, out)
	}
	data.Set("tcp_proxies", proxies)
	ok, msg = UpdateYAMLFile(op, "tcp", dumpYAML(data))
	return ok, msg, nil
}

// DeleteTCPProxy is delete_tcp_proxy.
func DeleteTCPProxy(op *Op, name string) (bool, string) {
	release, err := op.Lock("tcp")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	data, err := loadYAML(TCPYAML)
	if err != nil {
		return false, err.Error()
	}
	proxies, ok := asList(tcpProxiesOf(data))
	if !ok {
		return false, "Invalid tcp.yml structure (expected a tcp_proxies/tcp list)"
	}
	newList := []any{}
	var removed any
	for _, t := range proxies {
		if removed == nil && pyEqual(get(t, "name"), name) {
			removed = t
			continue
		}
		newList = append(newList, t)
	}
	if removed == nil {
		return false, fmt.Sprintf("TCP proxy with name=%s not found", pyRepr(name))
	}
	data.Set("tcp_proxies", newList)
	content := dumpYAML(data)
	kept, err := TrashKeep(op, "tcp", name, removed, nil)
	if err != nil {
		return false, "The entry could not be kept in the trash, so nothing was deleted: " + err.Error()
	}
	ok, msg := UpdateYAMLFile(op, "tcp", content)
	if !ok {
		if TrashSettle(kept, tcpInSource(name)) {
			return false, msg + " The TCP proxy is gone from tcp.yml all the same; it was kept in the trash."
		}
		return ok, msg
	}
	TrashCommit(kept)
	return ok, msg + " The TCP proxy was moved to the trash and can be restored there."
}

func tcpInSource(name string) bool {
	data, err := loadYAML(TCPYAML)
	if err != nil {
		return false
	}
	list, ok := asList(tcpProxiesOf(data))
	if !ok {
		return false
	}
	for _, p := range list {
		if m, ok := asMap(p); ok && pyEqual(m.Value("name"), name) {
			return true
		}
	}
	return false
}

// RestoreTCPProxy is restore_tcp_proxy.
func RestoreTCPProxy(op *Op, entry *Map, _ *Map) (bool, string, *Map) {
	release, err := op.Lock("tcp")
	if err != nil {
		return false, err.Error(), pyyaml.NewMap()
	}
	defer release()
	data, err := loadYAML(TCPYAML)
	if err != nil {
		return false, err.Error(), pyyaml.NewMap()
	}
	p := tcpProxiesOf(data)
	if p == nil {
		p = []any{}
	}
	proxies, ok := asList(p)
	if !ok {
		return false, "Invalid tcp.yml structure (expected a tcp_proxies/tcp list)", pyyaml.NewMap()
	}
	if c := TCPIdentityConflict(entry, proxies); c != "" {
		return false, c, pyyaml.NewMap()
	}
	proxies = append(proxies, entry)
	data.Set("tcp_proxies", proxies)
	ok, msg := UpdateYAMLFile(op, "tcp", dumpYAML(data))
	return ok, msg, pyyaml.NewMap()
}

func storedTCP(name string) any {
	if name == "" {
		return pyyaml.NewMap()
	}
	list, _ := GetTCPProxiesList()
	for _, p := range list {
		if m, ok := asMap(p); ok && pyEqual(m.Value("name"), name) {
			return m
		}
	}
	return pyyaml.NewMap()
}

func (a *App) registerTCPRoutes() {
	trashRestorers["tcp"] = RestoreTCPProxy
	a.Handle("routes.haproxy_tcp_save", func(c *Ctx) error {
		payloadV, err := c.JSONBody()
		if err != nil {
			return c.JSON(400, newMap("ok", false, "error", "Invalid JSON: "+err.Error()))
		}
		payload, ok := asMap(payloadV)
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "Expected a JSON object"))
		}
		tcp := payload.Value("tcp")
		orig := orStr(payload.Value("original_name"))
		if _, ok := asMap(tcp); !ok {
			return c.JSON(400, newMap("ok", false, "error", "The 'tcp' field must be an object"))
		}
		name := orStr(orValue(get(tcp, "name"), noneIfEmpty(orig)))
		expected := orValue(payload.Value("revision"), nil)
		op := c.op()
		var before any
		var okSave bool
		var msg, revision string
		err = func() error {
			release, lerr := op.Lock("tcp")
			if lerr != nil {
				return lerr
			}
			defer release()
			before = storedTCP(orig)
			var serr error
			okSave, msg, serr = SaveTCPFromJSON(op, tcp, orig, expected)
			if serr == nil && okSave {
				revision = TCPRevision(name)
			}
			return serr
		}()
		if err != nil && !okSave && before == nil {
			if _, stale := err.(*StaleEntry); !stale {
				// Lock acquisition error before reading storedTCP.
				return err
			}
		}
		act := "tcp_proxy.create"
		if truthy(before) {
			act = "tcp_proxy.update"
		}
		if err != nil {
			if se, stale := err.(*StaleEntry); stale {
				c.RecordRequest("tcp_proxy.update", AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: auditResultFailure, Detail: truncRunes(se.Msg, 500)})
				return c.JSON(409, newMap("ok", false, "conflict", true, "error", se.Msg))
			}
			log.Printf("Unhandled exception in route: %v", err)
			c.RecordRequest(act, AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: auditResultFailure, Detail: truncRunes(err.Error(), 500)})
			return c.JSON(500, newMap("ok", false, "error", "Internal error while saving TCP proxy"))
		}
		res, summary, detail := auditResultFailure, "", truncRunes(msg, 500)
		if okSave {
			res, summary, detail = auditResultSuccess, AuditSummarize(before, tcp), ""
		}
		c.RecordRequest(act, AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: res, Summary: summary, Detail: detail})
		answer := newMap("ok", okSave, okKey(okSave), msg)
		if revision != "" {
			answer.Set("revision", revision)
		}
		return c.JSON(200, answer)
	})
	a.Handle("routes.haproxy_tcp_delete", func(c *Ctx) error {
		name := c.Args["name"]
		ok, msg := DeleteTCPProxy(c.op(), name)
		res, detail := auditResultFailure, truncRunes(msg, 500)
		if ok {
			res, detail = auditResultSuccess, ""
		}
		c.RecordRequest("tcp_proxy.delete", AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: res, Detail: detail})
		return c.JSON(200, newMap("ok", ok, okKey(ok), msg))
	})
}

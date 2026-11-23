package app

// Port of routes_trash.py.

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

func (c *Ctx) trashDenied(action, objectID string) error {
	c.RecordRequest(action, AuditEntry{ObjectType: "trash", ObjectID: objectID, Result: auditResultDenied, Detail: "superadmin required"})
	return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
}

func certdTrashItems() *Map {
	payload, err := CertdDNS("trash", newMap())
	if err != nil {
		log.Printf("certd unavailable: %v", err)
		return newMap("items", []any{}, "error", "The certificate service does not answer", "keep_days", nil)
	}
	if !truthy(payload.Value("ok")) {
		return newMap("items", []any{}, "error", pyStr(orValue(payload.Value("error"), "unknown error")), "keep_days", nil)
	}
	items := []any{}
	list, _ := asList(orValue(payload.Value("items"), []any{}))
	for _, it := range list {
		item, ok := asMap(it)
		if !ok {
			continue
		}
		details, ok := asMap(item.Value("details"))
		if !ok {
			details = newMap()
		}
		detail := ""
		shown := orValue(details.Value("domains"), []any{})
		if l, ok := asList(shown); ok {
			var parts []string
			for _, n := range l {
				if truthy(n) {
					parts = append(parts, pyStr(n))
				}
			}
			detail = strings.Join(parts, ", ")
		}
		for _, k := range []string{"provider", "lineage", "host"} {
			if detail == "" && truthy(details.Value(k)) {
				detail = pyStr(details.Value(k))
			}
		}
		items = append(items, newMap("source", "certd", "id", strOrEmpty(item.Value("id")), "kind", strOrEmpty(item.Value("kind")),
			"name", strOrEmpty(item.Value("name")), "detail", detail, "not_after", orValue(details.Value("not_after"), ""),
			"deleted_at", pyIntOr0(orValue(item.Value("deleted_at"), int64(0))), "deleted_by", strOrEmpty(item.Value("deleted_by")),
			"expires_at", pyIntOr0(orValue(item.Value("expires_at"), int64(0)))))
	}
	var keep any
	if n, ok := payload.Value("keep_days").(int64); ok {
		keep = n
	}
	return newMap("items", items, "error", "", "keep_days", keep)
}

func (c *Ctx) jsonBodyMap() *Map {
	if m, ok := asMap(c.SilentJSON()); ok {
		return m
	}
	return newMap()
}

func (a *App) registerTrashRoutes() {
	a.Handle("routes.api_trash_list", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		items, keep, err := TrashListWithTerm()
		panelErr := ""
		if err != nil {
			log.Printf("panel trash unreadable: %v", err)
			items, keep, panelErr = []any{}, TrashKeepDays(), "The trash of sites and forwards cannot be read"
		}
		certd := certdTrashItems()
		merged := append(append([]any{}, items...), certd.Value("items").([]any)...)
		sort.SliceStable(merged, func(i, j int) bool {
			a, b := merged[i].(*Map), merged[j].(*Map)
			ad, bd := pyIntOr0(a.Value("deleted_at")), pyIntOr0(b.Value("deleted_at"))
			if ad != bd {
				return ad > bd
			}
			return pyStr(a.Value("id")) > pyStr(b.Value("id"))
		})
		errs := []any{}
		for _, m := range []string{panelErr, pyStr(certd.Value("error"))} {
			if m != "" {
				errs = append(errs, m)
			}
		}
		return c.JSON(200, newMap("ok", true, "items", merged, "keep_days", keep, "certd_keep_days", certd.Value("keep_days"), "errors", errs))
	})
	a.Handle("routes.api_trash_settings", func(c *Ctx) error {
		payload := c.jsonBodyMap()
		if !c.Superadmin() {
			return c.trashDenied("trash.settings", "settings")
		}
		days, err := NormalizeKeepDays(payload.Value("keep_days"))
		if err != nil {
			return c.JSON(400, newMap("ok", false, "error", err.Error()))
		}
		release, err := TrashSettingsLock()
		if err != nil {
			log.Printf("trash settings not saved: %v", err)
			return c.JSON(500, newMap("ok", false, "error", "The trash settings could not be saved"))
		}
		errText := ""
		days, err = SetTrashKeepDays(days)
		if err == nil {
			if answer, cerr := CertdDNSTimeout("trash/settings", newMap("keep_days", days), 15); cerr != nil {
				log.Printf("certd unavailable: %v", cerr)
				errText = "The certificate service does not answer"
			} else if !truthy(answer.Value("ok")) {
				errText = pyStr(orValue(answer.Value("error"), "certd refused"))
			}
		}
		release()
		if err != nil {
			if _, isTrash := err.(*TrashError); isTrash {
				return c.JSON(400, newMap("ok", false, "error", err.Error()))
			}
			return c.JSON(500, newMap("ok", false, "error", "The trash settings could not be saved"))
		}
		summary := fmt.Sprintf("kept for %d days", days)
		if days == 0 {
			summary = "kept until emptied"
		}
		res := auditResultSuccess
		if errText != "" {
			res = auditResultFailure
		}
		c.RecordRequest("trash.settings", AuditEntry{ObjectType: "trash", ObjectID: "settings", Result: res, Summary: summary, Detail: truncRunes(errText, 500)})
		if errText != "" {
			return c.JSON(502, newMap("ok", false, "keep_days", days, "error", "Saved for sites and forwards, but not for certificates: "+errText, "partial", true))
		}
		return c.JSON(200, newMap("ok", true, "keep_days", days))
	})
	target := func(c *Ctx) (string, string) {
		p := c.jsonBodyMap()
		return strOrEmpty(p.Value("source")), strOrEmpty(p.Value("id"))
	}
	validSource := func(s string) bool { return s == "panel" || s == "certd" }
	a.Handle("routes.api_trash_restore", func(c *Ctx) error {
		source, id := target(c)
		if !c.Superadmin() {
			return c.trashDenied("trash.restore", id)
		}
		if !validSource(source) || id == "" {
			return c.JSON(400, newMap("ok", false, "error", "source and id are required"))
		}
		var result *Map
		var err error
		if source == "panel" {
			result, err = TrashRestore(c.op(), id)
		} else {
			result, err = CertdDNS("trash/restore", newMap("id", id))
		}
		if err != nil {
			c.RecordRequest("trash.restore", AuditEntry{ObjectType: "trash", ObjectID: id, Result: auditResultFailure, Detail: truncRunes(err.Error(), 500)})
			if _, isTrash := err.(*TrashError); isTrash {
				return c.JSON(404, newMap("ok", false, "error", err.Error()))
			}
			if _, unavailable := err.(*CertdUnavailable); unavailable {
				return c.JSON(503, newMap("ok", false, "unavailable", true, "error", err.Error()))
			}
			return err
		}
		ok := truthy(result.Value("ok"))
		c.RecordRequest("trash.restore", AuditEntry{ObjectType: pyStr(orValue(result.Value("kind"), "trash")), ObjectID: pyStr(orValue(result.Value("name"), id)),
			Result: recordResult(ok), Detail: detailIfFailed(ok, strOrEmpty(result.Value("error")))})
		if !ok {
			return c.JSON(409, result)
		}
		kind := result.Value("kind")
		if (source == "panel" && (kind == "site" || kind == "tcp")) || (source == "certd" && kind == "haproxy_cert") {
			result.Set("apply_needed", true)
		}
		return c.JSON(200, result)
	})
	a.Handle("routes.api_trash_delete", func(c *Ctx) error {
		source, id := target(c)
		if !c.Superadmin() {
			return c.trashDenied("trash.delete", id)
		}
		if !validSource(source) || id == "" {
			return c.JSON(400, newMap("ok", false, "error", "source and id are required"))
		}
		var result *Map
		var err error
		if source == "panel" {
			result, err = TrashRemove(id)
		} else {
			result, err = CertdDNS("trash/purge", newMap("id", id))
		}
		if err != nil {
			c.RecordRequest("trash.delete", AuditEntry{ObjectType: "trash", ObjectID: id, Result: auditResultFailure, Detail: truncRunes(err.Error(), 500)})
			if _, isTrash := err.(*TrashError); isTrash {
				return c.JSON(404, newMap("ok", false, "error", err.Error()))
			}
			if _, unavailable := err.(*CertdUnavailable); unavailable {
				return c.JSON(503, newMap("ok", false, "unavailable", true, "error", err.Error()))
			}
			return err
		}
		objType, objID := pyStr(orValue(result.Value("kind"), "trash")), pyStr(orValue(result.Value("name"), id))
		if !truthy(result.Value("ok")) {
			c.RecordRequest("trash.delete", AuditEntry{ObjectType: objType, ObjectID: objID, Result: auditResultFailure, Detail: truncRunes(strOrEmpty(result.Value("error")), 500)})
			return c.JSON(400, result)
		}
		c.RecordRequest("trash.delete", AuditEntry{ObjectType: objType, ObjectID: objID, Detail: "deleted for good from the trash"})
		return c.JSON(200, result)
	})
	a.Handle("routes.api_trash_empty", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.trashDenied("trash.empty", "")
		}
		var errs []string
		removed := int64(0)
		if n, failed, err := TrashEmptyDetailed(); err != nil {
			errs = append(errs, err.Error())
		} else {
			removed += int64(n)
			if len(failed) > 0 {
				errs = append(errs, fmt.Sprintf("%d items could not be deleted: %s", len(failed), strings.Join(failed, "; ")))
			}
		}
		if answer, err := CertdDNS("trash/purge", newMap("all", true)); err != nil {
			errs = append(errs, "certd unavailable: "+err.Error())
		} else {
			removed += pyIntOr0(orValue(answer.Value("removed"), int64(0)))
			if !truthy(answer.Value("ok")) {
				errs = append(errs, pyStr(orValue(answer.Value("error"), "certd refused")))
			}
		}
		detail := fmt.Sprintf("%d items deleted for good", removed)
		if len(errs) > 0 {
			detail += "; " + strings.Join(errs, "; ")
		}
		res, status := auditResultSuccess, 200
		if len(errs) > 0 {
			res, status = auditResultFailure, 502
		}
		c.RecordRequest("trash.empty", AuditEntry{ObjectType: "trash", ObjectID: "all", Result: res, Detail: truncRunes(detail, 500)})
		return c.JSON(status, newMap("ok", len(errs) == 0, "removed", removed, "error", strings.Join(errs, "; ")))
	})
}

// CertdDNSTimeout is _dns_request with an explicit timeout in seconds.
func CertdDNSTimeout(path string, payload *Map, seconds int) (*Map, error) {
	return certdSection(path, payload, secondsDuration(seconds))
}

func secondsDuration(s int) time.Duration { return time.Duration(s) * time.Second }

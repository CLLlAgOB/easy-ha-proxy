package app

// Port of routes_dns_providers.py and routes_cert_delivery.py. Stored
// credentials, private keys and pinned host keys go to certd and never come
// back: the daemon does not hand them out.

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"easy-ha-proxy/panel/internal/jinja"
)

const (
	dnsMaxCredentialLength = 4096
	deliveryMaxKeyLength   = 16384
)

// jsonPayload is "request.get_json(silent=True) or {}" for a view that then
// calls payload.get: a body that is JSON but not an object is a 500 there.
func (c *Ctx) jsonPayload() (*Map, error) {
	v := c.SilentJSON()
	if !truthy(v) {
		return newMap(), nil
	}
	if m, ok := asMap(v); ok {
		return m, nil
	}
	return nil, fmt.Errorf("AttributeError: %s object has no attribute 'get'", pyRepr(pyTypeName(v)))
}

func containsAny(list []any, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// lowerName is str(payload.get(key) or "").strip().lower().
func lowerName(payload *Map, key string) string { return strings.ToLower(orStr(payload.Value(key))) }

// certdFailure answers a CertdUnavailable with 503, as _unavailable does.
func (c *Ctx) certdFailure(err error) error {
	var down *CertdUnavailable
	if !errors.As(err, &down) {
		return err
	}
	log.Printf("certd unavailable: %s", down.Msg)
	return c.JSON(503, newMap("ok", false, "unavailable", true, "error", down.Msg))
}

func (c *Ctx) superadminDenied(action, objectType, objectID string) error {
	c.RecordRequest(action, AuditEntry{ObjectType: objectType, ObjectID: objectID, Result: auditResultDenied, Detail: "superadmin required"})
	return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
}

func (a *App) registerDNSDelivery() {
	a.Handle("routes.cert_delivery_page", staticPage("cert_delivery.html", map[string]any{
		"formats":    jinja.Tuple(strList("pfx", "pem-pair", "pem-combined")),
		"transports": jinja.Tuple(strList("sftp", "scp")),
	}))

	a.Handle("routes.api_dns_providers", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		result, err := CertdDNS("dns-providers", newMap())
		if err != nil {
			return c.certdFailure(err)
		}
		return c.JSON(200, result)
	})

	a.Handle("routes.api_dns_provider_save", func(c *Ctx) error {
		payload, err := c.jsonPayload()
		if err != nil {
			return err
		}
		name := lowerName(payload, "name")
		provider := lowerName(payload, "provider")
		if !c.Superadmin() {
			return c.superadminDenied("dns_provider.save", "dns_provider", name)
		}
		if !dnsProfileRe.MatchString(name) {
			return c.JSON(400, newMap("ok", false, "error", "the profile name may use a-z, 0-9 and dashes"))
		}
		if !containsAny(dnsProviders, provider) {
			return c.JSON(400, newMap("ok", false, "error", "unsupported provider"))
		}
		supplied, ok := asMap(payload.Value("credentials"))
		if !ok || supplied.Len() == 0 {
			return c.JSON(400, newMap("ok", false, "error", "credentials are required"))
		}
		credentials := newMap()
		var tooLong string
		supplied.Each(func(k, v any) {
			text := strOrEmpty(v)
			if text == "" || tooLong != "" {
				return
			}
			if pyLen(text) > dnsMaxCredentialLength {
				tooLong = pyStr(k)
				return
			}
			credentials.Set(pyStr(k), text)
		})
		if tooLong != "" {
			return c.JSON(400, newMap("ok", false, "error", tooLong+" is too long"))
		}
		if credentials.Len() == 0 {
			return c.JSON(400, newMap("ok", false, "error", "credentials are required"))
		}
		result, err := CertdDNS("dns-providers/save", newMap("name", name, "provider", provider, "credentials", credentials))
		if err != nil {
			var down *CertdUnavailable
			if errors.As(err, &down) {
				c.RecordRequest("dns_provider.save", AuditEntry{ObjectType: "dns_provider", ObjectID: name, Result: auditResultFailure, Detail: down.Msg})
			}
			return c.certdFailure(err)
		}
		if !truthy(result.Value("ok")) {
			c.RecordRequest("dns_provider.save", AuditEntry{ObjectType: "dns_provider", ObjectID: name, Result: auditResultFailure,
				Detail: strOrEmpty(result.Value("error"))})
			return c.JSON(400, result)
		}
		// The credential values are deliberately absent from the record.
		c.RecordRequest("dns_provider.save", AuditEntry{ObjectType: "dns_provider", ObjectID: name,
			Summary: "provider: " + provider + ", credentials: changed"})
		return c.JSON(200, result)
	})

	a.Handle("routes.api_dns_provider_delete", func(c *Ctx) error {
		payload, err := c.jsonPayload()
		if err != nil {
			return err
		}
		name := lowerName(payload, "name")
		if !c.Superadmin() {
			return c.superadminDenied("dns_provider.delete", "dns_provider", name)
		}
		if !dnsProfileRe.MatchString(name) {
			return c.JSON(400, newMap("ok", false, "error", "invalid profile name"))
		}
		result, err := CertdDNS("dns-providers/delete", newMap("name", name, "actor", c.User()))
		if err != nil {
			var down *CertdUnavailable
			if errors.As(err, &down) {
				c.RecordRequest("dns_provider.delete", AuditEntry{ObjectType: "dns_provider", ObjectID: name, Result: auditResultFailure, Detail: down.Msg})
			}
			return c.certdFailure(err)
		}
		if !truthy(result.Value("ok")) {
			return c.JSON(400, result)
		}
		c.RecordRequest("dns_provider.delete", AuditEntry{ObjectType: "dns_provider", ObjectID: name})
		return c.JSON(200, result)
	})

	a.Handle("routes.api_cert_delivery_list", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		payload, err := CertdDelivery("deliveries", newMap())
		if err != nil {
			return c.certdFailure(err)
		}
		// The lineages the page offers to choose from, in the same answer.
		available := []any{}
		if items, ok := CertdListAll().Value("letsencrypt").([]any); ok {
			for _, it := range items {
				item, ok := asMap(it)
				if !ok {
					log.Printf("cannot list certificates for the delivery page: %s object has no attribute 'get'", pyRepr(pyTypeName(it)))
					break
				}
				if name := orStr(item.Value("lineage")); name != "" {
					expires, has := item.Get("not_after")
					if !has {
						expires = ""
					}
					available = append(available, newMap("name", name, "expires", expires))
				}
			}
		}
		payload.Set("available", available)
		return c.JSON(200, payload)
	})

	a.Handle("routes.api_cert_delivery_save", func(c *Ctx) error {
		payload, err := c.jsonPayload()
		if err != nil {
			return err
		}
		name := lowerName(payload, "name")
		if !c.Superadmin() {
			return c.superadminDenied("cert_delivery.save", "cert_delivery", name)
		}
		// Only the obvious size guard here; certd validates everything else.
		for _, field := range []string{"private_key", "host_key"} {
			if pyLen(strOrEmpty(payload.Value(field))) > deliveryMaxKeyLength {
				return c.JSON(400, newMap("ok", false, "error", field+" is too long"))
			}
		}
		result, err := CertdDelivery("deliveries/save", payload)
		if err != nil {
			var down *CertdUnavailable
			if errors.As(err, &down) {
				c.RecordRequest("cert_delivery.save", AuditEntry{ObjectType: "cert_delivery", ObjectID: name, Result: auditResultFailure, Detail: down.Msg})
			}
			return c.certdFailure(err)
		}
		if !truthy(result.Value("ok")) {
			detail := ""
			if v, has := result.Get("error"); has {
				detail = pyStr(v)
			}
			c.RecordRequest("cert_delivery.save", AuditEntry{ObjectType: "cert_delivery", ObjectID: name, Result: auditResultFailure, Detail: detail})
			return c.JSON(400, result)
		}
		c.RecordRequest("cert_delivery.save", AuditEntry{ObjectType: "cert_delivery", ObjectID: name, After: result.Value("target"),
			Detail: "certificate delivery target saved"})
		return c.JSON(200, result)
	})

	a.Handle("routes.api_cert_delivery_delete", func(c *Ctx) error {
		payload, err := c.jsonPayload()
		if err != nil {
			return err
		}
		name := lowerName(payload, "name")
		if !c.Superadmin() {
			return c.superadminDenied("cert_delivery.delete", "cert_delivery", name)
		}
		result, err := CertdDelivery("deliveries/delete", newMap("name", name, "actor", c.User()))
		if err != nil {
			return c.certdFailure(err)
		}
		if !truthy(result.Value("ok")) {
			return c.JSON(400, result)
		}
		c.RecordRequest("cert_delivery.delete", AuditEntry{ObjectType: "cert_delivery", ObjectID: name, Detail: "certificate delivery target removed"})
		return c.JSON(200, result)
	})

	a.Handle("routes.api_cert_delivery_test", func(c *Ctx) error {
		payload, err := c.jsonPayload()
		if err != nil {
			return err
		}
		name := lowerName(payload, "name")
		if !c.Superadmin() {
			return c.superadminDenied("cert_delivery.test", "cert_delivery", name)
		}
		result, err := CertdDelivery("deliveries/test", newMap("name", name))
		if err != nil {
			return c.certdFailure(err)
		}
		output := ""
		if v, has := result.Get("output"); has {
			output = pyStr(v)
		}
		entry := AuditEntry{ObjectType: "cert_delivery", ObjectID: name, Detail: truncRunes(output, 400)}
		if !truthy(result.Value("ok")) {
			entry.Result = auditResultFailure
		}
		c.RecordRequest("cert_delivery.test", entry)
		return c.JSON(200, result)
	})
}

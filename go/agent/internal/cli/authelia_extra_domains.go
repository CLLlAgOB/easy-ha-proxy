package cli

import (
	"strings"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Extra Authelia sign-in domains: vars.yml authelia_extra_domains, a list of
// {domain, portal} the panel's Authelia settings page keeps. Each is a
// session cookie domain of its own with a portal under it; the templates turn
// the list into Authelia cookies, HAProxy portal routes and certificate
// names. The runtime copy is written by the unprivileged panel container and
// lands in files rendered as root, so its shape is checked before it is
// trusted.

const maxAutheliaExtraDomains = 50

var autheliaExtraDomainKeys = map[string]bool{"domain": true, "portal": true, "certificate_source": true, "dns_profile": true}

// ValidateAutheliaExtraDomains checks authelia_extra_domains: nil when absent
// or well formed.
func ValidateAutheliaExtraDomains(raw any, label string) error {
	if raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok || len(list) > maxAutheliaExtraDomains {
		return installerErrorf("%s authelia_extra_domains must be a list of at most %d sign-in domains.", label, maxAutheliaExtraDomains)
	}
	seen := map[string]bool{}
	for idx, item := range list {
		entry, ok := item.(*pyyaml.Map)
		if !ok {
			return installerErrorf("%s authelia_extra_domains[%d] must be a mapping.", label, idx)
		}
		for _, k := range entry.Keys() {
			if ks, isStr := k.(string); !isStr || !autheliaExtraDomainKeys[ks] {
				return installerErrorf("%s authelia_extra_domains[%d] has an unsupported key.", label, idx)
			}
		}
		domain, _ := entry.Value("domain").(string)
		portal, _ := entry.Value("portal").(string)
		if domain != strings.ToLower(domain) || ValidateDomain(domain) != "" ||
			portal != strings.ToLower(portal) || ValidateDomain(portal) != "" || !strings.HasSuffix(portal, "."+domain) {
			return installerErrorf("%s authelia_extra_domains[%d] needs a domain and a portal name under it.", label, idx)
		}
		if source, has := entry.Get("certificate_source"); has {
			if s, _ := source.(string); s != "letsencrypt" && s != "internal" && s != "external" {
				return installerErrorf("%s authelia_extra_domains[%d] certificate_source must be letsencrypt, internal or external.", label, idx)
			}
		}
		if profile, has := entry.Get("dns_profile"); has && profile != nil {
			if s, isStr := profile.(string); !isStr || len(s) > 64 || strings.ContainsAny(s, " \t\r\n'\"{}%") {
				return installerErrorf("%s authelia_extra_domains[%d] dns_profile is not a profile name.", label, idx)
			}
		}
		if seen[domain] {
			return installerErrorf("%s authelia_extra_domains names %s twice.", label, domain)
		}
		seen[domain] = true
	}
	return nil
}

// AutheliaExtraDomainNames are the cookie domains of authelia_extra_domains.
func AutheliaExtraDomainNames(variables *pyyaml.Map) []string {
	var out []string
	if list, ok := variables.Value("authelia_extra_domains").([]any); ok {
		for _, item := range list {
			if entry, ok := item.(*pyyaml.Map); ok {
				if d, _ := entry.Value("domain").(string); d != "" {
					out = append(out, strings.ToLower(d))
				}
			}
		}
	}
	return out
}

// domainsOverlap: one cookie domain equal to or under the other.
func domainsOverlap(a, b string) bool {
	a, b = strings.Trim(strings.ToLower(a), "."), strings.Trim(strings.ToLower(b), ".")
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

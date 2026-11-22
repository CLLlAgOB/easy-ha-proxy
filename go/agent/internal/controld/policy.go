package controld

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

var forbiddenDirectives = map[string]struct{}{
	"program": {}, "pidfile": {}, "module-load": {}, "setuid": {}, "setgid": {},
	"uid": {}, "gid": {}, "external-check": {}, "external-check-path": {},
	"external-check-command": {}, "lua-load-per-thread": {}, "setenv": {},
	"presetenv": {}, "ssl-engine": {}, "insecure-fork-wanted": {},
	"insecure-setuid-wanted": {},
}

var sectionHeaders = map[string]struct{}{
	"defaults": {}, "frontend": {}, "backend": {}, "listen": {}, "resolvers": {},
	"mailers": {}, "peers": {}, "userlist": {}, "cache": {}, "program": {}, "ring": {},
	"log-forward": {}, "fcgi-app": {}, "crt-store": {}, "traces": {},
	"http-errors": {}, "acme": {},
}

var allowedGlobalDirectives = map[string]struct{}{
	"log": {}, "nbthread": {}, "maxconn": {}, "chroot": {}, "stats": {}, "user": {}, "group": {},
	"daemon": {}, "ca-base": {}, "crt-base": {}, "ssl-default-bind-ciphersuites": {},
	"ssl-default-bind-ciphers": {}, "ssl-default-bind-options": {}, "localpeer": {},
	"lua-prepend-path": {}, "lua-load": {}, "server-state-file": {},
}

var compatibilityBlocks = map[string]string{
	".if version_atleast(3.1)":     "tune.lua.bool-sample-conversion normal",
	".if !feature(OPENSSL_AWSLC)": "tune.ssl.default-dh-param 2048",
}

func unfoldHAProxyLines(text string) []string {
	var logical []string
	var pending string
	for _, rawLine := range strings.Split(text, "\n") {
		combined := rawLine
		if pending != "" {
			combined = pending + rawLine
		}
		strippedR := strings.TrimRight(combined, "\r")
		trailing := 0
		for i := len(strippedR) - 1; i >= 0 && strippedR[i] == '\\'; i-- {
			trailing++
		}
		if trailing%2 == 1 {
			pending = strippedR[:len(strippedR)-1]
			continue
		}
		logical = append(logical, strippedR)
		pending = ""
	}
	if pending != "" {
		logical = append(logical, pending)
	}
	return logical
}

func normalizedPrefixPath(rawPath, allowedPrefix string) bool {
	if rawPath == "" || !strings.HasPrefix(rawPath, "/") || strings.ContainsRune(rawPath, 0) {
		return false
	}
	for _, seg := range strings.Split(rawPath, "/") {
		if seg == ".." {
			return false
		}
	}
	cleaned := path.Clean(rawPath)
	prefix := strings.TrimRight(allowedPrefix, "/")
	return strings.HasPrefix(cleaned, prefix+"/")
}

// EnforceConfigPolicy validates that a candidate haproxy.cfg preserves privilege-drop
// directives and contains no forbidden command-execution or preprocessing directives.
func EnforceConfigPolicy(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("HAProxy configuration must be valid UTF-8")
	}
	text := string(raw)

	inGlobal := false
	sawGlobal := false
	hasUser, hasGroup, hasChroot := false, false, false
	condBody := ""
	condSeen := false

	for _, rawLine := range unfoldHAProxyLines(text) {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		token := strings.ToLower(parts[0])
		startsSpace := len(rawLine) > 0 && unicode.IsSpace(rune(rawLine[0]))

		if condBody != "" {
			if !startsSpace {
				return errors.New("HAProxy compatibility block must stay inside global")
			}
			if condSeen {
				if line != ".endif" {
					return errors.New("invalid HAProxy compatibility block ending")
				}
				condBody = ""
				condSeen = false
				continue
			}
			if line != condBody {
				return errors.New("invalid HAProxy compatibility block body")
			}
			condSeen = true
		} else if strings.HasPrefix(token, ".") {
			expected, ok := compatibilityBlocks[line]
			if !inGlobal || !startsSpace || !ok {
				return errors.New("unapproved HAProxy conditional directive")
			}
			condBody = expected
			continue
		}

		if _, bad := forbiddenDirectives[token]; bad {
			return fmt.Errorf("HAProxy directive '%s' is not allowed", token)
		}
		if token == "option" && len(parts) >= 2 && strings.ToLower(parts[1]) == "external-check" {
			return errors.New("HAProxy directive 'option external-check' is not allowed")
		}
		if token == "global" {
			if sawGlobal {
				return errors.New("multiple global sections are not allowed")
			}
			inGlobal = true
			sawGlobal = true
			continue
		}
		if _, isSec := sectionHeaders[token]; isSec {
			inGlobal = false
			continue
		}
		if !inGlobal {
			continue
		}

		if !strings.HasPrefix(token, "tune.") {
			if _, ok := allowedGlobalDirectives[token]; !ok {
				return fmt.Errorf("global directive '%s' is not allowed", token)
			}
		}

		switch token {
		case "user":
			hasUser = len(parts) == 2 && parts[1] == "haproxy"
		case "group":
			hasGroup = len(parts) == 2 && parts[1] == "haproxy"
		case "chroot":
			hasChroot = len(parts) == 2 && parts[1] == "/var/lib/haproxy"
		case "stats":
			if len(parts) >= 2 && strings.ToLower(parts[1]) == "socket" {
				if len(parts) < 3 || !normalizedPrefixPath(parts[2], "/run/haproxy/") {
					return errors.New("HAProxy stats socket must stay under /run/haproxy")
				}
			}
		case "lua-load":
			if len(parts) != 2 || parts[1] != "/etc/haproxy/lua/auth-request.lua" {
				return errors.New("unapproved HAProxy Lua entry point")
			}
		case "lua-prepend-path":
			if len(parts) != 2 || !normalizedPrefixPath(parts[1], "/etc/haproxy/lua/") {
				return errors.New("HAProxy Lua search path must stay under /etc/haproxy/lua")
			}
		case "server-state-file":
			if len(parts) != 2 || !normalizedPrefixPath(parts[1], "/var/lib/haproxy/") {
				return errors.New("HAProxy server state file must stay under /var/lib/haproxy")
			}
		}
	}

	if condBody != "" {
		return errors.New("unclosed HAProxy compatibility block")
	}
	if !sawGlobal || !hasUser || !hasGroup || !hasChroot {
		return errors.New("required HAProxy privilege-drop directives are missing")
	}
	return nil
}

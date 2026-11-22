package healthd

import (
	"crypto/subtle"
	"slices"
	"strings"
)

func unitBase(unit string) string {
	u := strings.TrimSpace(unit)
	return strings.TrimSuffix(u, ".service")
}

// AllowedActions mirrors Python `haproxy-healthd._control_allowed_actions` 1-to-1.
func AllowedActions(kind, name, selfUnit string) []string {
	k := strings.ToLower(strings.TrimSpace(kind))
	nm := strings.TrimSpace(name)
	if selfUnit == "" {
		selfUnit = DefaultHealthUnit
	}

	switch k {
	case "docker":
		switch nm {
		case "haproxy-admin", "authelia", "authelia-redis":
			return []string{"restart"}
		default:
			return []string{"start", "stop", "restart"}
		}
	case "systemd":
		base := unitBase(nm)
		switch {
		case base == "haproxy":
			return []string{"reload", "restart"}
		case strings.HasPrefix(base, "authelia"):
			return []string{"start", "stop", "restart"}
		case base == unitBase(selfUnit):
			return []string{"restart"}
		case base == "easy-ha-proxy-backup":
			return nil
		default:
			return []string{"start", "stop", "restart"}
		}
	default:
		return nil
	}
}

// ActionPermitted reports whether action is permitted for (kind, name).
func ActionPermitted(kind, name, action, selfUnit string) bool {
	return slices.Contains(AllowedActions(kind, name, selfUnit), strings.ToLower(strings.TrimSpace(action)))
}

// ConstantTimeTokenOK validates a control token in constant time.
func ConstantTimeTokenOK(provided, expected string) bool {
	if expected == "" || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

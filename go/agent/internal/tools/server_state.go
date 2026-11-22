package tools

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var (
	serverStateFields = []string{
		"be_id", "be_name", "srv_id", "srv_name", "srv_addr", "srv_op_state", "srv_admin_state",
		"srv_uweight", "srv_iweight", "srv_time_since_last_change", "srv_check_status",
		"srv_check_result", "srv_check_health", "srv_check_state", "srv_agent_state",
		"bk_f_forced_id", "srv_f_forced_id", "srv_fqdn", "srv_port", "srvrecord",
	}
	serverStateOptional = []string{
		"srv_use_ssl", "srv_check_port", "srv_check_addr", "srv_agent_addr", "srv_agent_port",
	}
	nonDecimalFields = map[string]struct{}{
		"be_name": {}, "srv_name": {}, "srv_addr": {}, "srv_fqdn": {}, "srvrecord": {},
	}
	haproxySections = map[string]struct{}{
		"global": {}, "defaults": {}, "frontend": {}, "backend": {}, "listen": {},
		"peers": {}, "resolvers": {}, "userlist": {}, "mailers": {}, "cache": {},
		"program": {}, "ring": {}, "crt-store": {}, "http-errors": {},
		"log-forward": {}, "fcgi-app": {}, "log-profile": {}, "acme": {},
	}
)

type serverSpec struct {
	host    string
	port    int
	hasPort bool
	check   bool
	agent   bool
}

type serverKey struct {
	backend string
	server  string
}

func parseEndpoint(value string) (string, int, bool, error) {
	value = strings.TrimPrefix(value, "ipv4@")
	value = strings.TrimPrefix(value, "ipv6@")
	var host, portStr string
	if strings.HasPrefix(value, "[") {
		idx := strings.IndexByte(value, ']')
		if idx < 0 {
			return "", 0, false, errors.New("Invalid bracketed server address")
		}
		host = value[1:idx]
		suffix := value[idx+1:]
		if strings.HasPrefix(suffix, ":") {
			portStr = suffix[1:]
		}
	} else if strings.Count(value, ":") == 1 {
		h, p, _ := strings.Cut(value, ":")
		host, portStr = h, p
	} else {
		host = value
	}
	if portStr != "" && isDecimal(portStr) {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 0 || p > 65535 {
			return "", 0, false, errors.New("Invalid server port")
		}
		return host, p, true, nil
	}
	return host, 0, false, nil
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func applyCheckOptions(words []string, check, agent bool) (bool, bool) {
	for _, w := range words {
		switch w {
		case "check":
			check = true
		case "no-check":
			check = false
		case "agent-check":
			agent = true
		case "no-agent-check":
			agent = false
		}
	}
	return check, agent
}

func splitConfigWords(line string) []string {
	var words []string
	var cur strings.Builder
	inQuote := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			cur.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && inQuote != '\'' {
			escaped = true
			continue
		}
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
			} else {
				cur.WriteByte(ch)
			}
			continue
		}
		if ch == '#' {
			break
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\r' {
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

func parseConfiguredServers(config string) (map[serverKey]serverSpec, error) {
	res := make(map[serverKey]serverSpec)
	var section, backend string
	var defCheck, defAgent, curCheck, curAgent bool

	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		words := splitConfigWords(trimmed)
		if len(words) == 0 {
			continue
		}
		kw := words[0]
		if _, isSec := haproxySections[kw]; isSec {
			section = kw
			if (kw == "backend" || kw == "listen") && len(words) > 1 {
				backend = words[1]
			} else {
				backend = ""
			}
			if kw == "defaults" {
				defCheck, defAgent = false, false
			}
			curCheck, curAgent = defCheck, defAgent
			continue
		}
		if kw == "default-server" {
			curCheck, curAgent = applyCheckOptions(words[1:], curCheck, curAgent)
			if section == "defaults" {
				defCheck, defAgent = curCheck, curAgent
			}
			continue
		}
		if kw == "server" && backend != "" && len(words) >= 3 {
			host, port, hasPort, err := parseEndpoint(words[2])
			if err != nil {
				return nil, err
			}
			sc, sa := applyCheckOptions(words[3:], curCheck, curAgent)
			res[serverKey{backend: backend, server: words[1]}] = serverSpec{
				host: host, port: port, hasPort: hasPort, check: sc, agent: sa,
			}
		}
	}
	return res, nil
}

// NormalizeServerState reproduces installer/haproxy_server_state.py normalize_state 1-to-1.
func NormalizeServerState(stateText, configText string, hasConfig bool) (string, error) {
	lines := strings.Split(strings.ReplaceAll(stateText, "\r\n", "\n"), "\n")
	if len(lines) == 0 || lines[0] != "1" {
		return "", errors.New("Unsupported HAProxy server-state version")
	}
	var servers map[serverKey]serverSpec
	if hasConfig {
		var err error
		servers, err = parseConfiguredServers(configText)
		if err != nil {
			return "", err
		}
	}

	output := []string{"1"}
	var header []string

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "# be_id ") {
				continue
			}
			header = strings.Fields(line[2:])
			if len(header) < len(serverStateFields) || len(header) > len(serverStateFields)+len(serverStateOptional) {
				return "", errors.New("Unsupported HAProxy server-state header")
			}
			for i, f := range serverStateFields {
				if header[i] != f {
					return "", errors.New("Unsupported HAProxy server-state header")
				}
			}
			for i := len(serverStateFields); i < len(header); i++ {
				if header[i] != serverStateOptional[i-len(serverStateFields)] {
					return "", errors.New("Unsupported HAProxy server-state header")
				}
			}
			output = append(output, "# "+strings.Join(serverStateFields, " "))
			continue
		}

		row := strings.Fields(line)
		if header == nil || len(row) != len(header) {
			return "", errors.New("Incomplete HAProxy server-state row")
		}
		values := make(map[string]string, len(serverStateFields))
		for i, f := range serverStateFields {
			values[f] = row[i]
			if _, ok := nonDecimalFields[f]; !ok && !isDecimal(row[i]) {
				return "", fmt.Errorf("Invalid numeric HAProxy server-state field: %s", f)
			}
		}

		if spec, found := servers[serverKey{backend: values["be_name"], server: values["srv_name"]}]; found {
			adm, _ := strconv.Atoi(values["srv_admin_state"])
			values["srv_admin_state"] = strconv.Itoa(adm &^ 0x40)
			if spec.hasPort {
				values["srv_port"] = strconv.Itoa(spec.port)
			}
			if addr, err := netip.ParseAddr(spec.host); err == nil {
				values["srv_addr"] = addr.String()
				values["srv_fqdn"] = "-"
				values["srvrecord"] = "-"
			} else if strings.HasPrefix(spec.host, "_") {
				if values["srvrecord"] != spec.host {
					values["srv_addr"] = "-"
					values["srv_fqdn"] = "-"
					values["srvrecord"] = "-"
					if !spec.hasPort {
						values["srv_port"] = "0"
					}
				}
			} else if spec.host != "" && !strings.HasPrefix(spec.host, "/") &&
				!strings.HasPrefix(spec.host, "unix@") &&
				!strings.HasPrefix(spec.host, "abns@") &&
				!strings.HasPrefix(spec.host, "fd@") {
				hostname := strings.TrimRight(strings.ToLower(spec.host), ".")
				if strings.TrimRight(strings.ToLower(values["srv_fqdn"]), ".") != hostname || values["srvrecord"] != "-" {
					values["srv_addr"] = "-"
				}
				values["srv_fqdn"] = hostname
				values["srvrecord"] = "-"
			}
			if !spec.check && !spec.agent {
				values["srv_op_state"] = "2"
				values["srv_check_status"] = "0"
				values["srv_check_result"] = "0"
				values["srv_check_health"] = "0"
				values["srv_check_state"] = "0"
				values["srv_agent_state"] = "0"
			}
		}

		cols := make([]string, len(serverStateFields))
		for i, f := range serverStateFields {
			cols[i] = values[f]
		}
		output = append(output, strings.Join(cols, " "))
	}
	return strings.Join(output, "\n") + "\n", nil
}

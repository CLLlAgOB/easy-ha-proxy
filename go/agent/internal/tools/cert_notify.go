package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The certificate mail hook (910-mail-notify.sh) asks this tool whether to
// write and to whom. It reads the panel's mail-notify.json and the renewed
// names and prints one tab-separated line: ENABLED TO FROM DOMAINS. Anything
// it cannot trust ends with exit 1 and nothing printed: the hook then skips
// the message, since the fields end up in mail headers.

var (
	certNotifyControl = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	certNotifyEmail   = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@" +
		`(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+` +
		`[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	certNotifyDomain = regexp.MustCompile(`^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+` +
		`[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// certNotifyMaxState bounds the read: the panel writes a few hundred bytes.
const certNotifyMaxState = 1 << 20

// CertNotifyState decides the hook's line from the state file's bytes and the
// renewed names (certbot's RENEWED_DOMAINS, space-separated).
func CertNotifyState(raw []byte, renewed string) (string, error) {
	invalid := fmt.Errorf("invalid notification state")
	if !utf8.Valid(raw) {
		return "", invalid
	}
	var state map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&state); err != nil || state == nil {
		return "", invalid
	}
	if strings.Trim(string(raw[decoder.InputOffset():]), " \t\r\n") != "" {
		return "", invalid
	}
	enabled, _ := state["enabled"].(bool)
	if !enabled {
		return "0\t\t\t", nil
	}
	text := func(key string) (string, bool) {
		value, present := state[key]
		if !present {
			return "", true
		}
		s, ok := value.(string)
		return s, ok
	}
	recipient, okTo := text("to")
	sender, okFrom := text("from")
	if !okTo || !okFrom {
		return "", invalid
	}
	for _, address := range []string{recipient, sender} {
		if certNotifyControl.MatchString(address) || !certNotifyEmail.MatchString(address) {
			return "", invalid
		}
	}
	domains := strings.Fields(renewed)
	if len(domains) == 0 {
		return "", invalid
	}
	for _, name := range domains {
		if !certNotifyDomain.MatchString(name) {
			return "", invalid
		}
	}
	var onlyFor []string
	if value, present := state["only_for"]; present {
		items, ok := value.([]any)
		if !ok {
			return "", invalid
		}
		for _, item := range items {
			name, ok := item.(string)
			if !ok || !certNotifyDomain.MatchString(name) {
				return "", invalid
			}
			onlyFor = append(onlyFor, name)
		}
	}
	if len(onlyFor) > 0 {
		wanted := false
		for _, name := range domains {
			for _, only := range onlyFor {
				if name == only {
					wanted = true
				}
			}
		}
		if !wanted {
			enabled = false
		}
	}
	flag := "0"
	if enabled {
		flag = "1"
	}
	return strings.Join([]string{flag, recipient, sender, strings.Join(domains, " ")}, "\t"), nil
}

// RunCertNotifyState is `easy-ha-proxy-agent cert-notify-state STATE DOMAINS`.
func RunCertNotifyState(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent cert-notify-state STATE_FILE DOMAINS")
		return 2
	}
	f, err := os.Open(args[0])
	if err != nil {
		return 1
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, certNotifyMaxState+1))
	if err != nil || len(raw) > certNotifyMaxState {
		return 1
	}
	line, err := CertNotifyState(raw, args[1])
	if err != nil {
		return 1
	}
	fmt.Fprintln(stdout, line)
	return 0
}

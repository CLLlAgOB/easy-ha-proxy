package fullbackup

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

const usageText = `usage: easy-ha-proxy-agent full-backup backup [--output-dir DIR] [--include-ssh] [--no-quiesce] [--passphrase-stdin]
       easy-ha-proxy-agent full-backup restore ARCHIVE [--mode auto|fresh|overlay] [--scope full|config]
           [--restore-ssh] [--skip-ssh] [--apply] [--replace-managed] [--passphrase-stdin] [--yes]
       easy-ha-proxy-agent full-backup inspect ARCHIVE [--passphrase-stdin]`

// parsed is the command line: flags (boolean or with a value) in any order
// around the positional arguments, as argparse takes them.
type parsed struct {
	flags      map[string]string
	positional []string
}

func parseArgs(args []string, booleans, valued map[string][]string) (*parsed, error) {
	p := &parsed{flags: map[string]string{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			if arg == "--" {
				p.positional = append(p.positional, args[i+1:]...)
				break
			}
			p.positional = append(p.positional, arg)
			continue
		}
		name, value, hasValue := strings.Cut(arg[2:], "=")
		if _, ok := booleans[name]; ok {
			if hasValue {
				return nil, fmt.Errorf("argument --%s: ignored explicit argument '%s'", name, value)
			}
			p.flags[name] = "true"
			continue
		}
		choices, ok := valued[name]
		if !ok {
			return nil, fmt.Errorf("unrecognized arguments: %s", arg)
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("argument --%s: expected one argument", name)
			}
			i++
			value = args[i]
		}
		if len(choices) > 0 && !contains(choices, value) {
			return nil, fmt.Errorf("argument --%s: invalid choice: '%s' (choose from %s)", name, value, strings.Join(choices, ", "))
		}
		p.flags[name] = value
	}
	return p, nil
}

func (p *parsed) set(name string) bool { return p.flags[name] == "true" }

func (p *parsed) value(name, fallback string) string {
	if v, ok := p.flags[name]; ok {
		return v
	}
	return fallback
}

// RunCLI is "easy-ha-proxy-agent full-backup": exit 2 for an expected
// failure (and bad arguments), 130 when cancelled.
func RunCLI(args []string, stdout, stderr io.Writer) int {
	bad := func(message string) int {
		fmt.Fprintln(stderr, usageText)
		fmt.Fprintf(stderr, "easy-ha-proxy-full-backup: error: %s\n", message)
		return 2
	}
	if len(args) == 0 {
		return bad("the following arguments are required: command")
	}
	none := []string(nil)
	var err error
	switch args[0] {
	case "backup":
		var p *parsed
		p, err = parseArgs(args[1:], map[string][]string{"include-ssh": none, "no-quiesce": none, "passphrase-stdin": none},
			map[string][]string{"output-dir": none})
		if err != nil {
			return bad(err.Error())
		}
		if len(p.positional) > 0 {
			return bad("unrecognized arguments: " + strings.Join(p.positional, " "))
		}
		if err = loadLimits(); err == nil {
			_, err = createBackup(backupOptions{outputDir: p.value("output-dir", ""), includeSSH: p.set("include-ssh"),
				quiesce: !p.set("no-quiesce"), passphraseStdin: p.set("passphrase-stdin")})
		}
	case "restore":
		var p *parsed
		p, err = parseArgs(args[1:], map[string][]string{"restore-ssh": none, "skip-ssh": none, "apply": none,
			"replace-managed": none, "passphrase-stdin": none, "yes": none},
			map[string][]string{"mode": {"auto", "fresh", "overlay"}, "scope": {"full", "config"}})
		if err != nil {
			return bad(err.Error())
		}
		if len(p.positional) != 1 {
			if len(p.positional) == 0 {
				return bad("the following arguments are required: archive")
			}
			return bad("unrecognized arguments: " + strings.Join(p.positional[1:], " "))
		}
		if err = loadLimits(); err == nil {
			err = restoreBackup(restoreOptions{archive: p.positional[0], mode: p.value("mode", "auto"),
				scope: p.value("scope", "full"), restoreSSH: p.set("restore-ssh"), skipSSH: p.set("skip-ssh"),
				apply: p.set("apply"), replaceManaged: p.set("replace-managed"),
				passphraseStdin: p.set("passphrase-stdin"), yes: p.set("yes")})
		}
	case "inspect":
		var p *parsed
		p, err = parseArgs(args[1:], map[string][]string{"passphrase-stdin": none}, nil)
		if err != nil {
			return bad(err.Error())
		}
		if len(p.positional) != 1 {
			if len(p.positional) == 0 {
				return bad("the following arguments are required: archive")
			}
			return bad("unrecognized arguments: " + strings.Join(p.positional[1:], " "))
		}
		if err = loadLimits(); err == nil {
			_, err = inspectBackup(p.positional[0], p.set("passphrase-stdin"))
		}
	default:
		return bad(fmt.Sprintf("argument command: invalid choice: '%s' (choose from 'backup', 'restore', 'inspect')", args[0]))
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, errCancelled) {
		fmt.Fprintln(stderr, "Cancelled.")
		return 130
	}
	fmt.Fprintf(stderr, "ERROR: %v\n", err)
	return 2
}

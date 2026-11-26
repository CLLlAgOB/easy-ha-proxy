package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

const rootUsage = `usage: easy-ha-proxy [-h] {install,plan,update,set-channels,status,reboot,language,backup-full,restore-full,configure,migrate-domain,promote-production} ...

Install and update easy-ha-proxy on one Debian/Ubuntu server.

subcommands:
  install             run first installation
  plan                preview an update
  update              update source and apply changes
  set-channels        persist the deployment channels without updating
  status              show service status
  reboot              schedule a reboot previously requested by operating-system updates
  language            change the assistant, UI, and notification language
  backup-full         create an encrypted disaster-recovery backup
  restore-full        restore an encrypted disaster-recovery backup
  configure           run the configuration wizard again
  migrate-domain      safely replace the managed root domain
  promote-production  promote a test installation to production without reinstalling
`

func sortedComponentNames() string {
	names := make([]string, 0, len(UpdateComponentTags))
	for k := range UpdateComponentTags {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// RunCLI executes the easy-ha-proxy command line and returns the process exit code.
func RunCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rootUsage)
		return 2
	}
	switch args[0] {
	case "--probe":
		return 0
	case "-h", "--help":
		fmt.Fprint(stdout, rootUsage)
		return 0
	}

	ctx := NewContext(stdin, stdout, stderr)
	sub := args[0]
	rest := args[1:]

	var err error
	var usageShown bool
	switch sub {
	case "install":
		usageShown, err = dispatchInstall(ctx, rest)
	case "plan":
		usageShown, err = dispatchPlan(ctx, rest)
	case "update":
		usageShown, err = dispatchUpdate(ctx, rest, args)
	case "set-channels":
		usageShown, err = dispatchSetChannels(ctx, rest)
	case "status":
		usageShown, err = dispatchStatus(ctx, rest)
	case "reboot":
		usageShown, err = dispatchReboot(ctx, rest)
	case "language":
		usageShown, err = dispatchLanguage(ctx, rest)
	case "backup-full":
		usageShown, err = dispatchBackupFull(ctx, rest)
	case "restore-full":
		usageShown, err = dispatchRestoreFull(ctx, rest)
	case "apply-restored":
		usageShown, err = dispatchApplyRestored(ctx, rest)
	case "configure":
		usageShown, err = dispatchConfigure(ctx, rest)
	case "migrate-domain":
		usageShown, err = dispatchMigrateDomain(ctx, rest, false)
	case "promote-production":
		usageShown, err = dispatchMigrateDomain(ctx, rest, true)
	default:
		fmt.Fprintf(stderr, "easy-ha-proxy: error: invalid choice: %q\n", sub)
		fmt.Fprint(stderr, rootUsage)
		return 2
	}

	if usageShown {
		return 0
	}
	if err == nil {
		return 0
	}
	var instErr *InstallerError
	if errors.As(err, &instErr) {
		fmt.Fprintf(stderr, "\nERROR: %s\n", instErr.Msg)
		return 2
	}
	var exitErr *CommandExitError
	if errors.As(err, &exitErr) {
		fmt.Fprintf(stderr, "\nERROR: command failed with exit code %d.\n", exitErr.ExitCode)
		if exitErr.ExitCode == 0 {
			return 1
		}
		return exitErr.ExitCode
	}
	var parseErr *argParseError
	if errors.As(err, &parseErr) {
		fmt.Fprintf(stderr, "easy-ha-proxy %s: error: %s\n", sub, parseErr.Msg)
		return 2
	}
	fmt.Fprintf(stderr, "\nERROR: %v\n", err)
	return 2
}

type argParseError struct{ Msg string }

func (e *argParseError) Error() string { return e.Msg }

func parseErrorf(format string, args ...any) error {
	return &argParseError{Msg: fmt.Sprintf(format, args...)}
}

func nextFlagValue(args []string, i *int, flagName string) (string, error) {
	if _, after, hasEq := strings.Cut(args[*i], "="); hasEq {
		return after, nil
	}
	if *i+1 >= len(args) {
		return "", parseErrorf("argument %s: expected one argument", flagName)
	}
	*i++
	return args[*i], nil
}

func flagKey(arg string) string {
	k, _, _ := strings.Cut(arg, "=")
	return k
}

func validateChoice(flagName, value string, choices ...string) error {
	for _, c := range choices {
		if value == c {
			return nil
		}
	}
	return parseErrorf("argument %s: invalid choice: %q (choose from %s)", flagName, value, strings.Join(choices, ", "))
}

func dispatchInstall(ctx *Context, args []string) (bool, error) {
	a := InstallArgs{
		SourceChannel: os.Getenv("EASY_HA_PROXY_SOURCE_CHANNEL"),
	}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy install [--reconfigure] [--skip-dns-check] [--test-mode] [--certificate-source {letsencrypt,internal}] [--image-channel {latest,alpha}] [--source-channel {github,local}]")
			return true, nil
		case "--reconfigure":
			a.Reconfigure = true
		case "--skip-dns-check":
			a.SkipDNSCheck = true
		case "--test-mode":
			a.TestMode = true
		case "--certificate-source":
			v, err := nextFlagValue(args, &i, "--certificate-source")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--certificate-source", v, "letsencrypt", "internal"); err != nil {
				return false, err
			}
			a.CertificateSource = v
		case "--image-channel", "--image":
			v, err := nextFlagValue(args, &i, "--image-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--image-channel", v, "latest", "alpha"); err != nil {
				return false, err
			}
			a.ImageChannel = v
		case "--source-channel", "--source":
			v, err := nextFlagValue(args, &i, "--source-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--source-channel", v, "github", "local"); err != nil {
				return false, err
			}
			a.SourceChannel = v
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandInstall(ctx, a)
}

func dispatchPlan(ctx *Context, args []string) (bool, error) {
	a := PlanArgs{Component: "all"}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintf(ctx.Stdout, "usage: easy-ha-proxy plan [--ui-only] [--component {%s}]\n", sortedComponentNames())
			return true, nil
		case "--ui-only":
			a.UIOnly = true
		case "--component":
			v, err := nextFlagValue(args, &i, "--component")
			if err != nil {
				return false, err
			}
			if _, ok := UpdateComponentTags[v]; !ok {
				return false, parseErrorf("argument --component: invalid choice: %q (choose from %s)", v, sortedComponentNames())
			}
			a.Component = v
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandPlan(ctx, a)
}

func dispatchUpdate(ctx *Context, args []string, origArgs []string) (bool, error) {
	a := UpdateArgs{Component: "all", OrigArgs: origArgs}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintf(ctx.Stdout, "usage: easy-ha-proxy update [--ui-only] [--component {%s}] [--no-fetch] [--source-channel {github,local}] [--image-channel {latest,alpha}]\n", sortedComponentNames())
			return true, nil
		case "--ui-only":
			a.UIOnly = true
		case "--automatic-os":
			a.AutomaticOS = true
		case "--runtime-maintenance":
			v, err := nextFlagValue(args, &i, "--runtime-maintenance")
			if err != nil {
				return false, err
			}
			a.RuntimeMaintenance = v
		case "--maintenance-revision":
			v, err := nextFlagValue(args, &i, "--maintenance-revision")
			if err != nil {
				return false, err
			}
			a.MaintenanceRevision = v
		case "--maintenance-until":
			v, err := nextFlagValue(args, &i, "--maintenance-until")
			if err != nil {
				return false, err
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return false, parseErrorf("argument --maintenance-until: invalid float value: %q", v)
			}
			a.MaintenanceUntil = f
			a.HasMaintenanceUntil = true
		case "--component":
			v, err := nextFlagValue(args, &i, "--component")
			if err != nil {
				return false, err
			}
			if _, ok := UpdateComponentTags[v]; !ok {
				return false, parseErrorf("argument --component: invalid choice: %q (choose from %s)", v, sortedComponentNames())
			}
			a.Component = v
		case "--no-fetch":
			a.NoFetch = true
		case "--source-channel", "--source":
			v, err := nextFlagValue(args, &i, "--source-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--source-channel", v, "github", "local"); err != nil {
				return false, err
			}
			a.SourceChannel = v
		case "--image-channel", "--image":
			v, err := nextFlagValue(args, &i, "--image-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--image-channel", v, "latest", "alpha"); err != nil {
				return false, err
			}
			a.ImageChannel = v
		case "--expected-source-revision":
			v, err := nextFlagValue(args, &i, "--expected-source-revision")
			if err != nil {
				return false, err
			}
			a.ExpectedSourceRevision = v
		case "--no-full-fallback":
			a.NoFullFallback = true
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandUpdate(ctx, a)
}

func dispatchSetChannels(ctx *Context, args []string) (bool, error) {
	a := SetChannelsArgs{}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy set-channels [--release-channel {stable,alpha,local}] [--source-channel {github,local}] [--branch BRANCH] [--image-channel {latest,alpha}]")
			return true, nil
		case "--release-channel", "--channel":
			v, err := nextFlagValue(args, &i, "--release-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--release-channel", v, "stable", "alpha", "local"); err != nil {
				return false, err
			}
			a.ReleaseChannel = v
		case "--source-channel", "--source":
			v, err := nextFlagValue(args, &i, "--source-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--source-channel", v, "github", "local"); err != nil {
				return false, err
			}
			a.SourceChannel = v
		case "--branch":
			v, err := nextFlagValue(args, &i, "--branch")
			if err != nil {
				return false, err
			}
			a.Branch = v
		case "--image-channel", "--image":
			v, err := nextFlagValue(args, &i, "--image-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--image-channel", v, "latest", "alpha"); err != nil {
				return false, err
			}
			a.ImageChannel = v
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandSetChannels(ctx, a)
}

func dispatchStatus(ctx *Context, args []string) (bool, error) {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy status")
			return true, nil
		}
		return false, parseErrorf("unrecognized arguments: %s", arg)
	}
	return false, CommandStatus(ctx)
}

func dispatchReboot(ctx *Context, args []string) (bool, error) {
	assumeYes := false
	for _, arg := range args {
		switch arg {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy reboot [--yes]")
			return true, nil
		case "--yes":
			assumeYes = true
		default:
			return false, parseErrorf("unrecognized arguments: %s", arg)
		}
	}
	return false, CommandReboot(ctx, assumeYes)
}

func dispatchLanguage(ctx *Context, args []string) (bool, error) {
	a := LanguageArgs{}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy language [--language {en,ru}] [--apply]")
			return true, nil
		case "--language":
			v, err := nextFlagValue(args, &i, "--language")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--language", v, "en", "ru"); err != nil {
				return false, err
			}
			a.Language = v
		case "--apply":
			a.Apply = true
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandLanguage(ctx, a)
}

func dispatchBackupFull(ctx *Context, args []string) (bool, error) {
	a := BackupFullArgs{}
	sshSet := false
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy backup-full [--output-dir OUTPUT_DIR] [--include-ssh | --exclude-ssh] [--no-quiesce]")
			return true, nil
		case "--output-dir":
			v, err := nextFlagValue(args, &i, "--output-dir")
			if err != nil {
				return false, err
			}
			a.OutputDir = v
		case "--include-ssh":
			if sshSet && a.IncludeSSH != nil && !*a.IncludeSSH {
				return false, parseErrorf("argument --include-ssh: not allowed with argument --exclude-ssh")
			}
			val := true
			a.IncludeSSH = &val
			sshSet = true
		case "--exclude-ssh":
			if sshSet && a.IncludeSSH != nil && *a.IncludeSSH {
				return false, parseErrorf("argument --exclude-ssh: not allowed with argument --include-ssh")
			}
			val := false
			a.IncludeSSH = &val
			sshSet = true
		case "--no-quiesce":
			a.NoQuiesce = true
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandBackupFull(ctx, a)
}

func dispatchRestoreFull(ctx *Context, args []string) (bool, error) {
	a := RestoreFullArgs{Mode: "auto"}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy restore-full [--mode {auto,fresh,overlay}] [--restore-ssh] [--skip-ssh] [--apply] archive")
			return true, nil
		case "--mode":
			v, err := nextFlagValue(args, &i, "--mode")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--mode", v, "auto", "fresh", "overlay"); err != nil {
				return false, err
			}
			a.Mode = v
		case "--restore-ssh":
			a.RestoreSSH = true
		case "--skip-ssh":
			a.SkipSSH = true
		case "--apply":
			a.Apply = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return false, parseErrorf("unrecognized arguments: %s", args[i])
			}
			if a.Archive != "" {
				return false, parseErrorf("unrecognized arguments: %s", args[i])
			}
			a.Archive = args[i]
		}
	}
	if a.Archive == "" {
		return false, parseErrorf("the following arguments are required: archive")
	}
	return false, CommandRestoreFull(ctx, a)
}

func dispatchApplyRestored(ctx *Context, args []string) (bool, error) {
	a := ApplyRestoredArgs{Scope: "full"}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy apply-restored [--offline] [--scope {full,config}]")
			return true, nil
		case "--offline":
			a.Offline = true
		case "--scope":
			v, err := nextFlagValue(args, &i, "--scope")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--scope", v, "full", "config"); err != nil {
				return false, err
			}
			a.Scope = v
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandApplyRestored(ctx, a)
}

func dispatchConfigure(ctx *Context, args []string) (bool, error) {
	a := ConfigureArgs{}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy configure [--apply] [--certificate-source {letsencrypt,internal}] [--image-channel {latest,alpha}]")
			return true, nil
		case "--apply":
			a.Apply = true
		case "--certificate-source":
			v, err := nextFlagValue(args, &i, "--certificate-source")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--certificate-source", v, "letsencrypt", "internal"); err != nil {
				return false, err
			}
			a.CertificateSource = v
		case "--image-channel", "--image":
			v, err := nextFlagValue(args, &i, "--image-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--image-channel", v, "latest", "alpha"); err != nil {
				return false, err
			}
			a.ImageChannel = v
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandConfigure(ctx, a)
}

func dispatchMigrateDomain(ctx *Context, args []string, promote bool) (bool, error) {
	a := MigrateDomainArgs{PromoteProduction: promote}
	for i := 0; i < len(args); i++ {
		switch flagKey(args[i]) {
		case "-h", "--help":
			if promote {
				fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy promote-production [--new-domain NEW_DOMAIN] [--certificate-source {letsencrypt,internal}] [--image-channel {latest,alpha}] [--skip-dns-check] [--plan-only]")
			} else {
				fmt.Fprintln(ctx.Stdout, "usage: easy-ha-proxy migrate-domain [--new-domain NEW_DOMAIN] [--skip-dns-check] [--plan-only]")
			}
			return true, nil
		case "--new-domain":
			v, err := nextFlagValue(args, &i, "--new-domain")
			if err != nil {
				return false, err
			}
			a.NewDomain = v
		case "--skip-dns-check":
			a.SkipDNSCheck = true
		case "--plan-only":
			a.PlanOnly = true
		case "--certificate-source":
			if !promote {
				return false, parseErrorf("unrecognized arguments: %s", args[i])
			}
			v, err := nextFlagValue(args, &i, "--certificate-source")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--certificate-source", v, "letsencrypt", "internal"); err != nil {
				return false, err
			}
			a.CertificateSource = v
		case "--image-channel", "--image":
			if !promote {
				return false, parseErrorf("unrecognized arguments: %s", args[i])
			}
			v, err := nextFlagValue(args, &i, "--image-channel")
			if err != nil {
				return false, err
			}
			if err := validateChoice("--image-channel", v, "latest", "alpha"); err != nil {
				return false, err
			}
			a.ImageChannel = v
		default:
			return false, parseErrorf("unrecognized arguments: %s", args[i])
		}
	}
	return false, CommandMigrateDomain(ctx, a)
}

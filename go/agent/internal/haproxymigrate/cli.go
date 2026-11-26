package haproxymigrate

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"syscall"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/hostsec"
)

var (
	cliGetEUID   = os.Geteuid
	cliNewEngine = func() *Engine { return NewEngine(nil, nil) }
	cliUmask     = syscall.Umask
)

// RunCLI implements "easy-ha-proxy-agent haproxy-migrate <action> [flags]".
func RunCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent haproxy-migrate <prepare|migrate|patch|apply|rollback|recover|status> [flags]")
		return 2
	}
	action := args[0]
	switch action {
	case "prepare", "migrate", "patch", "apply", "rollback", "recover", "status":
	default:
		fmt.Fprintf(stderr, "unsupported haproxy-migrate action: %s\n", action)
		return 2
	}
	fs := flag.NewFlagSet("haproxy-migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	txID := fs.String("id", "", "")
	exerciseRollback := fs.Bool("exercise-rollback", false, "")
	expectedVersion := fs.String("expected-version", "", "")
	reinstall := fs.Bool("reinstall", false, "")
	webProgress := fs.Bool("web-progress", false, "")
	maintRev := fs.String("maintenance-revision", "", "")
	maintUntil := fs.Float64("maintenance-until", math.NaN(), "")
	maintRoot := fs.String("maintenance-state-root", hostsec.DefaultStateRoot, "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if cliGetEUID() != 0 {
		fmt.Fprintln(stderr, "This operator command must run as root")
		return 2
	}
	cliUmask(0o077)
	engine := cliNewEngine()
	if *webProgress {
		engine.Observer = func(summary map[string]any) {
			phase := strVal(summary["phase"])
			val := "playbook"
			switch phase {
			case "preparing", "prepared":
				val = "prepare"
			case "target_verified", "committed":
				val = "verifying"
			}
			fmt.Fprintln(stdout, "EHP-PROGRESS phase="+val)
		}
	}

	var result map[string]any
	var err error
	switch action {
	case "prepare":
		result, err = engine.Prepare()
	case "migrate":
		result, err = engine.Migrate(*exerciseRollback)
	case "patch":
		if *expectedVersion == "" {
			fmt.Fprintln(stderr, "--expected-version is required")
			return 2
		}
		lastPhase := ""
		engine.Observer = func(summary map[string]any) {
			phase := strVal(summary["phase"])
			if phase != lastPhase {
				lastPhase = phase
				val := "playbook"
				switch phase {
				case "preparing", "prepared":
					val = "prepare"
				case "target_verified":
					val = "verifying"
				}
				fmt.Fprintln(stdout, "EHP-PROGRESS phase="+val)
			}
		}
		hasMaintRev := false
		hasMaintUntil := !math.IsNaN(*maintUntil)
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "maintenance-revision" {
				hasMaintRev = true
			}
		})
		if hasMaintRev {
			rev := *maintRev
			until := *maintUntil
			root := *maintRoot
			engine.BeforeChangeHook = func() error {
				if werr := hostsec.RequireUnifiedWindow(root, rev, until, hasMaintUntil); werr != nil {
					return migErr("%s", werr.Error())
				}
				return nil
			}
		}
		err = engine.withLock(func() error {
			prepared, perr := engine.PreparePatch(*expectedVersion, *reinstall)
			if perr != nil {
				return perr
			}
			result, perr = engine.Apply(strVal(prepared["id"]), *exerciseRollback)
			return perr
		})
	case "apply":
		if *txID == "" {
			fmt.Fprintln(stderr, "--id is required")
			return 2
		}
		result, err = engine.Apply(*txID, *exerciseRollback)
	case "rollback":
		if *txID == "" {
			fmt.Fprintln(stderr, "--id is required")
			return 2
		}
		result, err = engine.Rollback(*txID)
	case "recover":
		if *txID == "" {
			fmt.Fprintln(stderr, "--id is required")
			return 2
		}
		result, err = engine.Recover(*txID)
	case "status":
		if *txID == "" {
			fmt.Fprintln(stderr, "--id is required")
			return 2
		}
		if lerr := engine.load(*txID); lerr != nil {
			err = lerr
		} else {
			result = engine.Summary()
		}
	}

	if err != nil {
		payload := map[string]any{
			"error":       err.Error(),
			"transaction": engine.State["id"],
			"phase":       engine.State["phase"],
		}
		if failure := strVal(engine.State["failure"]); failure != "" {
			payload["failure"] = failure
		}
		raw, _ := json.Marshal(payload)
		fmt.Fprintln(stderr, string(raw))
		return 1
	}
	raw, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprintln(stdout, string(raw))
	return 0
}

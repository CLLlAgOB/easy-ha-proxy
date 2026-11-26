// Command easy-ha-proxy-agent is the unified static multi-call host daemon
// for easy-ha-proxy (healthd, metricsd, alertd, controld, certd, backupd, updated).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alertd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/authelia"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/backupd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/certd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/controld"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/healthd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/metricsd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updated"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updateplan"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updatescope"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "version":
		fmt.Printf("easy-ha-proxy-agent %s\n", version)
	case "healthd":
		runHealthd(args)
	case "metricsd":
		runMetricsd(args)
	case "alertd":
		runAlertd(args)
	case "controld":
		runControld(args)
	case "certd":
		runCertd(args)
	case "backupd":
		runBackupd(args)
	case "updated":
		runUpdated(args)
	case "authelia-bansd":
		if err := authelia.RunBansd(authelia.BansdOptionsFromEnv()); err != nil {
			log.Fatalf("authelia-bansd error: %v", err)
		}
	case "authelia-usersd":
		if err := authelia.RunUsersd(authelia.UsersdOptionsFromEnv()); err != nil {
			log.Fatalf("authelia-usersd error: %v", err)
		}
	case "authelia-configd":
		if err := authelia.RunConfigd(authelia.ConfigdOptionsFromEnv()); err != nil {
			log.Fatalf("authelia-configd error: %v", err)
		}
	case "unit-failed":
		unit := ""
		if len(args) == 1 {
			unit = args[0]
		}
		os.Exit(tools.RunUnitFailed(context.Background(), unit, tools.UnitFailedOptions{Stderr: os.Stderr}))
	case "backup-run":
		os.Exit(tools.RunBackupScheduled(context.Background(), "", 0, os.Stdout, os.Stderr))
	case "server-state":
		os.Exit(runServerState(args))
	case "udp-forward":
		os.Exit(runUDPForward(args))
	case "cert-deliver":
		os.Exit(runCertDeliver(args))
	case "update-geoip":
		os.Exit(runUpdateGeoIP(args))
	case "apt-metadata":
		os.Exit(tools.RunAptMetadata(args, os.Stdout, os.Stderr))
	case "update-plan":
		os.Exit(updateplan.RunCLI(args, os.Stdout, os.Stderr))
	case "update-scope":
		os.Exit(updatescope.RunCLI(args, os.Stdout, os.Stderr))
	case "apply":
		os.Exit(apply.Run(args, os.Stdout, os.Stderr))
	case "probe-host":
		text, _ := pyyaml.JSONDumps(metricsd.ProbeHost(), false, false)
		fmt.Println(text)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: easy-ha-proxy-agent <healthd|metricsd|alertd|controld|certd|backupd|updated|authelia-bansd|authelia-usersd|authelia-configd|unit-failed|backup-run|server-state|udp-forward|cert-deliver|update-geoip|apt-metadata|update-plan|update-scope|probe-host|apply|version> [flags]")
}

func runUDPForward(args []string) int {
	return tools.RunUDPForward(args, os.Stdout, os.Stderr)
}

func runCertDeliver(args []string) int {
	return tools.RunCertDeliver(args, tools.CertDeliverOptionsFromEnv(), os.Stdout, os.Stderr)
}

func runUpdateGeoIP(args []string) int {
	return tools.RunUpdateGeoIP(args, os.Stdout)
}

func runServerState(args []string) int {
	fs := flag.NewFlagSet("server-state", flag.ContinueOnError)
	statePath := fs.String("state", "", "path to HAProxy server-state file")
	cfgPath := fs.String("config", "", "path to haproxy.cfg")
	if err := fs.Parse(args); err != nil || *statePath == "" || *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: easy-ha-proxy-agent server-state --state <path> --config <path>")
		return 2
	}
	stateRaw, err := os.ReadFile(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot normalize HAProxy state: %v\n", err)
		return 1
	}
	var cfgText string
	hasCfg := false
	if cfgRaw, err := os.ReadFile(*cfgPath); err == nil {
		cfgText = string(cfgRaw)
		hasCfg = true
	}
	out, err := tools.NormalizeServerState(string(stateRaw), cfgText, hasCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot normalize HAProxy state: %v\n", err)
		return 1
	}
	_, _ = os.Stdout.WriteString(out)
	return 0
}

func runCertd(args []string) {
	opts := certd.OptionsFromEnv()
	if len(args) == 1 && args[0] == "--renew" {
		os.Exit(certd.RenewCertificates(opts))
	}
	fs := flag.NewFlagSet("certd", flag.ExitOnError)
	fs.StringVar(&opts.SocketPath, "socket", opts.SocketPath, "AF_UNIX socket path")
	fs.StringVar(&opts.HAProxyCertsDir, "certs-dir", opts.HAProxyCertsDir, "HAProxy PEM directory")
	_ = fs.Parse(args)

	if err := certd.Run(opts); err != nil {
		log.Fatalf("certd error: %v", err)
	}
}

func runBackupd(args []string) {
	opts, err := backupd.OptionsFromEnv()
	if err != nil {
		log.Fatalf("Cannot start backup daemon: %v", err)
	}
	fs := flag.NewFlagSet("backupd", flag.ExitOnError)
	fs.StringVar(&opts.SocketPath, "socket", opts.SocketPath, "AF_UNIX socket path")
	fs.StringVar(&opts.SpoolRoot, "spool", opts.SpoolRoot, "backup spool root directory")
	_ = fs.Parse(args)

	if err := backupd.Run(opts); err != nil {
		log.Fatalf("backupd error: %v", err)
	}
}

func runUpdated(args []string) {
	opts, err := updated.OptionsFromEnv()
	if err != nil {
		log.Fatalf("Cannot start update broker: %v", err)
	}
	fs := flag.NewFlagSet("updated", flag.ExitOnError)
	fs.StringVar(&opts.SocketPath, "socket", opts.SocketPath, "AF_UNIX socket path")
	fs.StringVar(&opts.StateRoot, "state", opts.StateRoot, "update broker state root directory")
	_ = fs.Parse(args)

	if err := updated.Run(opts); err != nil {
		log.Fatalf("updated error: %v", err)
	}
}

func runAlertd(args []string) {
	opts := alertd.OptionsFromEnv()
	fs := flag.NewFlagSet("alertd", flag.ExitOnError)
	fs.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "path to alertd.json")
	fs.StringVar(&opts.SocketPath, "socket", opts.SocketPath, "AF_UNIX socket path")
	fs.StringVar(&opts.DatabasePath, "database", opts.DatabasePath, "path to the alert database (alerts.db)")
	_ = fs.Parse(args)

	if err := alertd.Run(opts); err != nil {
		log.Fatalf("alertd error: %v", err)
	}
}

func runControld(args []string) {
	opts := controld.OptionsFromEnv()
	fs := flag.NewFlagSet("controld", flag.ExitOnError)
	fs.StringVar(&opts.ControlSocket, "socket", opts.ControlSocket, "AF_UNIX control socket path")
	fs.StringVar(&opts.HAProxyCfgPath, "cfg", opts.HAProxyCfgPath, "path to haproxy.cfg")
	_ = fs.Parse(args)

	if err := controld.Run(opts); err != nil {
		log.Fatalf("controld error: %v", err)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func runHealthd(args []string) {
	fs := flag.NewFlagSet("healthd", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("HEALTHD_CONFIG", healthd.DefaultConfigPath), "path to healthd.json")
	sockPath := fs.String("socket", envOr("HEALTHD_SOCKET_PATH", healthd.DefaultSocketPath), "AF_UNIX socket path")
	selfUnit := fs.String("unit", envOr("HEALTHD_UNIT", healthd.DefaultHealthUnit), "own systemd unit name")
	_ = fs.Parse(args)

	cfg, err := healthd.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("healthd: %v", err)
	}
	state := healthd.NewState(cfg, strings.TrimSpace(*selfUnit), nil)
	state.ForceRefresh()
	ctx, cancel := signalContext()
	defer cancel()
	if strings.TrimSpace(os.Getenv("HEALTHD_BACKGROUND_POLL")) == "1" {
		go func() {
			t := time.NewTicker(time.Duration(cfg.PollIntervalSeconds) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					state.ForceRefresh()
				}
			}
		}()
	}
	go healthd.NewSiteAlerts(alerts.FromEnv()).Run(ctx)
	srv := &healthd.Server{State: state, ControlToken: strings.TrimSpace(os.Getenv("HEALTHD_TOKEN"))}
	log.Printf("haproxy-healthd (Go) listening on %s config=%s ttl=%ds", *sockPath, *cfgPath, cfg.CacheTTLSeconds)
	if err := srv.Serve(ctx, *sockPath); err != nil {
		log.Fatalf("healthd error: %v", err)
	}
}

func runMetricsd(_ []string) {
	if err := metricsd.Main(); err != nil {
		log.Fatalf("metricsd error: %v", err)
	}
}

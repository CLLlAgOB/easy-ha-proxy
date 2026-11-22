// Command easy-ha-proxy-agent is the unified static multi-call host daemon
// for easy-ha-proxy (healthd, metricsd, alertd, controld, certd, backupd, updated).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alertd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/backupd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/certd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/controld"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/healthd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/metricsd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updated"
)

const version = "0.3.0-alpha"

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
	case "probe-host":
		s, _ := metricsd.ReadHostSample(time.Now().Unix(), nil)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: easy-ha-proxy-agent <healthd|metricsd|alertd|controld|certd|backupd|updated|probe-host|version> [flags]")
}

func runCertd(args []string) {
	opts := certd.OptionsFromEnv()
	fs := flag.NewFlagSet("certd", flag.ExitOnError)
	fs.StringVar(&opts.SocketPath, "socket", opts.SocketPath, "AF_UNIX socket path")
	fs.StringVar(&opts.HAProxyCertsDir, "certs-dir", opts.HAProxyCertsDir, "HAProxy PEM directory")
	_ = fs.Parse(args)

	if err := certd.Run(opts); err != nil {
		log.Fatalf("certd error: %v", err)
	}
}

func runBackupd(args []string) {
	opts := backupd.OptionsFromEnv()
	fs := flag.NewFlagSet("backupd", flag.ExitOnError)
	fs.StringVar(&opts.SocketPath, "socket", opts.SocketPath, "AF_UNIX socket path")
	fs.StringVar(&opts.SpoolRoot, "spool", opts.SpoolRoot, "backup spool root directory")
	_ = fs.Parse(args)

	if err := backupd.Run(opts); err != nil {
		log.Fatalf("backupd error: %v", err)
	}
}

func runUpdated(args []string) {
	opts := updated.OptionsFromEnv()
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
	fs.StringVar(&opts.StatePath, "state", opts.StatePath, "path to persisted alert state JSON")
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

	cfg := healthd.LoadConfig(*cfgPath)
	col := healthd.NewCollector(cfg, *selfUnit, nil)
	srv := &healthd.Server{
		Collector:    col,
		ControlToken: os.Getenv("HEALTHD_TOKEN"),
		SelfUnit:     *selfUnit,
	}

	ctx, cancel := signalContext()
	defer cancel()
	log.Printf("easy-ha-proxy-agent healthd listening on %s", *sockPath)
	if err := srv.Serve(ctx, *sockPath); err != nil {
		log.Fatalf("healthd error: %v", err)
	}
}

func runMetricsd(args []string) {
	fs := flag.NewFlagSet("metricsd", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("METRICSD_CONFIG", metricsd.DefaultConfigPath), "path to metricsd.json")
	sockPath := fs.String("socket", envOr("METRICSD_SOCKET_PATH", metricsd.DefaultSocketPath), "AF_UNIX socket path")
	_ = fs.Parse(args)

	cfg := metricsd.LoadConfig(*cfgPath)
	col := metricsd.NewCollector(cfg, haproxy.NewClient(cfg.HAProxySocket))
	srv := &metricsd.Server{Collector: col}

	ctx, cancel := signalContext()
	defer cancel()

	go func() {
		ticker := time.NewTicker(time.Duration(cfg.PollIntervalSeconds) * time.Second)
		defer ticker.Stop()
		_ = col.PollOnce(ctx, time.Now().Unix())
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				_ = col.PollOnce(ctx, t.Unix())
			}
		}
	}()

	log.Printf("easy-ha-proxy-agent metricsd listening on %s", *sockPath)
	if err := srv.Serve(ctx, *sockPath); err != nil {
		log.Fatalf("metricsd error: %v", err)
	}
}

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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alertd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/authelia"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/backupd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/certd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/controld"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/healthd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/metricsd"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updated"
)

const version = "0.7.1-alpha"

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
	fmt.Fprintln(os.Stderr, "usage: easy-ha-proxy-agent <healthd|metricsd|alertd|controld|certd|backupd|updated|authelia-bansd|authelia-usersd|authelia-configd|unit-failed|backup-run|server-state|udp-forward|cert-deliver|update-geoip|probe-host|version> [flags]")
}

func runUDPForward(args []string) int {
	opts := tools.UDPForwardOptionsFromEnv()
	fs := flag.NewFlagSet("udp-forward", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "print planned iptables rules")
	checkOnly := fs.Bool("check", false, "validate udp.yml only")
	healthTargets := fs.Bool("health-targets", false, "print failover probe targets as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	out, err := tools.ApplyUDPForwards(context.Background(), opts, *dryRun, *checkOnly, *healthTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[easy-ha-proxy-udp] ERROR: %v\n", err)
		return 1
	}
	_, _ = os.Stdout.WriteString(out)
	return 0
}

func runCertDeliver(args []string) int {
	opts := tools.CertDeliverOptionsFromEnv()
	fs := flag.NewFlagSet("cert-deliver", flag.ContinueOnError)
	lineage := fs.String("lineage", os.Getenv("RENEWED_LINEAGE"), "path to certbot lineage directory")
	targetName := fs.String("target", "", "deliver only to this named target")
	domainsStr := fs.String("domains", os.Getenv("RENEWED_DOMAINS"), "space-separated renewed domains")
	if err := fs.Parse(args); err != nil || *lineage == "" {
		fmt.Fprintln(os.Stderr, "usage: easy-ha-proxy-agent cert-deliver --lineage <dir> [--target <name>] [--domains '...']")
		return 2
	}
	targets, err := tools.LoadDeliveryTargets(opts.DestinationsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert-deliver: %v\n", err)
		return 1
	}
	domains := strings.Fields(*domainsStr)
	failed := 0
	for _, t := range targets {
		if *targetName != "" && t.Name != *targetName {
			continue
		}
		if *targetName == "" && (!t.Enabled || (len(domains) > 0 && !tools.TargetWantsDomains(t, domains))) {
			continue
		}
		if err := tools.DeliverTarget(context.Background(), opts, *lineage, t); err != nil {
			fmt.Fprintf(os.Stderr, "cert-deliver [%s]: %v\n", t.Name, err)
			failed++
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

type multiStringFlag []string

func (m *multiStringFlag) String() string { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func runUpdateGeoIP(args []string) int {
	fs := flag.NewFlagSet("update-geoip", flag.ContinueOnError)
	dir := fs.String("directory", "/etc/haproxy/geoip", "GeoIP directory")
	baseURL := fs.String("base-url", "https://download.db-ip.com/free", "DB-IP base URL")
	selFile := fs.String("selection-file", "", "selection.json path")
	cfgSel := fs.Bool("configure-selection", false, "update selection.json and exit")
	accessFilter := fs.Bool("access-filter-enabled", false, "enable country access filter")
	_ = fs.Bool("force-download", false, "force download")
	_ = fs.Bool("skip-reload", false, "skip HAProxy reload")
	_ = fs.String("vars-file", "", "vars.yml path")
	_ = fs.String("config-transaction-state", "", "transaction state path")
	_ = fs.String("config-transaction-id", "", "transaction id")
	_ = fs.String("haproxy", "/usr/sbin/haproxy", "haproxy binary")
	_ = fs.String("haproxy-config", "/etc/haproxy/haproxy.cfg", "haproxy config path")
	_ = fs.String("systemctl", "/usr/bin/systemctl", "systemctl binary")
	var countries multiStringFlag
	fs.Var(&countries, "country", "ISO-3166-1 alpha-2 country code (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	selPath := *selFile
	if selPath == "" {
		selPath = filepath.Join(*dir, "selection.json")
	}
	if *cfgSel {
		sel, err := tools.SaveGeoIPSelection(selPath, countries, *accessFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[easy-ha-proxy-geoip] ERROR: %v\n", err)
			return 1
		}
		fmt.Printf("[easy-ha-proxy-geoip] Saved selection: %v (filter=%v)\n", sel.Countries, sel.AccessFilterEnabled)
		return 0
	}
	sel, err := tools.LoadGeoIPSelection(selPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[easy-ha-proxy-geoip] ERROR: %v\n", err)
		return 1
	}
	period := time.Now().UTC().Format("2006-01")
	url := fmt.Sprintf("%s/dbip-country-lite-%s.mmdb.gz", *baseURL, period)
	raw, err := tools.DownloadDBIPGzip(context.Background(), url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[easy-ha-proxy-geoip] ERROR: %v\n", err)
		return 1
	}
	relID, err := tools.PublishGeoIPRelease(*dir, period, raw, sel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[easy-ha-proxy-geoip] ERROR: %v\n", err)
		return 1
	}
	fmt.Printf("[easy-ha-proxy-geoip] Activated GeoIP release %s\n", relID)
	return 0
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

func runMetricsd(args []string) {
	fs := flag.NewFlagSet("metricsd", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("METRICSD_CONFIG", metricsd.DefaultConfigPath), "path to metricsd.json")
	sockPath := fs.String("socket", envOr("METRICSD_SOCKET_PATH", metricsd.DefaultSocketPath), "AF_UNIX socket path")
	dbPath := envOr("METRICSD_DATABASE", "/var/lib/easy-ha-proxy/metrics/metrics.db")
	storePath := fs.String("store", envOr("METRICSD_STORE", filepath.Join(filepath.Dir(dbPath), "metrics-store.json")), "path to persisted metrics store")
	_ = fs.Parse(args)

	cfg := metricsd.LoadConfig(*cfgPath)
	ctx, cancel := signalContext()
	defer cancel()

	if !cfg.Enabled {
		log.Printf("easy-ha-proxy-agent metricsd disabled in %s; idling", *cfgPath)
		<-ctx.Done()
		return
	}

	store, err := metricsd.NewStore(*storePath, cfg)
	if err != nil {
		log.Fatalf("metricsd store error: %v", err)
	}
	col := metricsd.NewCollectorWithStore(cfg, haproxy.NewClient(cfg.HAProxySocket), store, alerts.FromEnv())
	srv := &metricsd.Server{Collector: col}

	go func() {
		pollTicker := time.NewTicker(time.Duration(cfg.PollIntervalSeconds) * time.Second)
		defer pollTicker.Stop()
		maintInterval := time.Duration(cfg.MaintenanceIntervalSeconds) * time.Second
		if maintInterval <= 0 {
			maintInterval = 5 * time.Minute
		}
		maintTicker := time.NewTicker(maintInterval)
		defer maintTicker.Stop()

		now := time.Now().Unix()
		col.EvaluateStorageAlerts(ctx, now)
		_ = col.PollOnce(ctx, now)
		for {
			select {
			case <-ctx.Done():
				store.Flush()
				return
			case t := <-pollTicker.C:
				_ = col.PollOnce(ctx, t.Unix())
			case t := <-maintTicker.C:
				col.EvaluateStorageAlerts(ctx, t.Unix())
				store.Prune(t.Unix())
			}
		}
	}()

	log.Printf("easy-ha-proxy-agent metricsd listening on %s store=%s", *sockPath, *storePath)
	if err := srv.Serve(ctx, *sockPath); err != nil {
		log.Fatalf("metricsd error: %v", err)
	}
}

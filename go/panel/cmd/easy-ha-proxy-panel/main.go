// Command easy-ha-proxy-panel runs the native Go web admin panel for
// easy-ha-proxy and provides a built-in low-overhead container healthcheck.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"easy-ha-proxy/panel/internal/app"
	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/security"
	"easy-ha-proxy/panel/internal/server"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = strings.ToLower(strings.TrimSpace(os.Args[1]))
	}

	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("easy-ha-proxy-panel %s\n", config.Version)
	case "healthcheck":
		if err := runHealthcheck(); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(); err != nil {
			log.Fatalf("easy-ha-proxy-panel: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (expected: serve, healthcheck, version)\n", cmd)
		os.Exit(2)
	}
}

func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	app.EnsureWhitelistFile()
	app.StartTrashPurger()
	srv := server.New(cfg, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("easy-ha-proxy-panel %s listening on %s", config.Version, cfg.ListenAddr)
	return srv.ListenAndServe(ctx)
}

func runHealthcheck() error {
	secret := strings.TrimSpace(os.Getenv("HAPROXY_ADMIN_PROXY_SECRET"))
	if secret == "" {
		return fmt.Errorf("HAPROXY_ADMIN_PROXY_SECRET is empty")
	}
	addr := strings.TrimSpace(os.Getenv("HAPROXY_ADMIN_HEALTHCHECK_URL"))
	if addr == "" {
		addr = "http://127.0.0.1:5000" + security.ControlPlaneHealthPath
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return err
	}
	req.Header.Set(security.ProxySecretHeader, secret)
	req.Header.Set("Remote-User", security.ControlPlaneHealthUser)
	req.Header.Set("Remote-Groups", security.ControlPlaneHealthGroup)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("invalid JSON response: %w", err)
	}
	if okVal, _ := payload["ok"].(bool); !okVal {
		return fmt.Errorf("health response ok != true")
	}
	return nil
}

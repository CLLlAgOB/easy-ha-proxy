package certd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

var domainRe = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// IssueRequest holds parameters for POST /api/v1/certs/issue.
type IssueRequest struct {
	Domains    []string `json:"domains"`
	Email      string   `json:"email"`
	Challenge  string   `json:"challenge"` // "http-01" or "dns-01"
	DNSProfile string   `json:"dns_profile"`
	DryRun     bool     `json:"dry_run"`
}

// IssueWithCertbot runs certbot certonly with bounded timeout and ephemeral DNS-01 creds.
func (m *Manager) IssueWithCertbot(ctx context.Context, req IssueRequest) (map[string]any, error) {
	if len(req.Domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	cleanDomains := make([]string, 0, len(req.Domains))
	for _, d := range req.Domains {
		c := strings.ToLower(strings.TrimSpace(d))
		if !domainRe.MatchString(c) {
			return nil, fmt.Errorf("invalid domain name: %q", d)
		}
		cleanDomains = append(cleanDomains, c)
	}

	args := []string{"certonly", "--non-interactive", "--agree-tos"}
	if strings.TrimSpace(req.Email) != "" {
		args = append(args, "--email", strings.TrimSpace(req.Email))
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	if req.DryRun || m.Opts.DryRun {
		args = append(args, "--dry-run")
	}

	challenge := strings.ToLower(strings.TrimSpace(req.Challenge))
	if challenge == "" {
		challenge = "http-01"
	}

	var cleanupCreds func()
	if challenge == "dns-01" {
		if !DNSProfileRe.MatchString(req.DNSProfile) {
			return nil, errors.New("valid dns_profile is required for dns-01")
		}
		profPath := filepath.Join(m.Opts.DNSCredsDir, req.DNSProfile+".json")
		raw, err := os.ReadFile(profPath)
		if err != nil {
			return nil, fmt.Errorf("DNS profile %q not found", req.DNSProfile)
		}
		var prof DNSProfile
		if err := json.Unmarshal(raw, &prof); err != nil {
			return nil, err
		}
		spec, ok := DNSProviders[prof.Provider]
		if !ok {
			return nil, fmt.Errorf("unsupported DNS provider %q", prof.Provider)
		}
		tmpCred, err := os.CreateTemp("", ".certbot-dns-*.ini")
		if err != nil {
			return nil, err
		}
		credPath := tmpCred.Name()
		cleanupCreds = func() { _ = os.Remove(credPath) }
		var ini strings.Builder
		for _, k := range spec.Keys {
			if v := prof.Credentials[k]; v != "" {
				fmt.Fprintf(&ini, "%s = %s\n", k, v)
			}
		}
		_, _ = tmpCred.WriteString(ini.String())
		_ = tmpCred.Chmod(0o600)
		_ = tmpCred.Close()

		prop := prof.Propagation
		if prop < DNSPropagationMin {
			prop = DNSPropagationDefault
		}
		args = append(args,
			"--"+spec.Plugin,
			"--"+spec.Plugin+"-credentials", credPath,
			"--"+spec.Plugin+"-propagation-seconds", fmt.Sprintf("%d", prop),
		)
	} else {
		args = append(args, "--standalone", "--http-01-port", "8000", "--http-01-address", "0.0.0.0")
	}
	if cleanupCreds != nil {
		defer cleanupCreds()
	}

	for _, d := range cleanDomains {
		args = append(args, "-d", d)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, m.Opts.CertbotBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		if m.Alerts != nil && m.Alerts.Enabled() {
			m.Alerts.Observe(ctx, alerts.Observation{
				Rule:    "certificate.renewal_failed",
				Subject: cleanDomains[0],
				Summary: fmt.Sprintf("Certificate issuance failed for %s", cleanDomains[0]),
				Detail:  detail,
			})
		}
		return map[string]any{
			"ok":      false,
			"error":   detail,
			"stdout":  stdout.String(),
			"stderr":  stderr.String(),
			"domains": cleanDomains,
		}, nil
	}
	return map[string]any{
		"ok":      true,
		"domains": cleanDomains,
		"stdout":  stdout.String(),
	}, nil
}

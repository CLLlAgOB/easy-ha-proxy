package tools

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var certTargetNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// CertDeliveryTarget describes one remote machine receiving renewed certificates.
type CertDeliveryTarget struct {
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	User        string   `json:"user"`
	Transport   string   `json:"transport"`   // "sftp" or "scp"
	Format      string   `json:"format"`      // "pfx", "pem-pair", or "pem-combined"
	RemotePath  string   `json:"remote_path"`
	PFXPassword string   `json:"pfx_password"`
	Domains     []string `json:"domains"`
	PostCommand string   `json:"post_command,omitempty"`
}

// CertDeliverOptions configures the cert-deliver tool.
type CertDeliverOptions struct {
	DestinationsDir string
	Timeout         time.Duration
	OpenSSLBin      string
	SFTPBin         string
	SCPBin          string
	SSHBin          string
}

// CertDeliverOptionsFromEnv reads CERT_DESTINATIONS_DIR and CERT_DELIVER_TIMEOUT.
func CertDeliverOptionsFromEnv() CertDeliverOptions {
	dir := strings.TrimSpace(os.Getenv("CERT_DESTINATIONS_DIR"))
	if dir == "" {
		dir = "/etc/easy-ha-proxy/cert-destinations"
	}
	secs := 120
	if raw := strings.TrimSpace(os.Getenv("CERT_DELIVER_TIMEOUT")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			secs = n
		}
	}
	return CertDeliverOptions{
		DestinationsDir: dir,
		Timeout:         time.Duration(secs) * time.Second,
		OpenSSLBin:      "openssl",
		SFTPBin:         "sftp",
		SCPBin:          "scp",
		SSHBin:          "ssh",
	}
}

// CertificateDNSNames reads DNS SANs from lineage/fullchain.pem natively using crypto/x509.
func CertificateDNSNames(lineage string) ([]string, error) {
	chainPath := filepath.Join(lineage, "fullchain.pem")
	raw, err := os.ReadFile(chainPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", chainPath, err)
	}
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate in %s: %w", chainPath, err)
		}
		seen := make(map[string]struct{}, len(cert.DNSNames))
		for _, n := range cert.DNSNames {
			seen[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
		}
		out := make([]string, 0, len(seen))
		for n := range seen {
			out = append(out, n)
		}
		sort.Strings(out)
		return out, nil
	}
	return nil, fmt.Errorf("no CERTIFICATE block in %s", chainPath)
}

// NameCovered reports whether a certificate holding `held` DNS names covers `name`,
// with wildcards matching exactly one label (matching TLS client rules).
func NameCovered(name string, held []string) bool {
	target := strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, entry := range held {
		if entry == target {
			return true
		}
		if strings.HasPrefix(entry, "*.") {
			if _, rest, ok := strings.Cut(target, "."); ok && rest == entry[2:] {
				return true
			}
		}
	}
	return false
}

// UncoveredNames returns target domains not covered by lineage's certificate.
func UncoveredNames(target CertDeliveryTarget, lineage string) ([]string, error) {
	held, err := CertificateDNSNames(lineage)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, d := range target.Domains {
		clean := strings.ToLower(strings.TrimSpace(d))
		if clean == "" {
			continue
		}
		if !NameCovered(clean, held) {
			missing = append(missing, clean)
		}
	}
	return missing, nil
}

// TargetWantsDomains returns true when any renewed domain matches target.Domains (exact, never substring).
func TargetWantsDomains(target CertDeliveryTarget, domains []string) bool {
	wanted := make(map[string]struct{}, len(target.Domains))
	for _, d := range target.Domains {
		if c := strings.ToLower(strings.TrimSpace(d)); c != "" {
			wanted[c] = struct{}{}
		}
	}
	for _, d := range domains {
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(d))]; ok {
			return true
		}
	}
	return false
}

// ArtefactPair pairs a local staging file with its destination remote path.
type ArtefactPair struct {
	LocalPath  string
	RemotePath string
}

// BuildCertArtefacts prepares pem-combined, pem-pair, or password-piped PKCS#12 files in workdir.
func BuildCertArtefacts(ctx context.Context, lineage string, target CertDeliveryTarget, workdir string, opensslBin string) ([]ArtefactPair, error) {
	fullchain := filepath.Join(lineage, "fullchain.pem")
	privkey := filepath.Join(lineage, "privkey.pem")
	fcBytes, err := os.ReadFile(fullchain)
	if err != nil {
		return nil, fmt.Errorf("%s is missing", fullchain)
	}
	pkBytes, err := os.ReadFile(privkey)
	if err != nil {
		return nil, fmt.Errorf("%s is missing", privkey)
	}

	fmtName := strings.ToLower(strings.TrimSpace(target.Format))
	if fmtName == "" {
		fmtName = "pfx"
	}
	remote := strings.TrimSpace(target.RemotePath)
	if remote == "" {
		return nil, errors.New("remote_path is required")
	}

	switch fmtName {
	case "pem-combined":
		out := filepath.Join(workdir, "certificate.pem")
		combined := append(append([]byte(nil), fcBytes...), pkBytes...)
		if err := os.WriteFile(out, combined, 0o600); err != nil {
			return nil, err
		}
		return []ArtefactPair{{LocalPath: out, RemotePath: remote}}, nil

	case "pem-pair":
		chainOut := filepath.Join(workdir, "fullchain.pem")
		keyOut := filepath.Join(workdir, "privkey.pem")
		if err := os.WriteFile(chainOut, fcBytes, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyOut, pkBytes, 0o600); err != nil {
			return nil, err
		}
		base := strings.TrimRight(remote, "/")
		return []ArtefactPair{
			{LocalPath: chainOut, RemotePath: base + "/fullchain.pem"},
			{LocalPath: keyOut, RemotePath: base + "/privkey.pem"},
		}, nil

	case "pfx":
		if strings.ContainsAny(target.PFXPassword, "\r\n") {
			return nil, errors.New("the PFX password cannot contain a line break")
		}
		out := filepath.Join(workdir, "certificate.pfx")
		if opensslBin == "" {
			opensslBin = "openssl"
		}
		// Pass password via pipe FD (fd:3 via ExtraFiles) so it never appears in /proc/<pid>/cmdline.
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		_, _ = pw.WriteString(target.PFXPassword + "\n")
		_ = pw.Close()
		defer pr.Close()

		cmdCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(
			cmdCtx, opensslBin, "pkcs12", "-export",
			"-inkey", privkey, "-in", fullchain, "-out", out, "-passout", "fd:3",
		)
		cmd.ExtraFiles = []*os.File{pr}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("openssl could not build PKCS#12: %s", strings.TrimSpace(stderr.String()))
		}
		_ = os.Chmod(out, 0o600)
		return []ArtefactPair{{LocalPath: out, RemotePath: remote}}, nil

	default:
		return nil, fmt.Errorf("format must be one of pfx, pem-pair, pem-combined")
	}
}

// DeliverTarget uploads prepared artefacts for one target via pinned-hostkey SFTP or SCP.
func DeliverTarget(ctx context.Context, opts CertDeliverOptions, lineage string, target CertDeliveryTarget) error {
	name := strings.ToLower(strings.TrimSpace(target.Name))
	if !certTargetNameRe.MatchString(name) {
		return errors.New("invalid delivery target name")
	}
	missing, err := UncoveredNames(target, lineage)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("certificate does not cover target domain(s): %s", strings.Join(missing, ", "))
	}

	workdir, err := os.MkdirTemp("", "cert-deliver-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workdir)

	artefacts, err := BuildCertArtefacts(ctx, lineage, target, workdir, opts.OpenSSLBin)
	if err != nil {
		return err
	}

	keyPath := filepath.Join(opts.DestinationsDir, name+".key")
	khPath := filepath.Join(opts.DestinationsDir, name+".known_hosts")
	port := target.Port
	if port <= 0 {
		port = 22
	}
	host := strings.TrimSpace(target.Host)
	user := strings.TrimSpace(target.User)
	if host == "" || user == "" {
		return errors.New("target host and user are required")
	}
	remoteSpec := user + "@" + host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		remoteSpec = fmt.Sprintf("%s@[%s]", user, host)
	}

	baseArgs := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + khPath,
		"-o", "ConnectTimeout=15",
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := strings.ToLower(strings.TrimSpace(target.Transport))
	if transport == "" {
		transport = "sftp"
	}
	switch transport {
	case "scp":
		for _, a := range artefacts {
			args := append([]string{"-P", strconv.Itoa(port)}, baseArgs...)
			args = append(args, a.LocalPath, fmt.Sprintf("%s:%s", remoteSpec, a.RemotePath))
			var stderr bytes.Buffer
			cmd := exec.CommandContext(cmdCtx, opts.SCPBin, args...)
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("scp failed: %s", strings.TrimSpace(stderr.String()))
			}
		}
	case "sftp":
		var batch strings.Builder
		for _, a := range artefacts {
			fmt.Fprintf(&batch, "put %q %q\n", a.LocalPath, a.RemotePath)
		}
		args := append([]string{"-P", strconv.Itoa(port), "-b", "-"}, baseArgs...)
		args = append(args, remoteSpec)
		var stderr bytes.Buffer
		cmd := exec.CommandContext(cmdCtx, opts.SFTPBin, args...)
		cmd.Stdin = strings.NewReader(batch.String())
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("sftp failed: %s", strings.TrimSpace(stderr.String()))
		}
	default:
		return errors.New("transport must be sftp or scp")
	}
	return nil
}

// LoadDeliveryTargets lists all JSON targets from DestinationsDir.
func LoadDeliveryTargets(dir string) ([]CertDeliveryTarget, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []CertDeliveryTarget{}, nil
		}
		return nil, err
	}
	var out []CertDeliveryTarget
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		var t CertDeliveryTarget
		if json.Unmarshal(raw, &t) == nil {
			t.Name = strings.TrimSuffix(ent.Name(), ".json")
			out = append(out, t)
		}
	}
	return out, nil
}

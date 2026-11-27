package certd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/hostfile"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// valueErr is Python's ValueError: a request problem reported to the caller.
type valueErr struct{ msg string }

func (e *valueErr) Error() string { return e.msg }

func vErr(format string, args ...any) error {
	if len(args) > 0 {
		return &valueErr{fmt.Sprintf(format, args...)}
	}
	return &valueErr{format}
}

// vErrS is a ValueError with a ready message.
func vErrS(msg string) error { return &valueErr{msg} }

func isValueErr(err error) bool {
	var ve *valueErr
	return errors.As(err, &ve)
}

// alertSink is the part of the alert client certd uses.
type alertSink interface {
	Enabled() bool
	Observe(ctx context.Context, obs alerts.Observation) bool
}

func (d *Daemon) alertsOn() bool { return d.alertsClient != nil && d.alertsClient.Enabled() }

func (d *Daemon) observe(obs alerts.Observation) {
	if !d.alertsOn() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.alertsClient.Observe(ctx, obs)
}

func (d *Daemon) reportAlert(rule, subject, summary, detail string) {
	d.observe(alerts.Observation{Rule: rule, Subject: subject, Summary: summary, Detail: detail})
}

// loadYAML is _load_yaml: {} for a missing or unreadable file.
func loadYAML(path string) map[string]any {
	data, err := readYAML(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Failed to load YAML %s: %v", path, err)
		}
		return map[string]any{}
	}
	return data
}

func readYAML(path string) (map[string]any, error) {
	raw, err := hostfile.ReadRegular(path, 16<<20)
	if err != nil {
		return nil, err
	}
	var data any
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	switch v := data.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return v, nil
	default:
		return map[string]any{"_": v}, nil
	}
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false))

// normalizeDNSName is _normalize_dns_name.
func normalizeDNSName(value string, allowWildcard bool) (string, error) {
	name := strings.ToLower(strings.TrimRight(strings.TrimSpace(value), "."))
	if name == "" || len([]rune(name)) > 253 || strings.ContainsAny(name, "/\\\x00\r\n") {
		return "", vErr("invalid DNS name")
	}
	if strings.HasPrefix(name, "*.") {
		if !allowWildcard {
			return "", vErr("a wildcard name is not allowed here")
		}
		remainder := name[2:]
		if strings.Contains(remainder, "*") {
			return "", vErr("only one wildcard label is allowed")
		}
		base, err := normalizeDNSName(remainder, false)
		if err != nil {
			return "", err
		}
		if len(strings.Split(base, ".")) < 2 {
			return "", vErr("a wildcard needs at least two labels beneath it")
		}
		return "*." + base, nil
	}
	if strings.Contains(name, "*") {
		return "", vErr("a wildcard is only allowed as the leftmost label")
	}
	asciiName := name
	if !isASCII(name) {
		converted, err := idnaProfile.ToASCII(name)
		if err != nil {
			return "", vErr("invalid internationalized DNS name")
		}
		asciiName = converted
	}
	labels := strings.Split(asciiName, ".")
	if len(labels) < 2 {
		return "", vErr("DNS name must contain at least two labels")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", vErr("invalid DNS label")
		}
		for _, r := range label {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
				return "", vErr("invalid DNS label")
			}
		}
	}
	return asciiName, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// safeSlug is _safe_slug.
func safeSlug(value string) (string, error) {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	slug := strings.Trim(b.String(), ".-_")
	slug = pyx.TruncRunes(slug, 120)
	if slug == "" || slug == "." || slug == ".." {
		return "", vErr("invalid certificate name")
	}
	return slug, nil
}

func mustSlug(value string) string {
	s, err := safeSlug(value)
	if err != nil {
		return ""
	}
	return s
}

// resolvePath is Path.resolve(strict=False).
func resolvePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	// Resolve the deepest existing parent, keep the rest.
	dir, rest := abs, ""
	for {
		parent := filepath.Dir(dir)
		rest = filepath.Join(filepath.Base(dir), rest)
		if parent == dir {
			return abs
		}
		dir = parent
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(r, rest)
		}
	}
}

// ensureWithin is _ensure_within: the resolved candidate, inside base.
func ensureWithin(base, candidate string) (string, error) {
	baseResolved := resolvePath(base)
	target := resolvePath(candidate)
	rel, err := filepath.Rel(baseResolved, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", vErr("path escapes protected directory: %s", candidate)
	}
	return target, nil
}

type procResult struct {
	rc             int
	stdout, stderr []byte
	args           []string
}

// runBounded is _run_bounded: its own process group, killed whole on timeout.
func runBounded(argv []string, timeout time.Duration, env []string) (procResult, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Stdin = nil
	if env != nil {
		cmd.Env = env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return procResult{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		rc := 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				rc = ee.ExitCode()
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					rc = -int(ws.Signal())
				}
			} else {
				return procResult{}, err
			}
		}
		return procResult{rc: rc, stdout: out.Bytes(), stderr: errb.Bytes(), args: argv}, nil
	case <-time.After(timeout):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		note := fmt.Sprintf("%s did not finish within %d seconds and was stopped", filepath.Base(argv[0]), int(timeout.Seconds()))
		log.Printf("%s: %s", note, strings.Join(argv, " "))
		stderr := errb.Bytes()
		if len(stderr) > 0 {
			stderr = append(append(stderr, '\n'), note...)
		} else {
			stderr = []byte(note)
		}
		return procResult{rc: timedOutRC, stdout: out.Bytes(), stderr: stderr, args: argv}, nil
	}
}

// writePrivateFile is _write_private_file.
func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// writeModeFile writes path with mode set before content lands.
func writeModeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func lexists(path string) bool { _, err := os.Lstat(path); return err == nil }

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func globSorted(pattern string) []string {
	matches, _ := filepath.Glob(pattern)
	return matches
}

func stem(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// ---------------------------------------------------------------------------
// Certificate information
// ---------------------------------------------------------------------------

type certInfo struct {
	Path      string
	NotAfter  time.Time
	DaysLeft  int
	Lifetime  *int
	WarnDays  int
	HasLeaf   bool
	NotBefore time.Time
}

// pyDays is timedelta.days: floored.
func pyDays(d time.Duration) int {
	return int(math.Floor(d.Seconds() / 86400))
}

// firstCertificate is _load_first_cert_from_pem / the ssl test decoder: the
// first CERTIFICATE block of a file.
func firstCertificate(path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return firstCertificateIn(data)
}

func firstCertificateIn(data []byte) *x509.Certificate {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}

// loadCertInfo is _load_cert_info (second precision, as OpenSSL prints it).
func loadCertInfo(path string) *certInfo {
	if path == "" {
		return nil
	}
	cert := firstCertificate(path)
	if cert == nil {
		return nil
	}
	notAfter := cert.NotAfter.UTC().Truncate(time.Second)
	notBefore := cert.NotBefore.UTC().Truncate(time.Second)
	days := pyDays(notAfter.Sub(time.Now().UTC()))
	lifetime := pyDays(notAfter.Sub(notBefore))
	return &certInfo{Path: path, NotAfter: notAfter, DaysLeft: days, Lifetime: &lifetime,
		WarnDays: certWarnDaysFor(&lifetime), NotBefore: notBefore}
}

func fmtDate(t time.Time) string { return t.UTC().Format("2006-01-02") }

// pyDatetime is str(datetime) for an aware UTC value.
func pyDatetime(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02 15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02 15:04:05.000000") + "+00:00"
}

// certDNSNames is _get_cert_dns_names: SANs and CN, lower case (sorted here;
// Python's set order is arbitrary).
func certDNSNames(cert *x509.Certificate) []string {
	seen := map[string]bool{}
	for _, n := range cert.DNSNames {
		seen[strings.ToLower(n)] = true
	}
	for _, attr := range cert.Subject.Names {
		if attr.Type.Equal([]int{2, 5, 4, 3}) {
			if s, ok := attr.Value.(string); ok && s != "" {
				seen[strings.ToLower(s)] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

package tools

// The native easy-ha-proxy-cert-deliver: a line-for-line port of
// ansible/roles/haproxy-admin/files/easy-ha-proxy-cert-deliver.py, which
// stays the specification. Certbot's 906 deploy hook runs it with the renewed
// lineage and domains, and certd runs it with --target when the operator
// sends to one target from the interface. certd shows what it writes to
// stderr as the target's last result, so the log lines are the Python ones.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/netpolicy"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

var (
	certTargetNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	certTargetUserRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@\\-]{0,127}$`)
	certDNSNameRe     = regexp.MustCompile(`DNS:([^\s,]+)`)
	certControlCharRe = regexp.MustCompile("[\x00-\x1f\x7f]")
)

var certFormats = []string{"pfx", "pem-pair", "pem-combined"}
var certTransports = []string{"sftp", "scp"}

// CertDeliverOptions configures the cert-deliver tool. The binaries are the
// ones the Python worker runs; tests point them at fakes.
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
	dir := os.Getenv("CERT_DESTINATIONS_DIR")
	if dir == "" {
		dir = "/etc/easy-ha-proxy/cert-destinations"
	}
	secs := 120
	if raw, ok := os.LookupEnv("CERT_DELIVER_TIMEOUT"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			secs = n
		}
	}
	return CertDeliverOptions{
		DestinationsDir: dir,
		Timeout:         time.Duration(secs) * time.Second,
		OpenSSLBin:      "openssl",
		SFTPBin:         "/usr/bin/sftp",
		SCPBin:          "/usr/bin/scp",
		SSHBin:          "/usr/bin/ssh",
	}
}

// certDeliveryError is Python's DeliveryError: something the operator can fix.
type certDeliveryError struct{ msg string }

func (e *certDeliveryError) Error() string { return e.msg }

func deliveryErr(format string, a ...any) error {
	return &certDeliveryError{msg: fmt.Sprintf(format, a...)}
}

type certLogger struct{ w io.Writer }

func (l certLogger) log(level, format string, a ...any) {
	fmt.Fprintf(l.w, "cert-deliver: %s %s\n", level, fmt.Sprintf(format, a...))
}

func (o CertDeliverOptions) keyPath(name string) string {
	return filepath.Join(o.DestinationsDir, name+".key")
}

func (o CertDeliverOptions) knownHostsPath(name string) string {
	return filepath.Join(o.DestinationsDir, name+".known_hosts")
}

func certIsFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func certIsDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func certValidName(value any) (string, error) {
	text := strings.ToLower(strings.TrimSpace(pyx.StrOr(value)))
	if !certTargetNameRe.MatchString(text) {
		return "", deliveryErr("name must be 1-40 characters of a-z, 0-9 and -, starting with a letter or digit")
	}
	return text, nil
}

func readCertRecord(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, err
	}
	record := pyx.Map(v)
	if record == nil {
		return nil, fmt.Errorf("%s does not hold a JSON object", path)
	}
	record["name"] = strings.TrimSuffix(filepath.Base(path), ".json")
	return record, nil
}

func (o CertDeliverOptions) loadDestination(name string) (map[string]any, error) {
	checked, err := certValidName(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(o.DestinationsDir, checked+".json")
	if !certIsFile(path) {
		return nil, deliveryErr("no delivery target named %s", name)
	}
	return readCertRecord(path)
}

func (o CertDeliverOptions) listDestinations(lg certLogger) []map[string]any {
	if !certIsDir(o.DestinationsDir) {
		return nil
	}
	entries, err := os.ReadDir(o.DestinationsDir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".json") {
			names = append(names, ent.Name())
		}
	}
	sort.Strings(names)
	var found []map[string]any
	for _, n := range names {
		path := filepath.Join(o.DestinationsDir, n)
		record, err := readCertRecord(path)
		if err != nil {
			lg.log("WARNING", "cannot read %s (%v); skipping", path, err)
			continue
		}
		found = append(found, record)
	}
	return found
}

func recordStrings(record map[string]any, key string) []string {
	var out []string
	if !pyx.Truthy(record[key]) {
		return out
	}
	for _, d := range pyx.List(record[key]) {
		out = append(out, pyx.Str(d))
	}
	return out
}

func recordStr(record map[string]any, key, def string) string {
	if v := record[key]; pyx.Truthy(v) {
		return pyx.Str(v)
	}
	return def
}

// certWantsDomain: matched whole, never as a substring.
func certWantsDomain(record map[string]any, domains []string) bool {
	wanted := map[string]struct{}{}
	for _, d := range recordStrings(record, "domains") {
		if c := strings.ToLower(strings.TrimSpace(d)); c != "" {
			wanted[c] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return false
	}
	for _, d := range domains {
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(d))]; ok {
			return true
		}
	}
	return false
}

// certificateNames: the DNS names in the lineage's certificate, as openssl reads them.
func (o CertDeliverOptions) certificateNames(lineage string) ([]string, error) {
	chain := filepath.Join(lineage, "fullchain.pem")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.OpenSSLBin, "x509", "-in", chain, "-noout", "-text")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, deliveryErr("openssl could not read %s: Command '%s' timed out after 30 seconds", chain, o.OpenSSLBin)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return nil, deliveryErr("openssl could not read %s: %v", chain, err)
	}
	if err != nil {
		return nil, deliveryErr("openssl could not read %s: %s", chain, strings.TrimSpace(strings.ToValidUTF8(stderr.String(), "�")))
	}
	seen := map[string]struct{}{}
	for _, m := range certDNSNameRe.FindAllStringSubmatch(strings.ToValidUTF8(stdout.String(), "�"), -1) {
		seen[strings.ToLower(m[1])] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// NameCovered reports whether a certificate holding `held` is valid for
// `name`. A wildcard stands for exactly one label, as TLS clients read it.
func NameCovered(name string, held []string) bool {
	name = strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, entry := range held {
		if entry == name {
			return true
		}
		if strings.HasPrefix(entry, "*.") {
			if _, rest, ok := strings.Cut(name, "."); ok && rest == entry[2:] {
				return true
			}
		}
	}
	return false
}

func (o CertDeliverOptions) uncoveredNames(record map[string]any, lineage string) ([]string, error) {
	held, err := o.certificateNames(lineage)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, d := range recordStrings(record, "domains") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		if name := strings.ToLower(strings.TrimSpace(d)); !NameCovered(name, held) {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

// ArtefactPair pairs a local file to send with the name to give it remotely.
type ArtefactPair struct {
	LocalPath  string
	RemotePath string
}

func copyCertFile(src, dst string, mode os.FileMode) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func (o CertDeliverOptions) buildArtefacts(lineage string, record map[string]any, workdir string) ([]ArtefactPair, error) {
	fullchain := filepath.Join(lineage, "fullchain.pem")
	privkey := filepath.Join(lineage, "privkey.pem")
	for _, required := range []string{fullchain, privkey} {
		if !certIsFile(required) {
			return nil, deliveryErr("%s is missing", required)
		}
	}

	format := strings.ToLower(strings.TrimSpace(recordStr(record, "format", "pfx")))
	known := false
	for _, f := range certFormats {
		known = known || f == format
	}
	if !known {
		return nil, deliveryErr("format must be one of %s", strings.Join(certFormats, ", "))
	}

	remote := strings.TrimSpace(recordStr(record, "remote_path", ""))
	if remote == "" {
		return nil, deliveryErr("remote_path is required")
	}

	switch format {
	case "pfx":
		out := filepath.Join(workdir, "certificate.pfx")
		password := recordStr(record, "pfx_password", "")
		// Through a pipe, never in the arguments: any local user can read a
		// process's command line while it runs.
		if strings.ContainsAny(password, "\n\r") {
			return nil, deliveryErr("the PFX password cannot contain a line break")
		}
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		_, _ = pw.WriteString(password + "\n")
		_ = pw.Close()
		defer pr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, o.OpenSSLBin, "pkcs12", "-export",
			"-inkey", privkey, "-in", fullchain, "-out", out, "-passout", "fd:3")
		cmd.ExtraFiles = []*os.File{pr}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err = cmd.Run()
		if ctx.Err() != nil {
			return nil, errCertTimeout
		}
		if err != nil {
			return nil, deliveryErr("openssl could not build the PKCS#12 file: %s", strings.TrimSpace(strings.ToValidUTF8(stderr.String(), "�")))
		}
		if err := os.Chmod(out, 0o600); err != nil {
			return nil, err
		}
		return []ArtefactPair{{out, remote}}, nil

	case "pem-combined":
		out := filepath.Join(workdir, "certificate.pem")
		chain, err := os.ReadFile(fullchain)
		if err != nil {
			return nil, err
		}
		key, err := os.ReadFile(privkey)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(out, append(chain, key...), 0o600); err != nil {
			return nil, err
		}
		if err := os.Chmod(out, 0o600); err != nil {
			return nil, err
		}
		return []ArtefactPair{{out, remote}}, nil
	}

	// pem-pair: remote_path names the directory the two files go into.
	chainOut := filepath.Join(workdir, "fullchain.pem")
	keyOut := filepath.Join(workdir, "privkey.pem")
	if err := copyCertFile(fullchain, chainOut, 0o644); err != nil {
		return nil, err
	}
	if err := copyCertFile(privkey, keyOut, 0o600); err != nil {
		return nil, err
	}
	base := strings.TrimRight(remote, "/")
	return []ArtefactPair{{chainOut, base + "/fullchain.pem"}, {keyOut, base + "/privkey.pem"}}, nil
}

// sshBaseCommand: the options shared by every call to the OpenSSH client,
// with the host key pinned to what the operator saved.
func (o CertDeliverOptions) sshBaseCommand(record map[string]any, binary string, target certSSHTarget) []string {
	name := pyx.Str(record["name"])
	portFlag := "-P" // sftp and scp; only ssh takes -p
	if strings.HasSuffix(binary, "/ssh") || binary == "ssh" {
		portFlag = "-p"
	}
	cmd := append([]string{binary}, netpolicy.SSHOptions(target.address, target.knownHost)...)
	return append(cmd,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+o.knownHostsPath(name),
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=20",
		"-i", o.keyPath(name),
		portFlag, strconv.FormatInt(target.port, 10),
	)
}

type certSSHTarget struct {
	address, knownHost, remote string
	port                       int64
}

func certValidatedTarget(record map[string]any) (certSSHTarget, error) {
	user := strings.TrimSpace(recordStr(record, "user", ""))
	host := strings.TrimSpace(recordStr(record, "host", ""))
	if !certTargetUserRe.MatchString(user) {
		return certSSHTarget{}, deliveryErr("delivery target user contains unsupported characters")
	}
	port := int64(22)
	if value := record["port"]; pyx.Truthy(value) {
		var err error
		port, err = strconv.ParseInt(pyx.Str(value), 10, 64)
		if err != nil || port < 1 || port > 65535 {
			return certSSHTarget{}, deliveryErr("delivery target port is invalid")
		}
	}
	address, err := netpolicy.ResolveSSHHost(host)
	if err != nil {
		return certSSHTarget{}, deliveryErr("%v", err)
	}
	remote := address
	if strings.ContainsRune(address, ':') {
		remote = "[" + address + "]"
	}
	return certSSHTarget{address: address, knownHost: netpolicy.SSHKnownHost(host, port), remote: user + "@" + remote, port: port}, nil
}

// remoteQuote quotes a path for the sftp batch language, which splits on whitespace.
func remoteQuote(value string) (string, error) {
	if certControlCharRe.MatchString(value) {
		return "", deliveryErr("remote path contains control characters")
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`, nil
}

var errCertTimeout = errors.New("timed out")

type certRun struct {
	rc     int
	stderr string
}

// runCertCommand runs argv with a deadline. errCertTimeout is Python's
// TimeoutExpired; any other error is a binary that could not be started.
func (o CertDeliverOptions) runCertCommand(argv []string, stdin string) (certRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr strings.Builder
	cmd.Stdout = io.Discard
	cmd.WaitDelay = 5 * time.Second
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return certRun{}, errCertTimeout
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return certRun{}, err
	}
	return certRun{rc: cmd.ProcessState.ExitCode(), stderr: strings.ToValidUTF8(stderr.String(), "�")}, nil
}

func (o CertDeliverOptions) send(record map[string]any, artefacts []ArtefactPair, target certSSHTarget) error {
	transport := strings.ToLower(strings.TrimSpace(recordStr(record, "transport", "sftp")))
	known := false
	for _, t := range certTransports {
		known = known || t == transport
	}
	if !known {
		return deliveryErr("transport must be one of %s", strings.Join(certTransports, ", "))
	}
	var res certRun
	var err error
	if transport == "sftp" {
		var batch strings.Builder
		for _, a := range artefacts {
			local, err := remoteQuote(a.LocalPath)
			if err != nil {
				return err
			}
			remote, err := remoteQuote(a.RemotePath)
			if err != nil {
				return err
			}
			batch.WriteString("put " + local + " " + remote + "\n")
		}
		batch.WriteString("quit\n")
		argv := append(o.sshBaseCommand(record, o.SFTPBin, target), "-b", "-", "--", target.remote)
		res, err = o.runCertCommand(argv, batch.String())
	} else {
		// scp takes many sources but only one destination: one artefact goes
		// to its exact remote name, a pair into remote_path as a directory.
		destination := ""
		if len(artefacts) == 1 {
			destination = artefacts[0].RemotePath
		} else {
			destination = strings.TrimRight(recordStr(record, "remote_path", ""), "/") + "/"
		}
		if certControlCharRe.MatchString(destination) {
			return deliveryErr("remote path contains control characters")
		}
		argv := append(o.sshBaseCommand(record, o.SCPBin, target), "--")
		for _, a := range artefacts {
			argv = append(argv, a.LocalPath)
		}
		argv = append(argv, target.remote+":"+destination)
		res, err = o.runCertCommand(argv, "")
	}
	if err != nil {
		if errors.Is(err, errCertTimeout) {
			return err
		}
		return deliveryErr("%s failed: %v", transport, err)
	}
	if res.rc != 0 {
		detail := strings.TrimSpace(res.stderr)
		if detail == "" {
			detail = fmt.Sprintf("exit %d", res.rc)
		}
		return deliveryErr("%s failed: %s", transport, detail)
	}
	return nil
}

// runPostCommand: whatever the far side needs once the file has landed. A
// failure is reported without undoing the delivery -- the file did arrive.
func (o CertDeliverOptions) runPostCommand(record map[string]any, target certSSHTarget) string {
	command := strings.TrimSpace(recordStr(record, "post_command", ""))
	if command == "" {
		return ""
	}
	argv := append(o.sshBaseCommand(record, o.SSHBin, target), "--", target.remote, command)
	res, err := o.runCertCommand(argv, "")
	if errors.Is(err, errCertTimeout) {
		return fmt.Sprintf("the file was delivered but the command afterwards timed out after %ds", o.timeoutSeconds())
	}
	if err != nil {
		return "the file was delivered but the command afterwards failed: " + err.Error()
	}
	if res.rc != 0 {
		detail := strings.TrimSpace(res.stderr)
		if detail == "" {
			detail = fmt.Sprintf("exit %d", res.rc)
		}
		return "the file was delivered but the command afterwards failed: " + detail
	}
	return ""
}

func (o CertDeliverOptions) timeoutSeconds() int { return int(o.Timeout / time.Second) }

// certOutcome is the dict deliver() returns.
type certOutcome struct {
	name    string
	ok      bool
	errText string
	warning string
}

func (o CertDeliverOptions) deliver(record map[string]any, lineage string) certOutcome {
	name := "?"
	if v, ok := record["name"]; ok {
		name = pyx.Str(v)
	}
	if v, ok := record["enabled"]; ok && !pyx.Truthy(v) {
		return certOutcome{name: name, ok: true}
	}
	for _, field := range []string{"host", "user"} {
		if strings.TrimSpace(recordStr(record, field, "")) == "" {
			return certOutcome{name: name, errText: field + " is not set"}
		}
	}
	if !certIsFile(o.keyPath(name)) {
		return certOutcome{name: name, errText: "no private key saved for this target"}
	}
	if !certIsFile(o.knownHostsPath(name)) {
		return certOutcome{name: name, errText: "no host key saved for this target"}
	}

	// Checked before any connection: the far side keeps what it had.
	missing, err := o.uncoveredNames(record, lineage)
	if err != nil {
		return certOutcome{name: name, errText: err.Error()}
	}
	if len(missing) > 0 {
		return certOutcome{name: name, errText: fmt.Sprintf(
			"the certificate in %s does not cover %s; a target receives one certificate, so give each certificate a target of its own",
			filepath.Base(lineage), strings.Join(missing, ", "))}
	}
	target, err := certValidatedTarget(record)
	if err != nil {
		return certOutcome{name: name, errText: err.Error()}
	}

	workdir, err := os.MkdirTemp("", "cert-deliver-")
	if err != nil {
		return certOutcome{name: name, errText: err.Error()}
	}
	defer os.RemoveAll(workdir)
	_ = os.Chmod(workdir, 0o700)
	artefacts, err := o.buildArtefacts(lineage, record, workdir)
	if err == nil {
		err = o.send(record, artefacts, target)
	}
	if err != nil {
		if errors.Is(err, errCertTimeout) {
			return certOutcome{name: name, errText: fmt.Sprintf("timed out after %ds", o.timeoutSeconds())}
		}
		return certOutcome{name: name, errText: err.Error()}
	}
	return certOutcome{name: name, ok: true, warning: o.runPostCommand(record, target)}
}

func (o CertDeliverOptions) deliverAll(lg certLogger, lineage string, domains []string) []certOutcome {
	var results []certOutcome
	for _, record := range o.listDestinations(lg) {
		if !certWantsDomain(record, domains) {
			continue
		}
		outcome := o.deliver(record, lineage)
		results = append(results, outcome)
		if outcome.ok {
			lg.log("INFO", "delivered to %s", outcome.name)
			if outcome.warning != "" {
				lg.log("WARNING", "%s: %s", outcome.name, outcome.warning)
			}
		} else {
			// One unreachable machine must not cost the others their certificate.
			lg.log("ERROR", "delivery to %s failed: %s", outcome.name, outcome.errText)
		}
	}
	return results
}

// certDeliverUsage is argparse's usage line for the worker, wrapped as
// argparse wraps it: to the terminal width (COLUMNS, else 80) less two.
func certDeliverUsage() string {
	const prefix, prog = "usage: ", "easy-ha-proxy-cert-deliver"
	parts := []string{"[-h]", "[--lineage LINEAGE]", "[--domains DOMAINS]", "[--target TARGET]"}
	columns := 80
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && n > 0 {
		columns = n
	}
	width := columns - 2
	whole := prog + " " + strings.Join(parts, " ")
	if len(prefix)+len(whole) <= width {
		return prefix + whole + "\n"
	}
	// argparse's get_lines: fill each line up to width, continuation lines
	// indented under the first option.
	lines := func(parts []string, indent string, first int) []string {
		var out, line []string
		length := first
		for _, part := range parts {
			if length+1+len(part) > width && len(line) > 0 {
				out = append(out, indent+strings.Join(line, " "))
				line, length = nil, len(indent)-1
			}
			line = append(line, part)
			length += len(part) + 1
		}
		if len(line) > 0 {
			out = append(out, indent+strings.Join(line, " "))
		}
		return out
	}
	var out []string
	if float64(len(prefix)+len(prog)) <= 0.75*float64(width) {
		indent := strings.Repeat(" ", len(prefix)+len(prog)+1)
		out = lines(append([]string{prog}, parts...), indent, len(prefix)-1)
		out[0] = out[0][len(indent):]
	} else {
		out = append([]string{prog}, lines(parts, strings.Repeat(" ", len(prefix)), len(prefix)-1)...)
	}
	return prefix + strings.Join(out, "\n") + "\n"
}

// parseCertDeliverArgs follows argparse for the worker's three options:
// "--opt value", "--opt=value" and unambiguous abbreviations.
func parseCertDeliverArgs(args []string, values map[string]*string) (help bool, errText string) {
	options := []string{"--domains", "--help", "--lineage", "--target"}
	resolve := func(flag string) (string, string) {
		var hits []string
		for _, opt := range options {
			if opt == flag {
				return opt, ""
			}
			if strings.HasPrefix(opt, flag) && len(flag) > 2 {
				hits = append(hits, opt)
			}
		}
		if len(hits) == 1 {
			return hits[0], ""
		}
		if len(hits) > 1 {
			return "", fmt.Sprintf("ambiguous option: %s could match %s", flag, strings.Join(hits, ", "))
		}
		return "", ""
	}
	var unknown []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" {
			return true, ""
		}
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			unknown = append(unknown, arg)
			continue
		}
		flag, value, hasValue := strings.Cut(arg, "=")
		opt, problem := resolve(flag)
		if problem != "" {
			return false, problem
		}
		if opt == "--help" {
			return true, ""
		}
		dst, ok := values[opt]
		if !ok {
			unknown = append(unknown, arg)
			continue
		}
		if !hasValue {
			if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-") {
				return false, fmt.Sprintf("argument %s: expected one argument", opt)
			}
			i++
			value = args[i]
		}
		*dst = value
	}
	if len(unknown) > 0 {
		return false, "unrecognized arguments: " + strings.Join(unknown, " ")
	}
	return false, ""
}

// RunCertDeliver is main() of easy-ha-proxy-cert-deliver.
func RunCertDeliver(args []string, opts CertDeliverOptions, stdout, stderr io.Writer) int {
	lg := certLogger{w: stderr}
	lineageArg := os.Getenv("RENEWED_LINEAGE")
	domainsArg := os.Getenv("RENEWED_DOMAINS")
	targetArg := ""
	help, problem := parseCertDeliverArgs(args, map[string]*string{
		"--lineage": &lineageArg, "--domains": &domainsArg, "--target": &targetArg,
	})
	if help {
		fmt.Fprint(stdout, certDeliverUsage())
		return 0
	}
	if problem != "" {
		fmt.Fprint(stderr, certDeliverUsage())
		fmt.Fprintf(stderr, "easy-ha-proxy-cert-deliver: error: %s\n", problem)
		return 2
	}

	if targetArg != "" {
		if lineageArg == "" {
			lg.log("ERROR", "--target needs --lineage")
			return 2
		}
		record, err := opts.loadDestination(targetArg)
		if err != nil {
			lg.log("ERROR", "%v", err)
			return 1
		}
		outcome := opts.deliver(record, lineageArg)
		if !outcome.ok {
			lg.log("ERROR", "delivery to %s failed: %s", outcome.name, outcome.errText)
			return 1
		}
		lg.log("INFO", "delivered to %s", outcome.name)
		if outcome.warning != "" {
			lg.log("WARNING", "%s: %s", outcome.name, outcome.warning)
		}
		return 0
	}

	if lineageArg == "" {
		// Not an error: certbot runs deploy hooks only after a renewal.
		lg.log("INFO", "no lineage given; nothing to deliver")
		return 0
	}
	domains := strings.Fields(strings.ReplaceAll(domainsArg, ",", " "))
	if len(domains) == 0 {
		lg.log("INFO", "no renewed domains given; nothing to deliver")
		return 0
	}
	results := opts.deliverAll(lg, lineageArg, domains)
	if len(results) == 0 {
		lg.log("INFO", "no delivery target wants %s", strings.Join(domains, " "))
		return 0
	}
	failed := 0
	for _, r := range results {
		if !r.ok {
			failed++
		}
	}
	lg.log("INFO", "%d of %d targets delivered", len(results)-failed, len(results))
	// Non-zero so certbot reports it and the notification mail carries it.
	if failed > 0 {
		return 1
	}
	return 0
}

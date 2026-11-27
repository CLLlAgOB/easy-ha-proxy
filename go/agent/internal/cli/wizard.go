package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

var (
	domainLabelRe   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	domainTLDRe     = regexp.MustCompile(`^[a-z]{2,63}$`)
	usernameRe      = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	timezoneNameRe  = regexp.MustCompile(`^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$`)
	detectLocalIPFn = defaultDetectLocalIP
	lookupHostFn    = defaultLookupHost
	dnsPreflightFn  = defaultDNSPreflight
	configureIntFn  = defaultConfigureInteractively
	genInternalCAFn = defaultGenerateInternalCertificate
)

// Context holds I/O streams and interactive hooks for one CLI invocation.
type Context struct {
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	reader   *bufio.Reader
	isTTYFn  func() bool
	promptFn func(label, defaultVal string, validator func(string) string) (string, error)
	boolFn   func(label string, defaultVal bool) (bool, error)
	passFn   func(prompt string) (string, error)
}

// NewContext creates a CLI execution context for the given streams.
func NewContext(stdin io.Reader, stdout, stderr io.Writer) *Context {
	return &Context{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		reader: bufio.NewReader(stdin),
	}
}

func (c *Context) ensureReader() *bufio.Reader {
	if c.reader == nil {
		if c.Stdin == nil {
			c.Stdin = os.Stdin
		}
		c.reader = bufio.NewReader(c.Stdin)
	}
	return c.reader
}

func (c *Context) isTTY() bool {
	if c.isTTYFn != nil {
		return c.isTTYFn()
	}
	f, ok := c.Stdin.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func (c *Context) interactiveInput() (*Context, func(), error) {
	if c.isTTY() || os.Getenv("EASY_HA_PROXY_ALLOW_STDIN") == "1" {
		return c, func() {}, nil
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, nil, installerErrorf("Interactive configuration needs a terminal. Download install-local.sh and run it from a terminal.")
	}
	interactive := *c
	interactive.Stdin, interactive.reader = tty, bufio.NewReader(tty)
	return &interactive, func() { _ = tty.Close() }, nil
}

func (c *Context) readLine(promptText string) (string, error) {
	if promptText != "" {
		fmt.Fprint(c.Stdout, promptText)
	}
	line, err := c.ensureReader().ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", io.EOF
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *Context) readSecret(promptText string) (string, error) {
	if c.passFn != nil {
		return c.passFn(promptText)
	}
	if promptText != "" {
		fmt.Fprint(c.Stdout, promptText)
	}
	if f, ok := c.Stdin.(*os.File); ok {
		fd := int(f.Fd())
		if oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
			newState := *oldState
			newState.Lflag &^= unix.ECHO
			_ = unix.IoctlSetTermios(fd, unix.TCSETS, &newState)
			defer func() {
				_ = unix.IoctlSetTermios(fd, unix.TCSETS, oldState)
				fmt.Fprintln(c.Stdout)
			}()
		}
	}
	line, err := c.ensureReader().ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *Context) prompt(label, defaultVal string, validator func(string) string) (string, error) {
	if c.promptFn != nil {
		return c.promptFn(label, defaultVal, validator)
	}
	for {
		suffix := ""
		if defaultVal != "" {
			suffix = fmt.Sprintf(" [%s]", defaultVal)
		}
		raw, err := c.readLine(fmt.Sprintf("%s%s: ", T(label), suffix))
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(raw)
		if value == "" && defaultVal != "" {
			value = defaultVal
		}
		if value == "" {
			fmt.Fprintln(c.Stdout, T("Value is required."))
			continue
		}
		if validator != nil {
			if msg := validator(value); msg != "" {
				fmt.Fprintln(c.Stdout, msg)
				continue
			}
		}
		return value, nil
	}
}

func (c *Context) promptBool(label string, defaultVal bool) (bool, error) {
	if c.boolFn != nil {
		return c.boolFn(label, defaultVal)
	}
	hint := "y/N"
	if defaultVal {
		hint = "Y/n"
	}
	for {
		raw, err := c.readLine(fmt.Sprintf("%s [%s]: ", T(label), hint))
		if err != nil {
			return false, err
		}
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			return defaultVal, nil
		}
		switch value {
		case "y", "yes", "д", "да":
			return true, nil
		case "n", "no", "н", "нет":
			return false, nil
		}
		fmt.Fprintln(c.Stdout, T("Enter yes or no."))
	}
}

func (c *Context) promptPassword() (string, error) {
	for {
		first, err := c.readSecret(T("First Authelia administrator password: "))
		if err != nil {
			return "", err
		}
		if len([]rune(first)) < 12 {
			fmt.Fprintln(c.Stdout, T("Use at least 12 characters."))
			continue
		}
		second, err := c.readSecret(T("Repeat password: "))
		if err != nil {
			return "", err
		}
		if first != second {
			fmt.Fprintln(c.Stdout, T("Passwords do not match."))
			continue
		}
		return first, nil
	}
}

// ValidateDomain checks whether value is a valid FQDN.
func ValidateDomain(value string) string {
	lower := strings.ToLower(value)
	if len(lower) < 1 || len(lower) > 253 {
		return T("Enter a full DNS name, for example example.com.")
	}
	parts := strings.Split(lower, ".")
	if len(parts) < 2 {
		return T("Enter a full DNS name, for example example.com.")
	}
	for _, label := range parts[:len(parts)-1] {
		if !domainLabelRe.MatchString(label) {
			return T("Enter a full DNS name, for example example.com.")
		}
	}
	if !domainTLDRe.MatchString(parts[len(parts)-1]) {
		return T("Enter a full DNS name, for example example.com.")
	}
	return ""
}

// ValidateEmail checks basic email syntax.
func ValidateEmail(value string) string {
	if strings.Count(value, "@") != 1 {
		return T("Enter a valid email address.")
	}
	_, domain, _ := strings.Cut(value, "@")
	if !strings.Contains(domain, ".") {
		return T("Enter a valid email address.")
	}
	return ""
}

// ValidateUsername checks allowed Authelia username characters.
func ValidateUsername(value string) string {
	if !usernameRe.MatchString(value) {
		return T("Use only letters, digits and . _ @ - (maximum 64 characters).")
	}
	return ""
}

// ValidatePort checks an integer port in 1..65535.
func ValidatePort(value string) string {
	port, err := strconv.Atoi(value)
	if err != nil {
		return T("Port must be an integer.")
	}
	if port < 1 || port > 65535 {
		return T("Port must be between 1 and 65535.")
	}
	return ""
}

// ValidateIP checks IPv4 or IPv6 syntax.
func ValidateIP(value string) string {
	if net.ParseIP(value) == nil {
		return T("Enter a valid IPv4 or IPv6 address.")
	}
	return ""
}

// ValidateCertificateSource checks letsencrypt or internal.
func ValidateCertificateSource(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "letsencrypt", "internal":
		return ""
	default:
		return T("Enter letsencrypt or internal.")
	}
}

// ParseNetworks parses a comma-separated list of IP addresses and CIDRs.
func ParseNetworks(value string) ([]string, error) {
	var networks []string
	for _, part := range strings.Split(value, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			_, ipNet, err := net.ParseCIDR(item)
			if err != nil {
				return nil, installerErrorf("Invalid IP/network %q: %v", item, err)
			}
			networks = append(networks, ipNet.String())
		} else {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, installerErrorf("Invalid IP/network %q: invalid IP address", item)
			}
			networks = append(networks, ip.String())
		}
	}
	return networks, nil
}

// ParseCountries parses comma-separated ISO alpha-2 country codes.
func ParseCountries(value string) ([]string, error) {
	var countries []string
	var invalid []string
	for _, part := range strings.Split(value, ",") {
		item := strings.ToUpper(strings.TrimSpace(part))
		if item == "" {
			continue
		}
		if !country2Up.MatchString(item) {
			invalid = append(invalid, item)
		} else {
			countries = append(countries, item)
		}
	}
	if len(invalid) > 0 {
		return nil, installerErrorf("Country codes must use ISO alpha-2 format: %s", strings.Join(invalid, ", "))
	}
	return countries, nil
}

// DetectTimezone returns the host IANA timezone name, falling back to UTC.
func DetectTimezone(timezoneFile, localtime string) string {
	if timezoneFile == "" {
		timezoneFile = "/etc/timezone"
	}
	if localtime == "" {
		localtime = "/etc/localtime"
	}
	value := ""
	if raw, err := os.ReadFile(timezoneFile); err == nil {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) > 0 {
			value = strings.TrimSpace(lines[0])
		}
	}
	if value == "" {
		if target, err := os.Readlink(localtime); err == nil {
			if _, after, ok := strings.Cut(target, "zoneinfo/"); ok {
				after = strings.TrimPrefix(after, "posix/")
				after = strings.TrimPrefix(after, "right/")
				value = after
			}
		}
	}
	if !timezoneNameRe.MatchString(value) || strings.Contains(value, "..") {
		return "UTC"
	}
	return value
}

func defaultDetectLocalIP() string {
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String()
	}
	return "127.0.0.1"
}

// HashPasswordArgon2id generates an Authelia-compatible PHC Argon2id digest.
func HashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, 65536, 3, 4, b64Salt, b64Hash), nil
}

// BuildSiteDefaults builds the default site_defaults mapping for fresh installs.
func BuildSiteDefaults(geoipEnabled bool) *pyyaml.Map {
	_ = geoipEnabled
	m := pyyaml.NewMap()
	m.Set("balance", "roundrobin")
	m.Set("sticky", "none")
	m.Set("backend_port", int64(80))
	m.Set("backend_ssl", false)
	m.Set("backend_ssl_verify", false)
	m.Set("redirect_to_https", true)
	m.Set("maintenance", false)
	m.Set("hsts", int64(15552000))
	m.Set("compress", false)
	m.Set("add_headers", pyyaml.NewMap())
	m.Set("max_req_rate", int64(200))
	m.Set("rate_window", "20s")
	m.Set("ban_policy", "u02")
	m.Set("rate_ban", true)
	m.Set("enable_geoip", true)
	m.Set("tcp_check", false)
	m.Set("health_uri", "/")
	m.Set("health_status", int64(200))
	m.Set("http_request_timeout", "5s")
	m.Set("frontend_keepalive_timeout", "30s")
	m.Set("conn_table_expire", "30s")
	m.Set("conn_rate_window", "10s")
	m.Set("conn_rate_burst", int64(200))
	m.Set("conn_cur_limit", int64(500))
	m.Set("err_limit", int64(8))
	m.Set("err_window", "20s")
	m.Set("other_err_window", "20s")
	m.Set("other_err_limit", int64(12))
	m.Set("other_err_exclude_enabled", true)
	exc := pyyaml.NewMap()
	exc.Set("path", "/")
	exc.Set("methods", []any{"GET"})
	m.Set("other_err_exclude_exact", []any{exc})
	return m
}

// ConfigureOptions controls interactive configuration wizard execution.
type ConfigureOptions struct {
	Overwrite         bool
	TestMode          *bool
	CertificateSource string
	ImageChannel      string
	SourceChannel     string
}

// ConfigureInteractively runs the interactive wizard and writes /etc/easy-ha-proxy.
func ConfigureInteractively(ctx *Context, opts ConfigureOptions) (string, error) {
	return configureIntFn(ctx, opts)
}

func defaultConfigureInteractively(ctx *Context, opts ConfigureOptions) (string, error) {
	directory := ConfigDir()
	marker := filepath.Join(directory, "metadata.yml")
	hasExisting := fileExists(marker)

	if hasExisting && !opts.Overwrite {
		return directory, nil
	}

	ctx, closeInput, err := ctx.interactiveInput()
	if err != nil {
		return "", err
	}
	defer closeInput()

	existingVars := pyyaml.NewMap()
	existingAuthelia := pyyaml.NewMap()
	existingSecrets := pyyaml.NewMap()
	existingMeta := pyyaml.NewMap()
	existingWebsites := pyyaml.NewMap()
	existingWebsites.Set("sites", []any{})
	existingTCP := pyyaml.NewMap()
	existingTCP.Set("tcp_proxies", []any{})
	var existingUsers *pyyaml.Map

	if hasExisting {
		loadExisting := func(path string) (*pyyaml.Map, error) {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, installerErrorf("Cannot safely read existing %s; refusing to overwrite the current configuration.", filepath.Base(path))
			}
			v, err := pyyaml.Load(raw)
			if err != nil {
				return nil, installerErrorf("Cannot safely read existing %s; refusing to overwrite the current configuration.", filepath.Base(path))
			}
			m, ok := v.(*pyyaml.Map)
			if !ok || m == nil {
				return nil, installerErrorf("Existing %s must contain a YAML mapping; refusing to overwrite the current configuration.", filepath.Base(path))
			}
			return m, nil
		}
		var err error
		if existingMeta, err = loadExisting(marker); err != nil {
			return "", err
		}
		if existingVars, err = loadExisting(filepath.Join(directory, "vars.yml")); err != nil {
			return "", err
		}
		if existingAuthelia, err = loadExisting(filepath.Join(directory, "authelia.yml")); err != nil {
			return "", err
		}
		if existingSecrets, err = loadExisting(filepath.Join(directory, "secrets.yml")); err != nil {
			return "", err
		}
		usersPath := filepath.Join(directory, "authelia_users_initial.yml")
		if fileExists(usersPath) {
			loadedUsers, err := loadExisting(usersPath)
			if err != nil {
				return "", err
			}
			if truthy(loadedUsers.Value("authelia_users")) {
				existingUsers = loadedUsers
			}
		}

		var rv, rw, rt *pyyaml.Map
		var foundRuntime bool
		if !truthy(existingMeta.Value("configuration_pending")) {
			rv, rw, rt, foundRuntime, err = loadRuntimeHAProxyDocuments(runtimeHAProxyConfigDir)
			if err != nil {
				return "", err
			}
		}
		if foundRuntime {
			keys := make([]string, 0, len(RuntimeHAProxyVarKeys))
			for k := range RuntimeHAProxyVarKeys {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if val, ok := rv.Get(key); ok {
					existingVars.Set(key, pyyaml.DeepCopy(val))
				} else {
					existingVars.Delete(key)
				}
			}
			existingWebsites = pyyaml.DeepCopy(rw).(*pyyaml.Map)
			existingTCP = pyyaml.DeepCopy(rt).(*pyyaml.Map)
		} else {
			if p := filepath.Join(directory, "websites.yml"); isRegularFile(p) {
				if existingWebsites, err = loadExisting(p); err != nil {
					return "", err
				}
			}
			if p := filepath.Join(directory, "tcp.yml"); isRegularFile(p) {
				if existingTCP, err = loadExisting(p); err != nil {
					return "", err
				}
			}
		}
	}

	testMode := truthy(existingMeta.Value("test_mode"))
	if opts.TestMode != nil {
		testMode = *opts.TestMode
	}

	certSource := strings.ToLower(strings.TrimSpace(opts.CertificateSource))
	if certSource != "" {
		if msg := ValidateCertificateSource(certSource); msg != "" {
			return "", installerErrorf("%s", msg)
		}
	}
	if testMode && certSource != "" && certSource != "internal" {
		return "", installerErrorf("Test mode requires the internal certificate authority.")
	}
	if testMode {
		certSource = "internal"
	}

	imageChannel := strings.ToLower(strings.TrimSpace(opts.ImageChannel))
	if imageChannel != "" && imageChannel != "latest" && imageChannel != "alpha" {
		return "", installerErrorf("Docker image channel must be latest or alpha.")
	}
	sourceChannel := strings.ToLower(strings.TrimSpace(opts.SourceChannel))
	if sourceChannel == "" {
		sourceChannel = strings.ToLower(strings.TrimSpace(os.Getenv("EASY_HA_PROXY_SOURCE_CHANNEL")))
	}
	if sourceChannel == "" {
		sourceChannel = strings.ToLower(strings.TrimSpace(strVal(existingMeta.Value("source_channel"))))
	}
	if sourceChannel == "" {
		sourceChannel = "github"
	}
	if sourceChannel != "github" && sourceChannel != "local" {
		return "", installerErrorf("Source channel must be github or local.")
	}

	lang := InstallerLanguage()
	if testMode {
		if lang == "ru" {
			fmt.Fprintln(ctx.Stdout, "\nТестовая конфигурация easy-ha-proxy")
		} else {
			fmt.Fprintln(ctx.Stdout, "\neasy-ha-proxy test configuration")
		}
	} else {
		if lang == "ru" {
			fmt.Fprintln(ctx.Stdout, "\nПервоначальная конфигурация easy-ha-proxy")
		} else {
			fmt.Fprintln(ctx.Stdout, "\nInitial easy-ha-proxy configuration")
		}
	}
	fmt.Fprintln(ctx.Stdout)

	if imageChannel == "" {
		existingIC := strings.ToLower(strings.TrimSpace(strVal(existingMeta.Value("image_channel"))))
		if existingIC == "" {
			if testMode {
				existingIC = "alpha"
			} else {
				existingIC = "latest"
			}
		}
		if existingIC != "latest" && existingIC != "alpha" {
			existingIC = "latest"
		}
		if lang == "ru" {
			fmt.Fprintln(ctx.Stdout, "  1) latest (релиз)\n  2) alpha (тестовая сборка)")
		} else {
			fmt.Fprintln(ctx.Stdout, "  1) latest (release)\n  2) alpha (test build)")
		}
		defChoice := "1"
		if existingIC == "alpha" {
			defChoice = "2"
		}
		choice, err := ctx.prompt("Docker image channel", defChoice, func(v string) string {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "1", "2", "latest", "alpha", "release", "test":
				return ""
			default:
				return T("Enter latest or alpha.")
			}
		})
		if err != nil {
			return "", err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "2", "alpha", "test":
			imageChannel = "alpha"
		default:
			imageChannel = "latest"
		}
	}

	if certSource == "" {
		existingCS := strings.ToLower(strings.TrimSpace(strVal(existingMeta.Value("certificate_source"))))
		if existingCS == "" {
			existingCS = strings.ToLower(strings.TrimSpace(strVal(existingVars.Value("easy_ha_proxy_certificate_source"))))
		}
		if existingCS != "letsencrypt" && existingCS != "internal" {
			existingCS = "letsencrypt"
		}
		if lang == "ru" {
			fmt.Fprintln(ctx.Stdout, "  1) Let's Encrypt\n  2) Внутренний CA (self-signed root)")
		} else {
			fmt.Fprintln(ctx.Stdout, "  1) Let's Encrypt\n  2) Internal CA (self-signed root)")
		}
		defSource := "1"
		if existingCS == "internal" {
			defSource = "2"
		}
		choice, err := ctx.prompt("Initial certificate source", defSource, func(v string) string {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "1", "2", "letsencrypt", "internal", "le", "ca":
				return ""
			default:
				return T("Enter letsencrypt or internal.")
			}
		})
		if err != nil {
			return "", err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "2", "internal", "ca":
			certSource = "internal"
		default:
			certSource = "letsencrypt"
		}
	}

	if certSource == "letsencrypt" {
		if lang == "ru" {
			fmt.Fprintln(ctx.Stdout, "DNS-записи A/AAAA доменов админки и Authelia должны указывать на сервер;\nвходящие TCP-порты 80 и 443 должны быть доступны.")
		} else {
			fmt.Fprintln(ctx.Stdout, "DNS A/AAAA records for the admin and Authelia domains must point to this server;\nincoming TCP ports 80 and 443 must be reachable.")
		}
	} else {
		if lang == "ru" {
			fmt.Fprintln(ctx.Stdout, "Для панели и Authelia будет создан сертификат внутреннего корневого CA.\nЕго публичный сертификат нужно добавить в доверенные на клиентских устройствах.")
		} else {
			fmt.Fprintln(ctx.Stdout, "The administration UI and Authelia will initially use the internal root CA.\nInstall its public certificate as trusted on client devices.")
		}
	}
	fmt.Fprintln(ctx.Stdout)
	if lang == "ru" {
		fmt.Fprintln(ctx.Stdout, "Certbot устанавливается в обоих вариантах. После установки каждый сайт может независимо\nиспользовать Let's Encrypt, внутренний CA или импортированный внешний CA на /haproxy/certs.")
	} else {
		fmt.Fprintln(ctx.Stdout, "Certbot is installed in both modes. After installation, each site can independently\nuse Let's Encrypt, the internal CA, or an imported external CA from /haproxy/certs.")
	}
	fmt.Fprintln(ctx.Stdout)

	existingRootDomain := strings.TrimSpace(strVal(existingVars.Value("root_domain")))
	defRoot := existingRootDomain
	if defRoot == "" && testMode {
		defRoot = "easy-ha-proxy.test"
	}
	rootDomain, err := ctx.prompt("Root domain", defRoot, ValidateDomain)
	if err != nil {
		return "", err
	}
	rootDomain = strings.ToLower(rootDomain)

	existingAdminDomain := strings.TrimSpace(strVal(existingVars.Value("admin_domain")))
	if existingAdminDomain == "" {
		existingAdminDomain = strings.TrimSpace(strVal(existingMeta.Value("admin_domain")))
	}
	defAdmin := existingAdminDomain
	if defAdmin == "" {
		defAdmin = "ha." + rootDomain
	}
	adminDomain, err := ctx.prompt("Administration domain", defAdmin, ValidateDomain)
	if err != nil {
		return "", err
	}
	adminDomain = strings.ToLower(adminDomain)

	existingAutDomain := strings.TrimSpace(strVal(existingAuthelia.Value("aut_domain")))
	if existingAutDomain == "" {
		existingAutDomain = strings.TrimSpace(strVal(existingVars.Value("aut_domain")))
	}
	if existingAutDomain == "" {
		existingAutDomain = strings.TrimSpace(strVal(existingMeta.Value("authelia_domain")))
	}
	defAut := existingAutDomain
	if defAut == "" {
		defAut = "aut." + rootDomain
	}
	autheliaDomain, err := ctx.prompt("Authelia portal domain", defAut, ValidateDomain)
	if err != nil {
		return "", err
	}
	autheliaDomain = strings.ToLower(autheliaDomain)

	if adminDomain == autheliaDomain {
		return "", installerErrorf("Administration and Authelia portal domains must be different.")
	}
	if hasExisting && (rootDomain != strings.ToLower(existingRootDomain) ||
		adminDomain != strings.ToLower(existingAdminDomain) ||
		autheliaDomain != strings.ToLower(existingAutDomain)) {
		return "", installerErrorf("Existing installation domains cannot be changed by configure. Use 'easy-ha-proxy migrate-domain --new-domain <domain>' for a reviewed domain migration.")
	}

	existingSites, ok := existingWebsites.Value("sites").([]any)
	if !ok {
		existingSites = []any{}
		existingWebsites.Set("sites", existingSites)
	}
	hasGate := false
	for _, s := range existingSites {
		if sm, ok := s.(*pyyaml.Map); ok && truthy(sm.Value("access_gate")) {
			hasGate = true
			break
		}
	}
	if !hasExisting && !hasGate {
		wantGate, err := ctx.promptBool("Create a zero-trust access-gate login site now?", true)
		if err != nil {
			return "", err
		}
		if wantGate {
			gateDomain, err := ctx.prompt("Access-gate domain", "a."+rootDomain, ValidateDomain)
			if err != nil {
				return "", err
			}
			gateDomain = strings.ToLower(gateDomain)
			for _, s := range existingSites {
				if sm, ok := s.(*pyyaml.Map); ok {
					d := strings.ToLower(strVal(sm.Value("domain")))
					if d == "" {
						d = strings.ToLower(strVal(sm.Value("name")))
					}
					if d == gateDomain {
						return "", installerErrorf("A site for %s already exists; edit it in the web UI to turn it into an access gate.", gateDomain)
					}
				}
			}
			gate := pyyaml.NewMap()
			gate.Set("name", gateDomain)
			gate.Set("domain", gateDomain)
			gate.Set("access_gate", true)
			gate.Set("authelia_enabled", true)
			gate.Set("certificate_source", certSource)
			gate.Set("le_managed", certSource == "letsencrypt")
			existingSites = append(existingSites, gate)
			existingWebsites.Set("sites", existingSites)
		}
	}

	defEmail := strings.TrimSpace(strVal(existingVars.Value("certbot_email")))
	if defEmail == "" && testMode {
		defEmail = "admin@example.test"
	}
	certbotEmail, err := ctx.prompt("Let's Encrypt / administrator email", defEmail, ValidateEmail)
	if err != nil {
		return "", err
	}

	defTZ := strings.TrimSpace(strVal(existingVars.Value("haproxy_admin_timezone")))
	if defTZ == "" {
		defTZ = strings.TrimSpace(strVal(existingAuthelia.Value("authelia_timezone")))
	}
	if defTZ == "" {
		defTZ = DetectTimezone("", "")
	}
	timezone, err := ctx.prompt("Timezone", defTZ, nil)
	if err != nil {
		return "", err
	}

	testServerIP := ""
	if testMode {
		defIP := strings.TrimSpace(strVal(existingVars.Value("easy_ha_proxy_test_ip")))
		if defIP == "" {
			defIP = strings.TrimSpace(strVal(existingMeta.Value("test_server_ip")))
		}
		if defIP == "" {
			defIP = detectLocalIPFn()
		}
		testServerIP, err = ctx.prompt("Server LAN/host-only IP", defIP, ValidateIP)
		if err != nil {
			return "", err
		}
	}

	allowedRaw, err := ctx.readLine(T("Admin allowed IP/CIDR list, comma-separated [all authenticated users]: "))
	if err != nil {
		return "", err
	}
	allowedRaw = strings.TrimSpace(allowedRaw)
	var allowedNetworks []any
	var adminIPsEnabled bool
	if allowedRaw == "" && hasExisting {
		if existingAllowed, ok := existingVars.Value("admin_allowed_ips").([]any); ok {
			allowedNetworks = pyyaml.DeepCopy(existingAllowed).([]any)
		} else {
			allowedNetworks = []any{}
		}
		if raw, ok := existingVars.Get("admin_ips_enabled"); ok {
			adminIPsEnabled = truthy(raw)
		} else {
			adminIPsEnabled = len(allowedNetworks) > 0
		}
	} else {
		nets, err := ParseNetworks(allowedRaw)
		if err != nil {
			return "", err
		}
		allowedNetworks = stringsToAnySlice(nets)
		adminIPsEnabled = len(nets) > 0
	}

	countriesRaw, err := ctx.readLine(T("GeoIP allowed country codes, comma-separated [disabled; examples: RU,PL,BY]: "))
	if err != nil {
		return "", err
	}
	countriesRaw = strings.TrimSpace(countriesRaw)
	var countries []any
	var geoipEnabled bool
	if countriesRaw == "" && hasExisting {
		if existingCountries, ok := existingVars.Value("geoip_country_codes").([]any); ok {
			countries = pyyaml.DeepCopy(existingCountries).([]any)
		} else {
			countries = []any{}
		}
		if raw, ok := existingVars.Get("enable_geoip"); ok {
			geoipEnabled = truthy(raw)
		} else {
			geoipEnabled = len(countries) > 0
		}
	} else {
		cs, err := ParseCountries(countriesRaw)
		if err != nil {
			return "", err
		}
		countries = stringsToAnySlice(cs)
		geoipEnabled = len(cs) > 0
	}

	var users *pyyaml.Map
	if existingUsers != nil {
		users = existingUsers
		fmt.Fprintln(ctx.Stdout, T("Existing initial Authelia users are preserved. Manage active users through the web UI."))
	} else {
		adminUsername, err := ctx.prompt("First administrator login", "admin", ValidateUsername)
		if err != nil {
			return "", err
		}
		adminDisplayName, err := ctx.prompt("Administrator display name", "Administrator", nil)
		if err != nil {
			return "", err
		}
		adminEmail, err := ctx.prompt("Administrator email", certbotEmail, ValidateEmail)
		if err != nil {
			return "", err
		}
		adminPassword, err := ctx.promptPassword()
		if err != nil {
			return "", err
		}
		passwordHash, err := HashPasswordArgon2id(adminPassword)
		if err != nil {
			return "", err
		}
		userEntry := pyyaml.NewMap()
		userEntry.Set("displayname", adminDisplayName)
		userEntry.Set("password", passwordHash)
		userEntry.Set("email", adminEmail)
		userEntry.Set("groups", []any{"admins", "superadmin", "users"})
		usersMap := pyyaml.NewMap()
		usersMap.Set(adminUsername, userEntry)
		users = pyyaml.NewMap()
		users.Set("authelia_users", usersMap)
	}

	var smtpEnabled bool
	smtpHost := "localhost"
	var smtpPort int64 = 25
	smtpUser := ""
	smtpPassword := ""
	mailFrom := certbotEmail
	mailTo := certbotEmail

	if hasExisting {
		if raw, ok := existingVars.Get("mail_notify_enabled"); ok {
			smtpEnabled = truthy(raw)
		} else {
			smtpEnabled = truthy(existingAuthelia.Value("mail_relay_server")) ||
				strVal(existingAuthelia.Value("authelia_notifier_type")) == "smtp"
		}
		if h := strVal(existingVars.Value("mail_smtp_host")); h != "" {
			smtpHost = h
		}
		if p, err := strconv.ParseInt(strVal(existingVars.Value("mail_smtp_port")), 10, 64); err == nil && p > 0 {
			smtpPort = p
		}
		smtpUser = strVal(existingVars.Value("mail_smtp_user"))
		smtpPassword = strVal(existingSecrets.Value("mail_smtp_pass"))
		if mf := strVal(existingVars.Value("mail_notify_from")); mf != "" {
			mailFrom = mf
		}
		if mt := strVal(existingVars.Value("mail_notify_to")); mt != "" {
			mailTo = mt
		}
	} else {
		smtpEnabled, err = ctx.promptBool("Configure email notifications through the internal relay", false)
		if err != nil {
			return "", err
		}
		if smtpEnabled {
			smtpHost, err = ctx.prompt("SMTP server", "", nil)
			if err != nil {
				return "", err
			}
			portStr, err := ctx.prompt("SMTP port", "587", ValidatePort)
			if err != nil {
				return "", err
			}
			smtpPort, _ = strconv.ParseInt(portStr, 10, 64)
			smtpUser, err = ctx.prompt("SMTP username", "", nil)
			if err != nil {
				return "", err
			}
			smtpPassword, err = ctx.readSecret(T("SMTP password: "))
			if err != nil {
				return "", err
			}
			mailFrom, err = ctx.prompt("Mail sender", certbotEmail, ValidateEmail)
			if err != nil {
				return "", err
			}
			mailTo, err = ctx.prompt("Notification recipient", certbotEmail, ValidateEmail)
			if err != nil {
				return "", err
			}
		}
	}

	var siteDefaults *pyyaml.Map
	if hasExisting {
		if existingSD, ok := existingVars.Value("site_defaults").(*pyyaml.Map); ok {
			siteDefaults = pyyaml.DeepCopy(existingSD).(*pyyaml.Map)
		} else {
			siteDefaults = pyyaml.NewMap()
		}
	} else {
		siteDefaults = BuildSiteDefaults(geoipEnabled)
		siteDefaults.Set("certificate_source", certSource)
		siteDefaults.Set("le_managed", certSource == "letsencrypt")
	}

	imageRepo := os.Getenv("EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY")
	if imageRepo == "" {
		imageRepo = DefaultAdminImageRepository
	}
	adminImage := imageRepo + ":" + imageChannel

	var variables *pyyaml.Map
	if hasExisting {
		variables = pyyaml.DeepCopy(existingVars).(*pyyaml.Map)
		variables.Set("root_domain", rootDomain)
		variables.Set("admin_domain", adminDomain)
		variables.Set("aut_domain", autheliaDomain)
		variables.Set("admin_ips_enabled", adminIPsEnabled)
		variables.Set("admin_allowed_ips", pyyaml.DeepCopy(allowedNetworks))
		variables.Set("enable_geoip", geoipEnabled)
		variables.Set("geoip_country_codes", pyyaml.DeepCopy(countries))
		variables.Set("certbot_email", certbotEmail)
		variables.Set("haproxy_admin_timezone", timezone)
		variables.Set("haproxy_admin_image", adminImage)
		variables.Set("authelia_timezone", timezone)
		variables.Set("easy_ha_proxy_test_mode", testMode)
		variables.Set("easy_ha_proxy_test_ip", testServerIP)
		variables.Set("easy_ha_proxy_certificate_source", certSource)
	} else {
		allowedOrDefault := allowedNetworks
		if len(allowedOrDefault) == 0 {
			allowedOrDefault = []any{"127.0.0.1"}
		}
		smtpAuth := "off"
		if smtpEnabled {
			smtpAuth = "on"
		}
		smtpSSLMode := "starttls"
		if smtpPort == 465 {
			smtpSSLMode = "smtps"
		}
		variables = pyyaml.NewMap()
		variables.Set("haproxy_socket", "/run/haproxy/admin.sock")
		variables.Set("haproxy_socket_group", "hadmin")
		variables.Set("haproxy_certs_dir", "/etc/haproxy/certs")
		variables.Set("root_domain", rootDomain)
		variables.Set("admin_ips_file", "/etc/haproxy/admin.allow")
		variables.Set("admin_domain", adminDomain)
		variables.Set("aut_domain", autheliaDomain)
		variables.Set("authelia_enabled", true)
		variables.Set("admin_authelia_enabled", true)
		variables.Set("admin_ips_enabled", adminIPsEnabled)
		variables.Set("admin_allowed_ips", allowedOrDefault)
		variables.Set("admin_dyn_enabled", false)
		variables.Set("admin_dyn_hostname", rootDomain)
		variables.Set("enable_http80", true)
		variables.Set("zero_trust", false)
		variables.Set("enable_geoip", geoipEnabled)
		variables.Set("geoip_mode", "allow")
		variables.Set("geoip_country_codes", countries)
		variables.Set("admin_password", false)
		variables.Set("certbot_email", certbotEmail)
		variables.Set("site_defaults", siteDefaults)
		variables.Set("mail_notify_enabled", smtpEnabled)
		variables.Set("mail_notify_only_for", []any{})
		variables.Set("mail_notify_to", mailTo)
		variables.Set("mail_notify_from", mailFrom)
		variables.Set("mail_smtp_host", smtpHost)
		variables.Set("mail_smtp_port", smtpPort)
		variables.Set("mail_smtp_user", smtpUser)
		variables.Set("mail_smtp_auth", smtpAuth)
		variables.Set("mail_smtp_ssl_mode", smtpSSLMode)
		variables.Set("mail_smtp_tls_trust_file", "/etc/ssl/certs/ca-certificates.crt")
		variables.Set("haproxy_admin_timezone", timezone)
		variables.Set("haproxy_admin_default_language", lang)
		variables.Set("haproxy_admin_image", adminImage)
		variables.Set("haproxy_admin_debug_routes", false)
		variables.Set("authelia_timezone", timezone)
		variables.Set("easy_ha_proxy_test_mode", testMode)
		variables.Set("easy_ha_proxy_test_ip", testServerIP)
		variables.Set("easy_ha_proxy_certificate_source", certSource)
	}

	var authelia *pyyaml.Map
	if hasExisting {
		authelia = pyyaml.DeepCopy(existingAuthelia).(*pyyaml.Map)
		offered := []struct {
			k string
			v any
		}{
			{"aut_domain", autheliaDomain},
			{"authelia_timezone", timezone},
			{"authelia_cookie_domain", rootDomain},
			{"authelia_portal_url", "https://" + autheliaDomain},
			{"authelia_default_redirection_url", "https://" + autheliaDomain + "/access_granted"},
		}
		for _, pair := range offered {
			if _, ok := authelia.Get(pair.k); ok {
				authelia.Set(pair.k, pair.v)
			}
		}
	} else {
		notifierType := "filesystem"
		if smtpEnabled {
			notifierType = "smtp"
		}
		smtpSSLAut := "smtp"
		if smtpPort == 465 {
			smtpSSLAut = "submissions"
		}
		authelia = pyyaml.NewMap()
		authelia.Set("authelia_enabled", true)
		authelia.Set("mail_relay_server", smtpEnabled)
		authelia.Set("admin_authelia_enabled", true)
		authelia.Set("aut_domain", autheliaDomain)
		authelia.Set("aut_geoip_enabled", false)
		authelia.Set("aut_geoip_mode", "allow")
		authelia.Set("authelia_server_address", "tcp://0.0.0.0:9091")
		authelia.Set("authelia_log_level", "warn")
		authelia.Set("authelia_session_name", "authelia_session")
		authelia.Set("authelia_session_same_site", "lax")
		authelia.Set("authelia_session_expiration", "12h")
		authelia.Set("authelia_session_inactivity", "30m")
		authelia.Set("authelia_session_remember_me", "3M")
		authelia.Set("authelia_cookie_domain", rootDomain)
		authelia.Set("authelia_portal_url", "https://"+autheliaDomain)
		authelia.Set("authelia_default_redirection_url", "https://"+autheliaDomain+"/access_granted")
		authelia.Set("authelia_storage_local_path", "/config/db.sqlite3")
		authelia.Set("authelia_users_file_path", "/config/users_database.yml")
		authelia.Set("authelia_password_algorithm", "argon2id")
		authelia.Set("authelia_regulation_modes", []any{"ip"})
		authelia.Set("authelia_regulation_max_retries", int64(5))
		authelia.Set("authelia_regulation_find_time", "2m")
		authelia.Set("authelia_regulation_ban_time", "1h")
		authelia.Set("authelia_notifier_type", notifierType)
		authelia.Set("mail_subject", fmt.Sprintf("[%s] %s", rootDomain, T("Security notification")))
		authelia.Set("authelia_notification_language", lang)
		authelia.Set("authelia_notifier_filesystem_filename", "/config/notification.log")
		authelia.Set("mail_smtp_ssl_authelia", smtpSSLAut)
		authelia.Set("mail_smtp_disable_starttls", false)
		authelia.Set("mail_smtp_disable_require_tls", false)
		authelia.Set("mail_smtp_tls_skip_verify", false)
		authelia.Set("mail_smtp_timeout", "10s")
		authelia.Set("authelia_totp_issuer", rootDomain)
		authelia.Set("authelia_totp_period", int64(30))
		authelia.Set("authelia_totp_skew", int64(1))
		authelia.Set("authelia_default_policy", "deny")
		authelia.Set("authelia_log_file_path", "/config/logs/authelia.log")
		authelia.Set("authelia_access_control_rules", defaultAutheliaRules(adminDomain, autheliaDomain))
	}

	var secretValues *pyyaml.Map
	if hasExisting {
		secretValues = pyyaml.DeepCopy(existingSecrets).(*pyyaml.Map)
	} else {
		secretValues = pyyaml.NewMap()
		secretValues.Set("authelia_session_secret", randomHex(64))
		secretValues.Set("authelia_jwt_secret", randomHex(64))
		secretValues.Set("authelia_storage_key", randomHex(64))
		secretValues.Set("mail_smtp_pass", smtpPassword)
		secretValues.Set("haproxy_admin_proxy_secret", tokenURLSafe(48))
	}

	nowISO := time.Now().UTC().Format(time.RFC3339Nano)
	var metadata *pyyaml.Map
	if hasExisting {
		metadata = pyyaml.DeepCopy(existingMeta).(*pyyaml.Map)
		metadata.Set("configured_at", nowISO)
		metadata.Set("test_mode", testMode)
		metadata.Set("certificate_source", certSource)
		metadata.Set("source_channel", sourceChannel)
		metadata.Set("image_channel", imageChannel)
		metadata.Set("test_server_ip", testServerIP)
		metadata.Set("admin_domain", adminDomain)
		metadata.Set("authelia_domain", autheliaDomain)
		metadata.Set("configuration_pending", true)
	} else {
		repo := os.Getenv("EASY_HA_PROXY_REPOSITORY")
		if repo == "" {
			repo = DefaultRepository
		}
		metadata = pyyaml.NewMap()
		metadata.Set("product", Product)
		metadata.Set("configured_at", nowISO)
		metadata.Set("repository", repo)
		metadata.Set("test_mode", testMode)
		metadata.Set("certificate_source", certSource)
		metadata.Set("source_channel", sourceChannel)
		metadata.Set("image_channel", imageChannel)
		metadata.Set("test_server_ip", testServerIP)
		metadata.Set("admin_domain", adminDomain)
		metadata.Set("authelia_domain", autheliaDomain)
		metadata.Set("installer_language", lang)
		metadata.Set("installation_complete", false)
		metadata.Set("configuration_pending", true)
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	if hasExisting {
		if _, err := BackupConfiguration(ctx.Stdout, directory); err != nil {
			return "", err
		}
	}
	for _, item := range []struct {
		name string
		data any
	}{
		{"vars.yml", variables},
		{"authelia.yml", authelia},
		{"authelia_users_initial.yml", users},
		{"websites.yml", existingWebsites},
		{"tcp.yml", existingTCP},
		{"secrets.yml", secretValues},
		{"metadata.yml", metadata},
	} {
		if err := WriteYAML(filepath.Join(directory, item.name), item.data, 0o600); err != nil {
			return "", err
		}
	}
	if err := WriteText(
		filepath.Join(directory, "inventory.ini"),
		"[easy_ha_proxy]\nlocalhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n",
		0o600,
	); err != nil {
		return "", err
	}
	if lang == "ru" {
		fmt.Fprintf(ctx.Stdout, "\nКонфигурация записана в %s\n", directory)
	} else {
		fmt.Fprintf(ctx.Stdout, "\nConfiguration written to %s\n", directory)
	}
	return directory, nil
}

func defaultAutheliaRules(adminDomain, autheliaDomain string) []any {
	r1 := pyyaml.NewMap()
	r1.Set("domain", adminDomain)
	r1.Set("subject", []any{"group:superadmin"})
	r1.Set("policy", "one_factor")

	r2 := pyyaml.NewMap()
	r2.Set("domain", adminDomain)
	r2.Set("resources", []any{"^/authelia(/.*)?$", "^/stats(/.*)?$", "^/haproxy(/.*)?$"})
	r2.Set("policy", "deny")

	r3 := pyyaml.NewMap()
	r3.Set("domain", adminDomain)
	r3.Set("subject", []any{"group:admins"})
	r3.Set("policy", "one_factor")

	r4 := pyyaml.NewMap()
	r4.Set("domain", autheliaDomain)
	r4.Set("resources", []any{"^/access_granted/?$"})
	r4.Set("policy", "one_factor")

	return []any{r1, r2, r3, r4}
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func stringsToAnySlice(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// GenerateInternalCertificate creates/reuses the internal root CA and issues a
// leaf certificate for admin_domain + authelia_domain.
func GenerateInternalCertificate(out io.Writer, directory string) (string, error) {
	return genInternalCAFn(out, directory)
}

func defaultGenerateInternalCertificate(out io.Writer, directory string) (string, error) {
	openssl, err := lookPath("openssl")
	if err != nil || openssl == "" {
		return "", installerErrorf("openssl is required for the internal certificate authority.")
	}
	metadata := LoadMetadata(directory)
	adminDomain := strings.TrimSpace(strVal(metadata.Value("admin_domain")))
	autheliaDomain := strings.TrimSpace(strVal(metadata.Value("authelia_domain")))
	if adminDomain == "" || autheliaDomain == "" {
		return "", installerErrorf("Admin or Authelia domains are missing from metadata.yml.")
	}

	certDir := filepath.Join(directory, "internal-pki")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(certDir, 0o700)

	caRoot := os.Getenv("HAPROXY_CA_ROOT_DIR")
	if caRoot == "" {
		caRoot = "/etc/haproxy/certificate-authorities"
	}
	if isSymlink(caRoot) {
		return "", installerErrorf("The certificate authority root must not be a symlink.")
	}
	if err := os.MkdirAll(caRoot, 0o700); err != nil {
		return "", err
	}
	if !isDir(caRoot) {
		return "", installerErrorf("The certificate authority root is not a directory.")
	}
	_ = os.Chmod(caRoot, 0o700)

	internalCADir := filepath.Join(caRoot, "internal")
	if isSymlink(internalCADir) {
		return "", installerErrorf("The internal certificate authority path must not be a symlink.")
	}
	if err := os.MkdirAll(internalCADir, 0o700); err != nil {
		return "", err
	}
	if !isDir(internalCADir) {
		return "", installerErrorf("The internal certificate authority path is not a directory.")
	}
	_ = os.Chmod(internalCADir, 0o700)

	caKey := filepath.Join(internalCADir, "ca.key")
	caCert := filepath.Join(internalCADir, "ca.crt")
	leafKey := filepath.Join(certDir, "server.key")
	leafReq := filepath.Join(certDir, "server.csr")
	leafCert := filepath.Join(certDir, "server.crt")
	extensions := filepath.Join(certDir, "server.ext")
	combined := filepath.Join(certDir, "easy-ha-proxy-internal.pem")

	legacyDir := filepath.Join(directory, "test-pki")
	legacyCAKey := filepath.Join(legacyDir, "ca.key")
	legacyCACert := filepath.Join(legacyDir, "ca.crt")
	if !fileExists(caKey) && !fileExists(caCert) && isRegularFile(legacyCAKey) && isRegularFile(legacyCACert) {
		if err := copyFilePreserve(legacyCAKey, caKey, 0o600); err != nil {
			return "", err
		}
		if err := copyFilePreserve(legacyCACert, caCert, 0o644); err != nil {
			return "", err
		}
	}

	if !fileExists(caKey) || !fileExists(caCert) {
		if fileExists(caKey) || fileExists(caCert) {
			return "", installerErrorf("The internal CA is incomplete; restore both ca.key and ca.crt.")
		}
		if err := runCommand(out, []string{
			openssl, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
			"-days", "3650", "-subj", "/CN=Easy HA Proxy Local Root CA",
			"-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
			"-addext", "keyUsage=critical,keyCertSign,cRLSign",
			"-addext", "subjectKeyIdentifier=hash",
			"-keyout", caKey, "-out", caCert,
		}, nil); err != nil {
			return "", err
		}
	}

	if err := runCommand(out, []string{
		openssl, "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
		"-subj", "/CN=" + adminDomain,
		"-keyout", leafKey, "-out", leafReq,
	}, nil); err != nil {
		return "", err
	}
	extText := "basicConstraints=CA:FALSE\n" +
		"keyUsage=digitalSignature,keyEncipherment\n" +
		"extendedKeyUsage=serverAuth\n" +
		fmt.Sprintf("subjectAltName=DNS:%s,DNS:%s\n", adminDomain, autheliaDomain)
	if err := WriteText(extensions, extText, 0o600); err != nil {
		return "", err
	}
	if err := runCommand(out, []string{
		openssl, "x509", "-req", "-in", leafReq,
		"-CA", caCert, "-CAkey", caKey, "-CAcreateserial",
		"-days", "397", "-sha256", "-extfile", extensions,
		"-out", leafCert,
	}, nil); err != nil {
		return "", err
	}

	leafCertText, err := os.ReadFile(leafCert)
	if err != nil {
		return "", err
	}
	leafKeyText, err := os.ReadFile(leafKey)
	if err != nil {
		return "", err
	}
	combinedText := string(leafCertText) + string(leafKeyText)
	if err := WriteText(combined, combinedText, 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(caKey, 0o600)
	_ = os.Chmod(caCert, 0o644)
	_ = os.Chmod(leafKey, 0o600)
	_ = os.Chmod(combined, 0o600)

	targetDir := os.Getenv("EASY_HA_PROXY_CERT_DIR")
	if targetDir == "" {
		targetDir = "/etc/haproxy/certs"
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}
	target := filepath.Join(targetDir, "easy-ha-proxy-internal.pem")
	if err := WriteText(target, combinedText, 0o600); err != nil {
		return "", err
	}

	caCertBytes, err := os.ReadFile(caCert)
	if err != nil {
		return "", err
	}
	exportedCA := InternalCAExportPath()
	if err := WriteText(exportedCA, string(caCertBytes), 0o644); err != nil {
		return "", err
	}
	if InstallerLanguage() == "ru" {
		fmt.Fprintf(out, "TLS-сертификат внутреннего CA установлен: %s\n", target)
		fmt.Fprintf(out, "Сертификат внутреннего CA: %s\n", caCert)
		fmt.Fprintf(out, "Публичный CA для копирования на рабочую станцию: %s\n", exportedCA)
	} else {
		fmt.Fprintf(out, "Internal-CA TLS certificate installed: %s\n", target)
		fmt.Fprintf(out, "Internal CA certificate: %s\n", caCert)
		fmt.Fprintf(out, "Public CA export for copying to a workstation: %s\n", exportedCA)
	}
	return caCert, nil
}

// PrintInternalCAInstructions prints workstation hosts-file and CA-trust instructions.
func PrintInternalCAInstructions(out io.Writer, directory string) {
	metadata := LoadMetadata(directory)
	serverIP := strings.TrimSpace(strVal(metadata.Value("test_server_ip")))
	adminDomain := strVal(metadata.Value("admin_domain"))
	autheliaDomain := strVal(metadata.Value("authelia_domain"))
	lang := InstallerLanguage()
	if serverIP != "" {
		if lang == "ru" {
			fmt.Fprintf(out, "\nДобавьте эту строку в файл hosts на рабочем компьютере:\n\n%s %s %s\n\nWindows: C:\\Windows\\System32\\drivers\\etc\\hosts\nLinux/macOS: /etc/hosts\n\n", serverIP, adminDomain, autheliaDomain)
		} else {
			fmt.Fprintf(out, "\nAdd this line to the hosts file on your workstation:\n\n%s %s %s\n\nWindows: C:\\Windows\\System32\\drivers\\etc\\hosts\nLinux/macOS: /etc/hosts\n\n", serverIP, adminDomain, autheliaDomain)
		}
	}
	exportedCA := InternalCAExportPath()
	if lang == "ru" {
		fmt.Fprintf(out, "\nОткройте https://%s/\nСкопируйте %s на рабочий компьютер и импортируйте его как доверенный корневой CA. Никогда не копируйте закрытый ключ CA.\n", adminDomain, exportedCA)
	} else {
		fmt.Fprintf(out, "\nOpen https://%s/\nCopy %s to your workstation and import it as a trusted root CA. Never copy the CA private key.\n", adminDomain, exportedCA)
	}
}

func defaultLookupHost(host string) ([]string, error) {
	return net.LookupHost(host)
}

// DNSPreflight checks DNS resolution for admin_domain and aut_domain.
func DNSPreflight(out io.Writer, directory string) (bool, error) {
	return dnsPreflightFn(out, directory)
}

func defaultDNSPreflight(out io.Writer, directory string) (bool, error) {
	varsRaw, err := os.ReadFile(filepath.Join(directory, "vars.yml"))
	if err != nil {
		return false, installerErrorf("Cannot read generated configuration: %v", err)
	}
	autRaw, err := os.ReadFile(filepath.Join(directory, "authelia.yml"))
	if err != nil {
		return false, installerErrorf("Cannot read generated configuration: %v", err)
	}
	vLoaded, err := pyyaml.Load(varsRaw)
	if err != nil {
		return false, installerErrorf("Cannot read generated configuration: %v", err)
	}
	aLoaded, err := pyyaml.Load(autRaw)
	if err != nil {
		return false, installerErrorf("Cannot read generated configuration: %v", err)
	}
	variables := mapOrEmpty(vLoaded)
	authelia := mapOrEmpty(aLoaded)

	domains := []string{
		strings.TrimSpace(strVal(variables.Value("admin_domain"))),
		strings.TrimSpace(strVal(authelia.Value("aut_domain"))),
	}
	ready := true
	lang := InstallerLanguage()
	for _, domain := range domains {
		if domain == "" {
			return false, installerErrorf("Admin or Authelia domain is missing.")
		}
		addrs, err := lookupHostFn(domain)
		if err != nil || len(addrs) == 0 {
			ready = false
			if lang == "ru" {
				fmt.Fprintf(out, "WARNING: DNS-имя %s пока не разрешается: %v. Установка может продолжиться, но первоначальный сертификат Let's Encrypt для этого имени выпущен не будет.\n", domain, err)
			} else {
				fmt.Fprintf(out, "WARNING: DNS lookup failed for %s: %v. Installation can continue, but the initial Let's Encrypt certificate for this name will not be issued.\n", domain, err)
			}
			continue
		}
		unique := uniqueSorted(addrs)
		fmt.Fprintf(out, "DNS %s: %s\n", domain, strings.Join(unique, ", "))
	}
	return ready, nil
}

func uniqueSorted(items []string) []string {
	set := map[string]bool{}
	for _, item := range items {
		set[item] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

// InstallArgs holds arguments for "easy-ha-proxy install".
type InstallArgs struct {
	Reconfigure       bool
	SkipDNSCheck      bool
	TestMode          bool
	CertificateSource string
	ImageChannel      string
	SourceChannel     string
}

// CommandInstall runs first-time (or reconfigured) installation.
func CommandInstall(ctx *Context, args InstallArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	ctx, closeInput, err := ctx.interactiveInput()
	if err != nil {
		return err
	}
	defer closeInput()
	tm := args.TestMode
	directory, err := ConfigureInteractively(ctx, ConfigureOptions{
		Overwrite:         args.Reconfigure,
		TestMode:          &tm,
		CertificateSource: args.CertificateSource,
		ImageChannel:      args.ImageChannel,
		SourceChannel:     args.SourceChannel,
	})
	if err != nil {
		return err
	}
	if err := PersistDeploymentChannels(ctx.Stdout, ChannelOptions{
		SourceChannel: args.SourceChannel,
		ImageChannel:  args.ImageChannel,
		Branch:        InstalledBranch(),
		Directory:     directory,
	}); err != nil {
		return err
	}
	testMode := IsTestMode(directory)
	internalCA := UsesInternalCA(directory)
	dnsReady := true
	if internalCA {
		if _, err := GenerateInternalCertificate(ctx.Stdout, directory); err != nil {
			return err
		}
		PrintInternalCAInstructions(ctx.Stdout, directory)
	} else if !args.SkipDNSCheck {
		dnsReady, err = DNSPreflight(ctx.Stdout, directory)
		if err != nil {
			return err
		}
	} else {
		dnsReady = false
	}

	var confirmLabel string
	switch {
	case testMode:
		confirmLabel = "The LAN/host-only IP and hosts-file setup are ready. Continue"
	case internalCA:
		confirmLabel = "Private DNS/hosts are configured and the internal CA trust plan is ready. Continue"
	case dnsReady:
		confirmLabel = "DNS is configured and TCP ports 80/443 are reachable. Continue"
	case args.SkipDNSCheck:
		confirmLabel = "DNS preflight was skipped. Continue installation"
	default:
		confirmLabel = "DNS is not ready. Continue installation and skip initial Let's Encrypt issuance for unresolved names"
	}
	confirmed, err := ctx.promptBool(confirmLabel, false)
	if err != nil {
		return err
	}
	if !confirmed {
		return installerErrorf("Installation cancelled. Configuration remains in %s.", directory)
	}
	managedPending := ManagedConfigurationIsPending(directory)
	tags := InstallTags
	if internalCA {
		tags = InternalCAInstallTags
	}
	var extraVars map[string]any
	if args.Reconfigure || managedPending {
		extraVars = map[string]any{"haproxy_admin_sync_managed_config": "true"}
	}
	if err := RunPlaybook(ctx, tags, PlaybookOptions{ExtraVars: extraVars}); err != nil {
		return err
	}
	if err := MarkInstallationComplete(directory); err != nil {
		return err
	}
	RecordAppliedSource(ctx.Stdout, directory)
	fmt.Fprintf(ctx.Stdout, "\n%s\n", T("easy-ha-proxy installation completed."))
	if internalCA {
		PrintInternalCAInstructions(ctx.Stdout, directory)
	}
	return nil
}

// ConfigureArgs holds arguments for "easy-ha-proxy configure".
type ConfigureArgs struct {
	Apply             bool
	CertificateSource string
	ImageChannel      string
}

// CommandConfigure re-runs the configuration wizard and optionally applies changes.
func CommandConfigure(ctx *Context, args ConfigureArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if err := HoldMaintenanceLock(""); err != nil {
		return err
	}
	directory, err := ConfigureInteractively(ctx, ConfigureOptions{
		Overwrite:         true,
		TestMode:          nil,
		CertificateSource: args.CertificateSource,
		ImageChannel:      args.ImageChannel,
		SourceChannel:     "",
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.Stdout, "Configuration updated. Run 'easy-ha-proxy plan' and then 'easy-ha-proxy update'.")
	if args.Apply {
		internalCA := UsesInternalCA(directory)
		if internalCA {
			if _, err := GenerateInternalCertificate(ctx.Stdout, directory); err != nil {
				return err
			}
		} else {
			if _, err := DNSPreflight(ctx.Stdout, directory); err != nil {
				return err
			}
		}
		tags := ConfigureTags
		if internalCA {
			tags = UpdateTags
		}
		if err := RunPlaybook(ctx, tags, PlaybookOptions{
			ExtraVars: map[string]any{"haproxy_admin_sync_managed_config": "true"},
		}); err != nil {
			return err
		}
		if err := MarkInstallationComplete(directory); err != nil {
			return err
		}
		RecordAppliedSource(ctx.Stdout, directory)
		if internalCA {
			PrintInternalCAInstructions(ctx.Stdout, directory)
		}
	}
	return nil
}

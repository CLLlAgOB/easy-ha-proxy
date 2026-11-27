package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// DomainChange records one human-readable preview change during domain migration.
type DomainChange struct {
	Path   string
	Before string
	After  string
}

func isDomainTokenChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-'
}

// ReplaceDomainText replaces oldDomain with newDomain respecting DNS label token boundaries
// (matching Python's `(?<![A-Za-z0-9-])<old>(?![A-Za-z0-9-])`).
func ReplaceDomainText(value, oldDomain, newDomain string) string {
	if oldDomain == "" || !strings.Contains(value, oldDomain) {
		return value
	}
	var out strings.Builder
	out.Grow(len(value))
	i := 0
	for i < len(value) {
		idx := strings.Index(value[i:], oldDomain)
		if idx < 0 {
			out.WriteString(value[i:])
			break
		}
		start := i + idx
		end := start + len(oldDomain)
		leftOK := start == 0 || !isDomainTokenChar(value[start-1])
		rightOK := end == len(value) || !isDomainTokenChar(value[end])
		if leftOK && rightOK {
			out.WriteString(value[i:start])
			out.WriteString(newDomain)
			i = end
		} else {
			out.WriteString(value[i : start+1])
			i = start + 1
		}
	}
	return out.String()
}

// ReplaceDomainInData recursively replaces oldDomain in strings inside decoded YAML data.
func ReplaceDomainInData(value any, oldDomain, newDomain, path string, changes *[]DomainChange) any {
	switch x := value.(type) {
	case *pyyaml.Map:
		out := pyyaml.NewMap()
		x.Each(func(k, v any) {
			ks := fmt.Sprint(k)
			childPath := ks
			if path != "" {
				childPath = path + "." + ks
			}
			out.Set(k, ReplaceDomainInData(v, oldDomain, newDomain, childPath, changes))
		})
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = ReplaceDomainInData(item, oldDomain, newDomain, fmt.Sprintf("%s[%d]", path, i), changes)
		}
		return out
	case string:
		if strings.Contains(x, oldDomain) {
			replaced := ReplaceDomainText(x, oldDomain, newDomain)
			if replaced != x {
				*changes = append(*changes, DomainChange{Path: path, Before: x, After: replaced})
			}
			return replaced
		}
		return x
	default:
		return pyyaml.DeepCopy(value)
	}
}

// DomainMigrationDNSNames collects sorted managed DNS names under newDomain.
func DomainMigrationDNSNames(variables, authelia, websites *pyyaml.Map, newDomain string) []string {
	names := map[string]bool{}
	addIfMatches := func(raw any) {
		v := strings.ToLower(strings.TrimSpace(strVal(raw)))
		if v != "" && (v == newDomain || strings.HasSuffix(v, "."+newDomain)) {
			names[v] = true
		}
	}
	addIfMatches(variables.Value("admin_domain"))
	addIfMatches(authelia.Value("aut_domain"))
	if sites, ok := websites.Value("sites").([]any); ok {
		for _, item := range sites {
			site, ok := item.(*pyyaml.Map)
			if !ok {
				continue
			}
			addIfMatches(site.Value("domain"))
			if alts, ok := site.Value("alt_names").([]any); ok {
				for _, alt := range alts {
					addIfMatches(alt)
				}
			}
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// VerifyPublicDNS checks public DNS records for domains using dig (1.1.1.1/8.8.8.8) or OS lookup.
func VerifyPublicDNS(out io.Writer, domains []string) bool {
	if len(domains) == 0 {
		fmt.Fprintln(out, "WARNING: No managed domains were found for public DNS validation.")
		return false
	}
	dig, _ := lookPath("dig")
	var failures []string
	for _, domain := range domains {
		addrSet := map[string]bool{}
		if dig != "" {
			for _, resolver := range []string{"1.1.1.1", "8.8.8.8"} {
				resAddrs := map[string]bool{}
				for _, recType := range []string{"A", "AAAA"} {
					res := runSubprocess(dig, "+time=3", "+tries=1", "+short", recType, domain, "@"+resolver)
					for _, line := range strings.Split(res.Stdout, "\n") {
						cand := strings.TrimSpace(line)
						if net.ParseIP(cand) != nil {
							resAddrs[cand] = true
						}
					}
				}
				if len(resAddrs) == 0 {
					failures = append(failures, fmt.Sprintf("%s via %s", domain, resolver))
				}
				for a := range resAddrs {
					addrSet[a] = true
				}
			}
		} else {
			addrs, err := lookupHostFn(domain)
			if err != nil || len(addrs) == 0 {
				failures = append(failures, domain)
			} else {
				for _, a := range addrs {
					addrSet[a] = true
				}
			}
		}
		if len(addrSet) > 0 {
			sorted := make([]string, 0, len(addrSet))
			for a := range addrSet {
				sorted = append(sorted, a)
			}
			sort.Strings(sorted)
			fmt.Fprintf(out, "DNS %s: %s\n", domain, strings.Join(sorted, ", "))
		}
	}
	if len(failures) > 0 {
		fmt.Fprintf(out, "WARNING: Public DNS is not ready for: %s. The change can continue, but Let's Encrypt issuance for unresolved names will be skipped.\n", strings.Join(failures, ", "))
		return false
	}
	return true
}

func backupRuntimeUIConfig(destination string) error {
	if !isDir(runtimeHAProxyConfigDir) {
		return nil
	}
	target := filepath.Join(destination, "runtime-haproxy-admin")
	if err := os.MkdirAll(target, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(target, 0o700)
	for _, name := range []string{"vars.yml", "websites.yml", "tcp.yml", "haproxy.cfg.j2"} {
		src := filepath.Join(runtimeHAProxyConfigDir, name)
		if isSymlink(src) {
			return installerErrorf("Runtime config %s is a symlink; refusing to copy it", src)
		}
		if isRegularFile(src) {
			if err := copyFilePreserve(src, filepath.Join(target, name), 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func restoreDomainMigrationBackup(directory, backup string) error {
	runtimeBackup := filepath.Join(backup, "runtime-haproxy-admin")
	for _, name := range []string{"vars.yml", "websites.yml", "tcp.yml", "authelia.yml", "metadata.yml"} {
		src := filepath.Join(backup, name)
		if name == "vars.yml" || name == "websites.yml" || name == "tcp.yml" {
			if cand := filepath.Join(runtimeBackup, name); isRegularFile(cand) {
				src = cand
			}
		}
		if !isRegularFile(src) {
			return installerErrorf("Rollback file is missing: %s", src)
		}
		if err := copyFilePreserve(src, filepath.Join(directory, name), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// SetMigrationValue sets key=value on m and appends a preview change if it differs.
func SetMigrationValue(m *pyyaml.Map, key string, value any, path string, changes *[]DomainChange) {
	prev, exists := m.Get(key)
	if exists && yamlValuesEqual(prev, value) {
		return
	}
	before := "None"
	if exists && prev != nil {
		before = fmt.Sprint(prev)
	}
	*changes = append(*changes, DomainChange{
		Path:   path + "." + key,
		Before: before,
		After:  fmt.Sprint(value),
	})
	m.Set(key, value)
}

// MigrateDomainArgs holds arguments for migrate-domain and promote-production.
type MigrateDomainArgs struct {
	NewDomain         string
	SkipDNSCheck      bool
	PlanOnly          bool
	PromoteProduction bool
	CertificateSource string
	ImageChannel      string
}

// CommandMigrateDomain performs reviewed root-domain migration or test-to-production promotion.
func CommandMigrateDomain(ctx *Context, args MigrateDomainArgs) error {
	if err := RequireRoot(); err != nil {
		return err
	}
	if !args.PlanOnly {
		if err := HoldMaintenanceLock(""); err != nil {
			return err
		}
	}
	directory := ConfigDir()
	if args.PromoteProduction && !IsTestMode(directory) {
		return installerErrorf("Production promotion is available only for a test-mode installation.")
	}
	requiredNames := []string{
		"vars.yml", "authelia.yml", "websites.yml", "tcp.yml",
		"metadata.yml", "inventory.ini", "secrets.yml", "authelia_users_initial.yml",
	}
	var missing []string
	for _, name := range requiredNames {
		if !isRegularFile(filepath.Join(directory, name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return installerErrorf("Managed configuration is incomplete: %s", strings.Join(missing, ", "))
	}

	// Fold the runtime UI edits into the managed config through the runtime
	// key filter first, then read only the managed files: the runtime files
	// are writable by the unprivileged panel container, so reading them raw
	// would let it inject host-owned keys (native delivery, sockets) or a
	// symlink to a root secret into a migration applied as root.
	if _, err := SyncRuntimeHAProxyConfigToManaged(ctx.Stdout, directory, ""); err != nil {
		return err
	}
	pickSource := func(name string) string {
		return filepath.Join(directory, name)
	}
	sourceOrder := []string{"vars.yml", "websites.yml", "tcp.yml", "authelia.yml", "metadata.yml"}
	sourcePaths := map[string]string{}
	current := map[string]*pyyaml.Map{}
	for _, name := range sourceOrder {
		p := pickSource(name)
		sourcePaths[name] = p
		m, err := LoadYAMLMapping(p)
		if err != nil {
			return err
		}
		current[name] = m
	}

	oldDomain := strings.ToLower(strings.TrimSpace(strVal(current["vars.yml"].Value("root_domain"))))
	if ValidateDomain(oldDomain) != "" {
		return installerErrorf("Current root_domain is missing or invalid: %q", oldDomain)
	}
	newDomain := strings.ToLower(strings.TrimSpace(args.NewDomain))
	if newDomain == "" {
		label := "New root domain"
		if args.PromoteProduction {
			label = "Production root domain"
		}
		var err error
		newDomain, err = ctx.prompt(label, "", ValidateDomain)
		if err != nil {
			return err
		}
		newDomain = strings.ToLower(newDomain)
	}
	if msg := ValidateDomain(newDomain); msg != "" {
		return installerErrorf("%s", msg)
	}
	if oldDomain == newDomain && !args.PromoteProduction {
		return installerErrorf("The new root domain is identical to the current one.")
	}

	var changes []DomainChange
	migrated := map[string]*pyyaml.Map{}
	if oldDomain == newDomain {
		for _, name := range sourceOrder {
			migrated[name] = pyyaml.DeepCopy(current[name]).(*pyyaml.Map)
		}
	} else {
		for _, name := range sourceOrder {
			migrated[name] = ReplaceDomainInData(current[name], oldDomain, newDomain, name, &changes).(*pyyaml.Map)
		}
	}

	migratedText := map[string]string{}
	if !args.PromoteProduction {
		for _, name := range []string{"vars.yml", "websites.yml", "tcp.yml", "authelia.yml"} {
			raw, err := os.ReadFile(sourcePaths[name])
			if err != nil {
				return err
			}
			replaced := ReplaceDomainText(string(raw), oldDomain, newDomain)
			parsed, err := pyyaml.Load([]byte(replaced))
			if err != nil {
				return installerErrorf("Domain replacement produced invalid YAML in %s: %v", name, err)
			}
			if !yamlValuesEqual(parsed, migrated[name]) {
				return installerErrorf("Text-preserving and structural domain replacements differ in %s.", name)
			}
			migratedText[name] = replaced
		}
	}
	migrated["vars.yml"].Set("root_domain", newDomain)
	if oldDomain != newDomain {
		migrated["metadata.yml"].Set("previous_root_domain", oldDomain)
	}
	migrated["metadata.yml"].Set("domain_migrated_at", time.Now().UTC().Format(time.RFC3339Nano))

	targetInternalCA := UsesInternalCA(directory)
	if args.PromoteProduction {
		lang := InstallerLanguage()
		certSource := strings.ToLower(strings.TrimSpace(args.CertificateSource))
		if certSource == "" {
			if lang == "ru" {
				fmt.Fprintln(ctx.Stdout, "  1) Let's Encrypt\n  2) Внутренний CA (self-signed root)")
			} else {
				fmt.Fprintln(ctx.Stdout, "  1) Let's Encrypt\n  2) Internal CA (self-signed root)")
			}
			choice, err := ctx.prompt("Initial certificate source", "2", func(v string) string {
				switch strings.ToLower(strings.TrimSpace(v)) {
				case "1", "2", "letsencrypt", "internal", "le", "ca":
					return ""
				default:
					return T("Enter letsencrypt or internal.")
				}
			})
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(choice)) {
			case "2", "internal", "ca":
				certSource = "internal"
			default:
				certSource = "letsencrypt"
			}
		}
		if msg := ValidateCertificateSource(certSource); msg != "" {
			return installerErrorf("%s", msg)
		}

		imageChannel := strings.ToLower(strings.TrimSpace(args.ImageChannel))
		if imageChannel == "" {
			if lang == "ru" {
				fmt.Fprintln(ctx.Stdout, "  1) latest (релиз)\n  2) alpha (тестовая сборка)")
			} else {
				fmt.Fprintln(ctx.Stdout, "  1) latest (release)\n  2) alpha (test build)")
			}
			choice, err := ctx.prompt("Docker image channel", "1", func(v string) string {
				switch strings.ToLower(strings.TrimSpace(v)) {
				case "1", "2", "latest", "alpha", "release", "test":
					return ""
				default:
					return T("Enter latest or alpha.")
				}
			})
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(choice)) {
			case "2", "alpha", "test":
				imageChannel = "alpha"
			default:
				imageChannel = "latest"
			}
		}
		if imageChannel != "latest" && imageChannel != "alpha" {
			return installerErrorf("Docker image channel must be latest or alpha.")
		}

		variables := migrated["vars.yml"]
		metadata := migrated["metadata.yml"]
		SetMigrationValue(variables, "easy_ha_proxy_test_mode", false, "vars.yml", &changes)
		SetMigrationValue(variables, "easy_ha_proxy_test_ip", "", "vars.yml", &changes)
		SetMigrationValue(variables, "easy_ha_proxy_certificate_source", certSource, "vars.yml", &changes)
		siteDefaults, ok := variables.Value("site_defaults").(*pyyaml.Map)
		if !ok || siteDefaults == nil {
			siteDefaults = pyyaml.NewMap()
			variables.Set("site_defaults", siteDefaults)
		}
		SetMigrationValue(siteDefaults, "certificate_source", certSource, "vars.yml.site_defaults", &changes)
		SetMigrationValue(siteDefaults, "le_managed", certSource == "letsencrypt", "vars.yml.site_defaults", &changes)
		repo := os.Getenv("EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY")
		if repo == "" {
			repo = DefaultAdminImageRepository
		}
		SetMigrationValue(variables, "haproxy_admin_image", repo+":"+imageChannel, "vars.yml", &changes)
		SetMigrationValue(metadata, "test_mode", false, "metadata.yml", &changes)
		SetMigrationValue(metadata, "test_server_ip", "", "metadata.yml", &changes)
		SetMigrationValue(metadata, "certificate_source", certSource, "metadata.yml", &changes)
		SetMigrationValue(metadata, "image_channel", imageChannel, "metadata.yml", &changes)
		SetMigrationValue(metadata, "configuration_pending", true, "metadata.yml", &changes)
		metadata.Set("promoted_to_production_at", time.Now().UTC().Format(time.RFC3339Nano))
		targetInternalCA = certSource == "internal"
	}

	if len(changes) == 0 {
		return installerErrorf("No references to %s were found in managed configuration.", oldDomain)
	}

	title := "Domain migration"
	if args.PromoteProduction {
		title = "Test-to-production promotion"
	}
	fmt.Fprintf(ctx.Stdout, "\n%s preview: %s -> %s\n", title, oldDomain, newDomain)
	fmt.Fprintln(ctx.Stdout, "Runtime UI vars/sites/TCP are used as the current source of truth.")
	for _, ch := range changes {
		fmt.Fprintf(ctx.Stdout, "  %s: %s -> %s\n", ch.Path, ch.Before, ch.After)
	}
	fmt.Fprintf(ctx.Stdout, "\nChanged values: %d\n", len(changes))

	previewDir, err := os.MkdirTemp("/tmp", "easy-ha-proxy-domain-preview.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(previewDir)
	previewSignals := make(chan os.Signal, 1)
	previewDone := make(chan struct{})
	signal.Notify(previewSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(previewSignals)
	defer close(previewDone)
	go func() {
		select {
		case sig := <-previewSignals:
			_ = os.RemoveAll(previewDir)
			signal.Stop(previewSignals)
			_ = syscall.Kill(os.Getpid(), sig.(syscall.Signal))
		case <-previewDone:
		}
	}()
	_ = os.Chmod(previewDir, 0o700)

	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(directory, entry.Name())
		info, err := os.Stat(src)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := copyFilePreserve(src, filepath.Join(previewDir, entry.Name()), 0o600); err != nil {
			return err
		}
	}
	for _, name := range sourceOrder {
		if text, ok := migratedText[name]; ok {
			if err := WriteText(filepath.Join(previewDir, name), text, 0o600); err != nil {
				return err
			}
		} else {
			if err := WriteYAML(filepath.Join(previewDir, name), migrated[name], 0o600); err != nil {
				return err
			}
		}
	}

	if !args.SkipDNSCheck && !targetInternalCA {
		VerifyPublicDNS(ctx.Stdout, DomainMigrationDNSNames(
			migrated["vars.yml"], migrated["authelia.yml"], migrated["websites.yml"], newDomain,
		))
	}

	migrationExtra := map[string]any{"haproxy_admin_sync_managed_config": "true"}
	migrationTags := DomainMigrationTags
	if args.PromoteProduction {
		if targetInternalCA {
			migrationTags = InternalCAInstallTags
		} else {
			migrationTags = InstallTags
		}
	} else if targetInternalCA {
		migrationTags = InternalCADomainMigration
	}

	fmt.Fprintln(ctx.Stdout, "\nRunning the domain migration plan...")
	if err := RunPlaybook(ctx, migrationTags, PlaybookOptions{
		CheckMode: true,
		Directory: previewDir,
		ExtraVars: migrationExtra,
	}); err != nil {
		return err
	}

	if args.PlanOnly {
		fmt.Fprintln(ctx.Stdout, "\nPlan completed. No configuration was changed.")
		return nil
	}

	confirmWord := "MIGRATE"
	if args.PromoteProduction {
		confirmWord = "PROMOTE"
	}
	confirmInput, err := ctx.readLine(fmt.Sprintf("\nType %s to switch %s to %s: ", confirmWord, oldDomain, newDomain))
	if err != nil {
		return err
	}
	if strings.TrimSpace(confirmInput) != confirmWord {
		return installerErrorf("Domain migration cancelled; no files were changed.")
	}

	backup, err := BackupConfiguration(ctx.Stdout, directory)
	if err != nil {
		return err
	}
	if backup == "" {
		return installerErrorf("Could not create the configuration backup.")
	}
	if err := backupRuntimeUIConfig(backup); err != nil {
		return err
	}
	for _, name := range sourceOrder {
		if text, ok := migratedText[name]; ok {
			if err := WriteText(filepath.Join(directory, name), text, 0o600); err != nil {
				return err
			}
		} else {
			if err := WriteYAML(filepath.Join(directory, name), migrated[name], 0o600); err != nil {
				return err
			}
		}
	}
	if targetInternalCA {
		if _, err := GenerateInternalCertificate(ctx.Stdout, directory); err != nil {
			return err
		}
	}
	if err := RunPlaybook(ctx, migrationTags, PlaybookOptions{
		Directory: directory,
		ExtraVars: migrationExtra,
	}); err != nil {
		fmt.Fprintln(ctx.Stderr, "\nDomain migration apply failed. Restoring the previous managed configuration...")
		if rerr := restoreDomainMigrationBackup(directory, backup); rerr != nil {
			fmt.Fprintf(ctx.Stderr, "Automatic rollback also failed. Protected backup: %s. Error: %v\n", backup, rerr)
			return err
		}
		rollbackInternalCA := UsesInternalCA(directory)
		var rollbackErr error
		if rollbackInternalCA {
			_, rollbackErr = GenerateInternalCertificate(ctx.Stdout, directory)
		}
		if rollbackErr == nil {
			rbTags := DomainMigrationTags
			if args.PromoteProduction {
				if rollbackInternalCA {
					rbTags = InternalCAInstallTags
				} else {
					rbTags = InstallTags
				}
			} else if rollbackInternalCA {
				rbTags = InternalCADomainMigration
			}
			rollbackErr = RunPlaybook(ctx, rbTags, PlaybookOptions{
				Directory: directory,
				ExtraVars: migrationExtra,
			})
		}
		if rollbackErr != nil {
			fmt.Fprintf(ctx.Stderr, "Automatic rollback also failed. Protected backup: %s. Error: %v\n", backup, rollbackErr)
		} else {
			fmt.Fprintln(ctx.Stderr, "Previous domain configuration restored.")
		}
		return err
	}

	if err := MarkInstallationComplete(directory); err != nil {
		return err
	}
	if args.PromoteProduction {
		fmt.Fprintf(ctx.Stdout, "\nProduction promotion completed: %s -> %s\n", oldDomain, newDomain)
	} else {
		fmt.Fprintf(ctx.Stdout, "\nDomain migration completed: %s -> %s\n", oldDomain, newDomain)
	}
	fmt.Fprintln(ctx.Stdout, "Existing Authelia sessions for the previous cookie domain may need login again.")
	return nil
}

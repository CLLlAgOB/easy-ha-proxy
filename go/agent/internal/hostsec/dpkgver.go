package hostsec

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// CompareVersions compares two Debian package versions following deb-version(7)
// (epoch:upstream-debian, ~ sorts before everything including empty).
func CompareVersions(a, b string) int {
	ea, ua, da := splitDebVersion(a)
	eb, ub, db := splitDebVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if cmp := compareDebSegment(ua, ub); cmp != 0 {
		return cmp
	}
	return compareDebSegment(da, db)
}

func splitDebVersion(v string) (int, string, string) {
	epoch := 0
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil && n >= 0 {
			epoch = n
			v = v[i+1:]
		}
	}
	if j := strings.LastIndexByte(v, '-'); j >= 0 {
		return epoch, v[:j], v[j+1:]
	}
	return epoch, v, ""
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }
func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func debCharOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case isASCIIAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareDebSegment(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		// Compare non-digit prefixes character by character.
		for (ia < len(a) && !isASCIIDigit(a[ia])) || (ib < len(b) && !isASCIIDigit(b[ib])) {
			ca, cb := 0, 0
			if ia < len(a) && !isASCIIDigit(a[ia]) {
				ca = debCharOrder(a[ia])
				ia++
			}
			if ib < len(b) && !isASCIIDigit(b[ib]) {
				cb = debCharOrder(b[ib])
				ib++
			}
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
		}
		// Skip leading zeros in digit runs.
		for ia < len(a) && a[ia] == '0' {
			ia++
		}
		for ib < len(b) && b[ib] == '0' {
			ib++
		}
		// Compare digit runs numerically.
		firstDiff := 0
		for ia < len(a) && isASCIIDigit(a[ia]) && ib < len(b) && isASCIIDigit(b[ib]) {
			if firstDiff == 0 && a[ia] != b[ib] {
				if a[ia] < b[ib] {
					firstDiff = -1
				} else {
					firstDiff = 1
				}
			}
			ia++
			ib++
		}
		if ia < len(a) && isASCIIDigit(a[ia]) {
			return 1
		}
		if ib < len(b) && isASCIIDigit(b[ib]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// APT origin & security package inspection (pure Go over apt-cache + dpkg-query)
// ---------------------------------------------------------------------------

type aptOrigin struct {
	Origin   string
	Archive  string
	Codename string
	Label    string
	Trusted  bool
}

func isSecurityOrigin(o aptOrigin, distro, codename string) bool {
	if !o.Trusted {
		return false
	}
	if distro == "ubuntu" {
		switch o.Origin {
		case "Ubuntu":
			return o.Archive == codename+"-security"
		case "UbuntuESMApps":
			return o.Archive == codename+"-apps-security"
		case "UbuntuESM":
			return o.Archive == codename+"-infra-security"
		default:
			return false
		}
	}
	return o.Origin == "Debian" && o.Label == "Debian-Security" && o.Codename == codename+"-security"
}

func isOfficialDistroOrigin(o aptOrigin, distro, codename string) bool {
	if !o.Trusted {
		return false
	}
	wantOrigin := "Debian"
	if distro == "ubuntu" {
		wantOrigin = "Ubuntu"
	}
	if o.Origin != wantOrigin {
		return false
	}
	for _, allowed := range []string{codename, codename + "-security", codename + "-updates"} {
		if o.Codename == allowed || o.Archive == allowed {
			return true
		}
	}
	return false
}

// parsePolicyFiles parses `apt-cache policy` (no args) into a map keyed by
// package-file descriptor (e.g. "http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages").
func parsePolicyFiles(text string, allowInsecure bool) map[string]aptOrigin {
	out := map[string]aptOrigin{}
	lines := strings.Split(text, "\n")
	curKey := ""
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "Pinned packages:") {
			break
		}
		if strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "     ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if _, err := strconv.Atoi(fields[0]); err == nil {
					curKey = strings.Join(fields[1:], " ")
					continue
				}
			}
		}
		if curKey != "" && strings.HasPrefix(strings.TrimSpace(line), "release ") {
			spec := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "release "))
			o := parseReleaseKV(spec)
			// Release metadata (o=/a=/n=/l=) is only attached by APT to a Release/InRelease
			// file; combined with Acquire::AllowInsecureRepositories=false and a fresh
			// apt-get --error-on=any update, it represents a trusted repository.
			o.Trusted = !allowInsecure && (o.Origin != "" || o.Archive != "" || o.Label != "" || o.Codename != "")
			out[curKey] = o
		}
	}
	return out
}

func parseReleaseKV(spec string) aptOrigin {
	var o aptOrigin
	for _, part := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "o":
			o.Origin = v
		case "a":
			o.Archive = v
		case "n":
			o.Codename = v
		case "l":
			o.Label = v
		}
	}
	return o
}

type installedPkg struct {
	FullName string
	Short    string
	Version  string
	Held     bool
}

func queryInstalledPackages() ([]installedPkg, error) {
	_, out, err := runCommand([]string{"/usr/bin/dpkg-query", "-W",
		"-f=${binary:Package}\t${db:Status-Status}\t${db:Status-Want}\t${Version}\n"},
		cmdOpts{timeout: 30 * time.Second, check: true})
	if err != nil {
		return nil, err
	}
	var pkgs []installedPkg
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 || parts[1] != "installed" {
			continue
		}
		full := parts[0]
		short, _, _ := strings.Cut(full, ":")
		pkgs = append(pkgs, installedPkg{
			FullName: full,
			Short:    short,
			Version:  parts[3],
			Held:     parts[2] == "hold",
		})
	}
	return pkgs, nil
}

type policyVersion struct {
	Version string
	Files   []string
}

// parsePackagePolicies parses `apt-cache policy pkg1 pkg2 ...` into pkg -> versions.
func parsePackagePolicies(text string) map[string][]policyVersion {
	result := map[string][]policyVersion{}
	curPkg := ""
	inTable := false
	curVerIdx := -1
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			curPkg = strings.TrimSuffix(line, ":")
			inTable = false
			curVerIdx = -1
			continue
		}
		if curPkg == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "Version table:" {
			inTable = true
			curVerIdx = -1
			continue
		}
		if !inTable {
			continue
		}
		// File source line under a version: 8 leading spaces (e.g. "        500 http://...")
		if strings.HasPrefix(line, "        ") {
			if curVerIdx >= 0 {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					if _, err := strconv.Atoi(fields[0]); err == nil {
						key := strings.Join(fields[1:], " ")
						result[curPkg][curVerIdx].Files = append(result[curPkg][curVerIdx].Files, key)
					}
				}
			}
			continue
		}
		// Version line: " *** 3.0.13 500" or "     3.0.13 500"
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			ver := fields[0]
			if ver == "***" && len(fields) >= 3 {
				ver = fields[1]
			}
			result[curPkg] = append(result[curPkg], policyVersion{Version: ver})
			curVerIdx = len(result[curPkg]) - 1
		}
	}
	return result
}

func aptAllowsInsecure() bool {
	code, out, err := runCommand([]string{"/usr/bin/apt-config", "shell",
		"INSECURE", "Acquire::AllowInsecureRepositories",
		"UNAUTH", "APT::Get::AllowUnauthenticated"},
		cmdOpts{timeout: 5 * time.Second})
	if err != nil || code != 0 {
		return false
	}
	vals := parseAptConfigShell(out)
	return parseAptBool(vals["INSECURE"], false) || parseAptBool(vals["UNAUTH"], false)
}

func parseAptConfigShell(text string) map[string]string {
	out := map[string]string{}
	for _, token := range shlexSplit(text) {
		if k, v, ok := strings.Cut(token, "="); ok {
			out[k] = v
		}
	}
	return out
}

func parseAptBool(raw string, def bool) bool {
	if raw == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// shlexSplit splits shell-quoted output from `apt-config shell` and `iptables-save`.
func shlexSplit(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				cur.WriteString(s[i+1:])
				i = len(s)
				break
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune("\\\"$`\n", rune(s[i+1])) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == '\\' && i+1 < len(s):
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

type securityPackageRow struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Candidate string `json:"candidate"`
	Protected bool   `json:"protected"`
	Held      bool   `json:"held"`
}

func loadPolicyOrigins() (map[string]aptOrigin, error) {
	_, globalOut, err := runCommand([]string{"/usr/bin/apt-cache", "policy"}, cmdOpts{timeout: 30 * time.Second, check: true, rawOutput: true})
	if err != nil {
		return nil, err
	}
	return parsePolicyFiles(globalOut, aptAllowsInsecure()), nil
}

// querySecurityPackages finds all installed packages with a newer version from
// a trusted distribution security origin.
var querySecurityPackages = func(distro, codename string) ([]securityPackageRow, error) {
	origins, err := loadPolicyOrigins()
	if err != nil {
		return nil, err
	}
	installed, err := queryInstalledPackages()
	if err != nil {
		return nil, err
	}
	if len(installed) == 0 {
		return []securityPackageRow{}, nil
	}
	allPolicies := map[string][]policyVersion{}
	const batchSize = 100
	for i := 0; i < len(installed); i += batchSize {
		end := i + batchSize
		if end > len(installed) {
			end = len(installed)
		}
		argv := make([]string, 0, 2+(end-i))
		argv = append(argv, "/usr/bin/apt-cache", "policy")
		for _, p := range installed[i:end] {
			argv = append(argv, p.FullName)
		}
		_, out, err := runCommand(argv, cmdOpts{timeout: 60 * time.Second, check: true, rawOutput: true})
		if err != nil {
			return nil, err
		}
		for k, v := range parsePackagePolicies(out) {
			allPolicies[k] = v
		}
	}
	rows := []securityPackageRow{}
	for _, pkg := range installed {
		vers := allPolicies[pkg.FullName]
		if len(vers) == 0 {
			vers = allPolicies[pkg.Short]
		}
		bestVer := ""
		for _, pv := range vers {
			if CompareVersions(pv.Version, pkg.Version) <= 0 {
				continue
			}
			hasSecOrigin := false
			for _, f := range pv.Files {
				if o, ok := origins[f]; ok && isSecurityOrigin(o, distro, codename) {
					hasSecOrigin = true
					break
				}
			}
			if !hasSecOrigin {
				continue
			}
			if bestVer == "" || CompareVersions(pv.Version, bestVer) > 0 {
				bestVer = pv.Version
			}
		}
		if bestVer == "" {
			continue
		}
		if !osPkgNameRe.MatchString(pkg.FullName) {
			return nil, secErr("Invalid APT package name")
		}
		rows = append(rows, securityPackageRow{
			Name:      pkg.FullName,
			Installed: pkg.Version,
			Candidate: bestVer,
			Protected: osProtectedPackages[pkg.Short],
			Held:      pkg.Held,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func checkOfficialPackageVersion(origins map[string]aptOrigin, distro, codename, name, version string) (bool, error) {
	_, out, err := runCommand([]string{"/usr/bin/apt-cache", "policy", name}, cmdOpts{timeout: 30 * time.Second, check: true, rawOutput: true})
	if err != nil {
		return false, err
	}
	policies := parsePackagePolicies(out)
	vers := policies[name]
	if len(vers) == 0 {
		short, _, _ := strings.Cut(name, ":")
		vers = policies[short]
	}
	for _, pv := range vers {
		if pv.Version != version {
			continue
		}
		for _, f := range pv.Files {
			if o, ok := origins[f]; ok && isOfficialDistroOrigin(o, distro, codename) {
				return true, nil
			}
		}
	}
	return false, nil
}

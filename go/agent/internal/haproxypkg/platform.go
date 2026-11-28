// Package haproxypkg describes the qualified HAProxy package paths for each OS.
package haproxypkg

import (
	"os"
	"strings"
)

type Platform struct {
	Distribution string
	Codename     string
	Baseline     string
	Target       string
	Architecture string
}

const SupportedHosts = "Ubuntu 24.04 or Debian 12 on AMD64 or ARM64"

func ForOS(id, version, arch string) Platform {
	switch arch {
	case "amd64", "x86_64":
		arch = "amd64"
	case "arm64", "aarch64":
		arch = "arm64"
	default:
		return Platform{}
	}
	switch strings.ToLower(id) + ":" + version {
	case "ubuntu:24.04", "ubuntu:noble":
		return Platform{"Ubuntu", "noble", "2.8", "3.4", arch}
	case "debian:12", "debian:bookworm":
		return Platform{"Debian", "bookworm", "2.6", "3.2", arch}
	default:
		return Platform{}
	}
}

func ReadPlatform(path, arch string) Platform {
	data, err := os.ReadFile(path)
	if err != nil {
		return Platform{}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	p := ForOS(fields["ID"], fields["VERSION_ID"], arch)
	if codename := fields["VERSION_CODENAME"]; codename != "" && codename != p.Codename {
		return Platform{}
	}
	return p
}

func (p Platform) Repository() string {
	return "https://www.haproxy.com/download/haproxy/performance/" +
		strings.ToLower(p.Distribution) + "/ha" + strings.ReplaceAll(p.Target, ".", "")
}

func (p Platform) SourceLine(key string) string {
	return "deb [arch=" + p.Architecture + " signed-by=" + key + "] " + p.Repository() + " " + p.Codename + " main"
}

func Pin(branch string) string {
	return "# Only the explicitly selected HAProxy branch may be installed.\n" + `Package: haproxy-awslc
Pin: version ` + branch + `.*
Pin-Priority: 990

Package: haproxy-awslc
Pin: version *
Pin-Priority: -1

# A distribution update must not replace this provider implicitly.
Package: haproxy
Pin: version *
Pin-Priority: -1

# Do not let this extra repository replace unrelated system packages.
Package: *
Pin: origin "www.haproxy.com"
Pin-Priority: 100
`
}

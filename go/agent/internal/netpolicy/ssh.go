// Package netpolicy validates outbound destinations delegated to OpenSSH.
package netpolicy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	sshHostname = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]*$`)
	metadataV4  = netip.MustParseAddr("100.100.100.200")
	metadataV6  = netip.MustParseAddr("fd00:ec2::254")
)

func forbiddenSSHAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return !addr.IsGlobalUnicast() || addr.Zone() != "" || addr == metadataV4 || addr == metadataV6
}

func ValidateSSHHost(raw string) error {
	host := strings.TrimPrefix(strings.TrimSuffix(raw, "]"), "[")
	if addr, err := netip.ParseAddr(host); err == nil {
		if forbiddenSSHAddr(addr) {
			return fmt.Errorf("SSH destination is a forbidden address")
		}
		return nil
	}
	if len(raw) > 253 || !sshHostname.MatchString(raw) {
		return fmt.Errorf("SSH destination host is invalid")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("SSH destination cannot be localhost")
	}
	return nil
}

// ResolveSSHHost resolves once. The caller must pass the numeric address to
// the subprocess to prevent DNS changes between policy check and connection.
func ResolveSSHHost(raw string) (string, error) {
	if err := ValidateSSHHost(raw); err != nil {
		return "", err
	}
	host := strings.Trim(raw, "[]")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("SSH destination does not resolve: %w", err)
	}
	for _, addr := range addrs {
		if forbiddenSSHAddr(addr) {
			return "", fmt.Errorf("SSH destination resolves to a forbidden address")
		}
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("SSH destination did not resolve to an address")
	}
	return addrs[0].Unmap().String(), nil
}

// SSHKnownHost keeps saved host keys associated with the operator's original
// host and port while the transport uses the checked numeric address.
func SSHKnownHost(host string, port int64) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if port != 22 {
		return "[" + host + "]:" + strconv.FormatInt(port, 10)
	}
	return host
}

func SSHOptions(address, knownHost string) []string {
	return []string{"-F", "/dev/null", "-o", "HostName=" + address, "-o", "HostKeyAlias=" + knownHost}
}

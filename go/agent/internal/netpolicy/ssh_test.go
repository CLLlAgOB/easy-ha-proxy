package netpolicy

import "testing"

func TestSSHDestinationPolicy(t *testing.T) {
	for _, host := range []string{"localhost.", "ssh.localhost", "127.0.0.1", "[::1]", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "[fd00:ec2::254]"} {
		if _, err := ResolveSSHHost(host); err == nil {
			t.Errorf("allowed %q", host)
		}
	}
	for _, host := range []string{"192.168.1.20", "fd00::1"} {
		if got, err := ResolveSSHHost(host); err != nil || got != host {
			t.Errorf("allowed LAN address %q resolved to %q, %v", host, got, err)
		}
	}
	if got := SSHKnownHost("[2001:db8::4]", 2222); got != "[2001:db8::4]:2222" {
		t.Errorf("host key alias = %q", got)
	}
}

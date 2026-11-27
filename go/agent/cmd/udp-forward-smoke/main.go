// Command udp-forward-smoke drives the agent's udp-forward through real
// netns/iptables/ipset plumbing and verifies actual UDP replies, bans,
// zero-trust authorization, Docker rule reordering, isolation and removal.
//
// Run ONLY inside a disposable privileged container with iproute2/iptables/
// ipset. AGENT_BIN must point at the easy-ha-proxy-agent binary:
//
//	AGENT_BIN=<easy-ha-proxy-agent> udp-forward-smoke
//
// It creates a client and a backend netns; the container is the gateway.
// Never run it against a production network namespace. The UDP echo server
// and the client probe are this same binary re-executed inside the netns via
// the "echo" and "probe" subcommands (Python used sys.executable -c).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	banSet  = "haproxy_ban"
	authSet = "haproxy_ip_auth"
)

func main() {
	// Re-exec subcommands used inside the network namespaces.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "echo":
			runEcho()
			return
		case "probe":
			runProbe()
			return
		}
	}
	if err := smoke(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run executes a command, capturing stdout and stderr separately (Python's
// subprocess.run(check=True, capture_output=True, text=True)). On failure the
// error carries the captured output, as CalledProcessError does.
func run(args ...string) (string, error) {
	return runEnv(nil, args...)
}

func runEnv(env []string, args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%s: %w\n%s%s",
			strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

func smoke() error {
	// Refuse to run anywhere but a disposable privileged container.
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		return fmt.Errorf("Use a disposable privileged Docker container, never a host")
	}
	agent := os.Getenv("AGENT_BIN")
	if !executable(agent) {
		return fmt.Errorf("Set AGENT_BIN to the easy-ha-proxy-agent binary")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}

	// Create the client and backend netns with their veth pairs; the
	// container keeps the .1 gateway address of each /24.
	for _, ns := range []struct{ name, address, iface, peer string }{
		{"client", "192.0.2", "uc0", "uc1"},
		{"backend", "198.51.100", "ub0", "ub1"},
	} {
		for _, args := range [][]string{
			{"ip", "netns", "add", ns.name},
			{"ip", "link", "add", ns.iface, "type", "veth", "peer", "name", ns.peer},
			{"ip", "link", "set", ns.peer, "netns", ns.name},
			{"ip", "addr", "add", ns.address + ".1/24", "dev", ns.iface},
			{"ip", "link", "set", ns.iface, "up"},
			{"ip", "-n", ns.name, "addr", "add", ns.address + ".2/24", "dev", ns.peer},
			{"ip", "-n", ns.name, "link", "set", ns.peer, "up"},
			{"ip", "-n", ns.name, "link", "set", "lo", "up"},
			{"ip", "-n", ns.name, "route", "add", "default", "via", ns.address + ".1"},
		} {
			if _, err := run(args...); err != nil {
				return err
			}
		}
	}
	for _, name := range []string{banSet, authSet} {
		if _, err := run("ipset", "create", name, "hash:ip"); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{"iptables-nft", "-N", "DOCKER-USER"},
		{"iptables-nft", "-N", "DOCKER-FORWARD"},
		{"iptables-nft", "-A", "DOCKER-FORWARD", "-j", "DROP"},
		{"iptables-nft", "-A", "FORWARD", "-j", "DOCKER-USER"},
		{"iptables-nft", "-A", "FORWARD", "-j", "DOCKER-FORWARD"},
		{"iptables-nft", "-P", "FORWARD", "DROP"},
	} {
		if _, err := run(args...); err != nil {
			return err
		}
	}

	// UDP echo server in the backend netns: this binary's "echo" subcommand.
	server := exec.Command("ip", "netns", "exec", "backend", self, "echo")
	if err := server.Start(); err != nil {
		return err
	}
	// Mirror the Python finally: stop the server and delete both netns even
	// when a check fails. The container is disposable, so an orphaned echo
	// child (as under Python's SIGTERM to `ip`) is reaped at container exit.
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
		_, _ = run("ip", "netns", "del", "client")
		_, _ = run("ip", "netns", "del", "backend")
	}()

	// exchange runs the client probe inside the client netns and requires it
	// to exit 0, i.e. the observed reply must match `expected`.
	exchange := func(expected bool, host string, port int) error {
		_, err := run("ip", "netns", "exec", "client", self, "probe",
			strconv.FormatBool(expected), host, strconv.Itoa(port))
		return err
	}

	time.Sleep(200 * time.Millisecond)
	directory, err := os.MkdirTemp("", "udp-forward-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)

	config := filepath.Join(directory, "udp.yml")
	// Copy the environment and override the HP_UDP_* knobs (Go keeps the last
	// value for a duplicate key, so appending overrides os.Environ()).
	env := append(os.Environ(),
		"HP_UDP_CONFIG="+config,
		"HP_UDP_STATE="+filepath.Join(directory, "state.json"),
		"HP_UDP_FAILOVER="+filepath.Join(directory, "failover.json"),
		"HP_UDP_BAN_SET="+banSet,
		"HP_UDP_AUTH_SET="+authSet,
	)
	apply := func(forwards ...map[string]any) error {
		// udp.yml is YAML; JSON is a subset of it.
		data, err := json.Marshal(map[string]any{"udp_forwards": forwards})
		if err != nil {
			return err
		}
		if err := os.WriteFile(config, data, 0o644); err != nil {
			return err
		}
		_, err = runEnv(env, agent, "udp-forward")
		return err
	}

	forward := map[string]any{"listen_port": 20000, "backend_host": "198.51.100.2", "backend_port": 30000}
	zeroTrust := func() map[string]any {
		m := map[string]any{}
		for k, v := range forward {
			m[k] = v
		}
		m["zero_trust"] = true
		return m
	}

	if err := apply(forward); err != nil {
		return err
	}
	if err := exchange(true, "192.0.2.1", 20000); err != nil {
		return err
	}
	// Docker can put its own jumps back ahead of the UDP FORWARD hook.
	for _, chain := range []string{"DOCKER-USER", "DOCKER-FORWARD"} {
		if _, err := run("iptables-nft", "-D", "FORWARD", "-j", chain); err != nil {
			return err
		}
	}
	for _, chain := range []string{"DOCKER-FORWARD", "DOCKER-USER"} {
		if _, err := run("iptables-nft", "-I", "FORWARD", "1", "-j", chain); err != nil {
			return err
		}
	}
	if err := exchange(true, "192.0.2.1", 20000); err != nil {
		return err
	}
	// Direct traffic is not opened.
	if err := exchange(false, "198.51.100.2", 30000); err != nil {
		return err
	}
	if _, err := run("ipset", "add", banSet, "192.0.2.2"); err != nil {
		return err
	}
	if err := exchange(false, "192.0.2.1", 20000); err != nil {
		return err
	}
	if _, err := run("ipset", "del", banSet, "192.0.2.2"); err != nil {
		return err
	}
	if err := apply(zeroTrust()); err != nil {
		return err
	}
	if err := exchange(false, "192.0.2.1", 20000); err != nil {
		return err
	}
	if _, err := run("ipset", "add", authSet, "192.0.2.2"); err != nil {
		return err
	}
	if err := exchange(true, "192.0.2.1", 20000); err != nil {
		return err
	}
	if err := apply(zeroTrust()); err != nil { // repeated apply
		return err
	}
	if err := exchange(true, "192.0.2.1", 20000); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return err
	}
	if err := exchange(false, "192.0.2.1", 20000); err != nil {
		return err
	}

	stateRaw, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if err != nil {
		return err
	}
	var state map[string]any
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		return err
	}
	if state["forwards"] != float64(0) {
		return fmt.Errorf("expected 0 forwards after removal, state: %s", stateRaw)
	}
	out, err := run("iptables-nft", "-S", "FORWARD")
	if err != nil {
		return err
	}
	policy := strings.SplitN(out, "\n", 2)[0]
	if policy != "-P FORWARD DROP" {
		return fmt.Errorf("unexpected FORWARD policy: %q", policy)
	}
	fmt.Println("PASS: mixed Docker filters, UDP replies, ordering, bans, zero trust, isolation, removal")
	return nil
}

// executable reports whether path is an executable file (os.access X_OK).
func executable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

// runEcho is the backend UDP echo server: bind 198.51.100.2:30000 and send
// every datagram back to its sender.
func runEcho() {
	conn, err := net.ListenPacket("udp", "198.51.100.2:30000")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := conn.WriteTo(buf[:n], peer); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// runProbe is the client probe: send "udp-proof" and check the reply.
// Usage: udp-forward-smoke probe <expected:true|false> <host> <port>
// It exits 0 when the observed reply matches `expected`, else 1.
func runProbe() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: udp-forward-smoke probe <expected:true|false> <host> <port>")
		os.Exit(1)
	}
	expected := os.Args[2] == "true"
	addr := net.JoinHostPort(os.Args[3], os.Args[4])
	conn, err := net.Dial("udp", addr)
	if err != nil {
		// A dial failure means no reply, i.e. ok == false.
		if !expected {
			os.Exit(0)
		}
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	ok := false
	if _, err := conn.Write([]byte("udp-proof")); err == nil {
		buf := make([]byte, 1024)
		if n, err := conn.Read(buf); err == nil {
			ok = string(buf[:n]) == "udp-proof"
		}
	}
	if ok == expected {
		os.Exit(0)
	}
	os.Exit(1)
}

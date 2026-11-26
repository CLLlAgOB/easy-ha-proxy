package hostsec

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func saveSSHGlobals(t *testing.T) {
	t.Helper()
	origClient := sshClientPath
	origSysctl := sshSystemctlPath
	origConfig := sshConfigDir
	origDropIn := sshDropInPath
	origAuthLog := sshAuthLogPath
	origInet6 := sshProcIfInet6
	origQuick := sshQuickFunc
	origLookPath := sshLookPathFunc
	origSleep := sshSleepFunc
	origRun := runCommand
	origPlat := checkPlatform
	origRoot := requireRootOwner
	t.Cleanup(func() {
		sshClientPath = origClient
		sshSystemctlPath = origSysctl
		sshConfigDir = origConfig
		sshDropInPath = origDropIn
		sshAuthLogPath = origAuthLog
		sshProcIfInet6 = origInet6
		sshQuickFunc = origQuick
		sshLookPathFunc = origLookPath
		sshSleepFunc = origSleep
		runCommand = origRun
		checkPlatform = origPlat
		requireRootOwner = origRoot
	})
}

func TestSSHFirewallMatchesPortsAndActiveIPsForBothFamilies(t *testing.T) {
	saveSSHGlobals(t)
	hook := "-A INPUT -p tcp -m multiport --dports 22,2222 -j f2b-sshd\n"
	ipv4 := hook + "-A f2b-sshd -s 192.0.2.2/32 -j REJECT --reject-with icmp-port-unreachable\n"
	ipv6 := hook + "-A f2b-sshd -s 2001:db8::2/128 -j REJECT --reject-with icmp6-port-unreachable\n"
	status := &sshJailStatusData{Banned: []string{"192.0.2.2", "2001:db8::2"}, CurrentlyBanned: 2}

	var calls [][]string
	responses := []string{ipv4, ipv6}
	sshQuickFunc = func(argv ...string) (int, string) {
		calls = append(calls, argv)
		out := responses[0]
		responses = responses[1:]
		return 0, out
	}
	got := sshFirewallStatus([]int{22, 2222}, []int{2222, 22}, status)
	want := map[string]any{"state": "verified", "families": map[string]string{"4": "verified", "6": "verified"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	wantCalls := [][]string{
		{"/usr/sbin/iptables-save", "-t", "filter"},
		{"/usr/sbin/ip6tables-save", "-t", "filter"},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls %#v, want %#v", calls, wantCalls)
	}

	responses = []string{ipv4, hook}
	got = sshFirewallStatus([]int{22, 2222}, []int{22, 2222}, status)
	if got["state"] != "missing" {
		t.Fatalf("expected missing, got %v", got)
	}

	called := false
	sshQuickFunc = func(argv ...string) (int, string) {
		called = true
		return 0, ""
	}
	if sshFirewallStatus([]int{22}, []int{2222}, status)["state"] != "ports_changed" {
		t.Fatal("expected ports_changed")
	}
	if sshFirewallStatus([]int{22}, []int{22}, &sshJailStatusData{})["state"] != "idle" {
		t.Fatal("expected idle")
	}
	if called {
		t.Fatal("quick should not have been called for ports_changed/idle")
	}
}

func TestSSHFirewallDoesNotClaimRulesBelowEarlierVerdicts(t *testing.T) {
	saveSSHGlobals(t)
	hook := "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n"
	block := "-A f2b-sshd -s 192.0.2.2/32 -j DROP\n"
	sshQuickFunc = func(argv ...string) (int, string) { return 0, "-A INPUT -j ACCEPT\n" + hook + block }
	if got := sshFirewallFamily(4, []int{22}, map[string]bool{"192.0.2.2": true}); got != "order_unknown" {
		t.Fatalf("got %q, want order_unknown", got)
	}
	sshQuickFunc = func(argv ...string) (int, string) { return 0, hook + "-A f2b-sshd -j RETURN\n" + block }
	if got := sshFirewallFamily(4, []int{22}, map[string]bool{"192.0.2.2": true}); got != "missing" {
		t.Fatalf("got %q, want missing", got)
	}
}

func TestSSHPanelHTTPBanChainKeepsBlocksVerified(t *testing.T) {
	saveSSHGlobals(t)
	hook := "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n"
	block := "-A f2b-sshd -s 192.0.2.2/32 -j REJECT --reject-with icmp-port-unreachable\n"
	sshQuickFunc = func(argv ...string) (int, string) { return 0, "-A INPUT -j HP_BAN\n" + hook + block }
	if got := sshFirewallFamily(4, []int{22}, map[string]bool{"192.0.2.2": true}); got != "verified" {
		t.Fatalf("got %q, want verified", got)
	}
	sshQuickFunc = func(argv ...string) (int, string) {
		return 0, "-A INPUT -j HP_BAN\n-A INPUT -j ACCEPT\n" + hook + block
	}
	if got := sshFirewallFamily(4, []int{22}, map[string]bool{"192.0.2.2": true}); got != "order_unknown" {
		t.Fatalf("got %q, want order_unknown", got)
	}
}

func TestSSHFirewallJailChainOrdering(t *testing.T) {
	saveSSHGlobals(t)
	hook := "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n"
	block := "-A f2b-sshd -s 192.0.2.2/32 -j DROP\n"
	for _, earlier := range []string{"-j ACCEPT", "-s 192.0.2.0/24 -j RETURN", "-j custom-chain"} {
		sshQuickFunc = func(argv ...string) (int, string) {
			return 0, hook + "-A f2b-sshd " + earlier + "\n" + block
		}
		if got := sshFirewallFamily(4, []int{22}, map[string]bool{"192.0.2.2": true}); got != "order_unknown" {
			t.Fatalf("earlier=%q: got %q, want order_unknown", earlier, got)
		}
	}
	sshQuickFunc = func(argv ...string) (int, string) {
		return 0, hook + block + "-A f2b-sshd -j ACCEPT\n"
	}
	if got := sshFirewallFamily(4, []int{22}, map[string]bool{"192.0.2.2": true}); got != "verified" {
		t.Fatalf("later rule made block uncertain: got %q", got)
	}
}

func TestSSHBanTimes(t *testing.T) {
	saveSSHGlobals(t)
	output := "192.0.2.1 \t2026-11-19 11:00:00 + 3600 = 2026-11-19 12:00:00\n" +
		"2001:0db8::1 \t2026-11-19 11:10:00 + -1 = 9999-12-31 23:59:59\n" +
		"192.0.2.9 \t2026-11-19 11:10:00 + 3600 = 2026-11-19 12:10:00"
	sshQuickFunc = func(argv ...string) (int, string) { return 0, output }
	got := sshBanTimes([]string{"192.0.2.1", "2001:db8::1"})
	want := map[string]map[string]any{
		"192.0.2.1":   {"started": "2026-11-19 11:00:00", "expires": "2026-11-19 12:00:00", "permanent": false},
		"2001:db8::1": {"started": "2026-11-19 11:10:00", "expires": nil, "permanent": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestSSHCheckConnection(t *testing.T) {
	saveSSHGlobals(t)
	var calledArgv []string
	sshQuickFunc = func(argv ...string) (int, string) {
		calledArgv = argv
		return 0, "passwordauthentication no\nallowusers operator\nallowusers backup\n"
	}
	got, err := sshCheckConnection("operator", "2001:0db8::2", "vpn.example.test", "192.0.2.5", "22")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"passwordauthentication": "no", "allowusers": "operator backup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	wantArgv := []string{"/usr/sbin/sshd", "-T", "-C", "user=operator,addr=2001:db8::2,host=vpn.example.test,laddr=192.0.2.5,lport=22"}
	if !reflect.DeepEqual(calledArgv, wantArgv) {
		t.Fatalf("argv %#v, want %#v", calledArgv, wantArgv)
	}
	if _, err := sshCheckConnection("operator,addr=192.0.2.1", "192.0.2.2", "", "", ""); err == nil {
		t.Fatal("expected error for invalid username with comma")
	}
}

func TestSSHManagedConfigAndValidation(t *testing.T) {
	saveSSHGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	sshDropInPath = filepath.Join(dir, "99-easy-ha-proxy-sshd.local")

	custom := SSHPolicy{MaxRetry: 8, FindTime: 900, BanTime: 7200}
	for _, pol := range []*SSHPolicy{nil, &custom} {
		txt := sshConfigText(true, []int{22}, "systemd", nil, pol)
		if err := os.WriteFile(sshDropInPath, []byte(txt), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := sshManagedConfig()
		if err != nil {
			t.Fatalf("pol=%v: %v", pol, err)
		}
		want := defaultSSHPolicy()
		if pol != nil {
			want = *pol
		}
		if got.Policy != want {
			t.Fatalf("got policy %+v, want %+v", got.Policy, want)
		}
	}
	if _, err := sshValidatePolicy(SSHPolicy{MaxRetry: 8, FindTime: 900, BanTime: -1}); err == nil {
		t.Fatal("expected error for negative bantime")
	}
}

func TestSSHJailStatusParsing(t *testing.T) {
	saveSSHGlobals(t)
	output := "Status for the jail: sshd\n" +
		"|- Filter\n" +
		"|  |- Currently failed: 2\n" +
		"|  `- Total failed: 31\n" +
		"`- Actions\n" +
		"   |- Currently banned: 2\n" +
		"   |- Total banned: 4\n" +
		"   `- Banned IP list: 192.0.2.1 2001:db8::1 arbitrary-text\n"
	var gotArgv []string
	sshQuickFunc = func(argv ...string) (int, string) {
		gotArgv = argv
		return 0, output
	}
	st, err := sshJailStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.CurrentlyFailed != 2 || st.TotalFailed != 31 || st.CurrentlyBanned != 2 || st.TotalBanned != 4 ||
		!reflect.DeepEqual(st.Banned, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("unexpected jail status: %+v", st)
	}
	if !reflect.DeepEqual(gotArgv, []string{sshClientPath, "status", "sshd"}) {
		t.Fatalf("unexpected argv: %#v", gotArgv)
	}
}

func TestSSHSetProtectionInstallAndRollback(t *testing.T) {
	saveSSHGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	sshConfigDir = filepath.Join(dir, "fail2ban")
	sshDropInPath = filepath.Join(sshConfigDir, "jail.d", "99-easy-ha-proxy-sshd.local")
	if err := os.MkdirAll(filepath.Dir(sshDropInPath), 0o755); err != nil {
		t.Fatal(err)
	}
	sshClientPath = filepath.Join(dir, "fail2ban-client")
	sshProcIfInet6 = filepath.Join(dir, "no-inet6")
	sshAuthLogPath = filepath.Join(dir, "auth.log")
	if err := os.WriteFile(sshAuthLogPath, []byte("log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkPlatform = func() (string, string, error) { return "ubuntu", "noble", nil }
	sshLookPathFunc = func(name, _ string) string { return "/usr/sbin/" + name }
	oldGuardDir := runGuardDir
	oldMigDir := haproxyMigrationDir
	oldUI := haproxyPendingUIFile
	oldTx := haproxyGuardTxFile
	oldLocks := aptLockPaths
	runGuardDir = filepath.Join(dir, "run")
	haproxyMigrationDir = filepath.Join(dir, "mig")
	haproxyPendingUIFile = filepath.Join(dir, "ui")
	haproxyGuardTxFile = filepath.Join(dir, "tx")
	aptLockPaths = nil
	t.Cleanup(func() {
		runGuardDir = oldGuardDir
		haproxyMigrationDir = oldMigDir
		haproxyPendingUIFile = oldUI
		haproxyGuardTxFile = oldTx
		aptLockPaths = oldLocks
	})

	// 1. Install stages disabled rule before apt-get, then writes active config.
	var cmds [][]string
	var stagedAtApt string
	runCommand = func(argv []string, opts cmdOpts) (int, string, error) {
		cmds = append(cmds, argv)
		if argv[0] == "/usr/bin/apt-get" {
			raw, _ := os.ReadFile(sshDropInPath)
			stagedAtApt = string(raw)
			_ = os.WriteFile(sshClientPath, []byte("bin"), 0o755)
		}
		return 0, "", nil
	}
	sshQuickFunc = func(argv ...string) (int, string) {
		if len(argv) >= 2 && strings.HasSuffix(argv[0], "ss") {
			return 0, "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
				"LISTEN 0 128 0.0.0.0:22022 0.0.0.0:* users:((\"sshd\",pid=1,fd=4))\n"
		}
		if len(argv) >= 2 && argv[1] == "is-active" {
			return 3, "inactive\n"
		}
		if len(argv) >= 2 && argv[0] == "/usr/bin/journalctl" {
			return 0, "{\"_COMM\":\"sshd\"}\n"
		}
		if len(argv) >= 2 && argv[1] == "ping" {
			return 0, "Server replied: pong\n"
		}
		if len(argv) >= 2 && argv[1] == "status" {
			return 0, "|- Currently failed: 0\n`- Total failed: 0\n|- Currently banned: 0\n`- Total banned: 0\n`- Banned IP list:\n"
		}
		return 0, ""
	}
	msg, err := SSHSetProtection("install", []string{"2001:db8::/64"}, nil)
	if err != nil || msg != "SSH protection is enabled." {
		t.Fatalf("install failed: %q %v", msg, err)
	}
	if stagedAtApt != sshConfigText(false, nil, "", nil, nil) {
		t.Fatalf("disabled drop-in not staged before apt-get: %q", stagedAtApt)
	}
	finalCfg, err := os.ReadFile(sshDropInPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(finalCfg), "port = 2222,22022") ||
		!strings.Contains(string(finalCfg), "ignoreip = 127.0.0.0/8 ::1 2001:db8::/64") {
		t.Fatalf("unexpected final drop-in:\n%s", string(finalCfg))
	}

	// 2. Failed verification restores previous rule and reloads only sshd.
	saved := sshConfigText(true, []int{2222, 22022}, "polling", []string{"192.0.2.1"}, nil)
	if err := os.WriteFile(sshDropInPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	statusCalls := 0
	sshQuickFunc = func(argv ...string) (int, string) {
		if len(argv) >= 2 && strings.HasSuffix(argv[0], "ss") {
			return 0, "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
		}
		if len(argv) >= 2 && argv[1] == "is-active" {
			return 3, "inactive\n"
		}
		if len(argv) >= 2 && argv[0] == "/usr/bin/journalctl" {
			return 1, ""
		}
		if len(argv) >= 2 && argv[1] == "ping" {
			return 0, "pong\n"
		}
		if len(argv) >= 2 && argv[1] == "status" {
			statusCalls++
			if statusCalls == 1 {
				return 0, "|- Currently failed: 0\n`- Total failed: 0\n|- Currently banned: 0\n`- Total banned: 0\n`- Banned IP list:\n"
			}
			return 1, ""
		}
		return 0, ""
	}
	cmds = nil
	if _, err := SSHSetProtection("enable", []string{"192.0.2.44"}, nil); err == nil || !strings.Contains(err.Error(), "could not be verified") {
		t.Fatalf("expected verification error, got %v", err)
	}
	restored, _ := os.ReadFile(sshDropInPath)
	if string(restored) != saved {
		t.Fatalf("previous drop-in was not restored:\ngot: %q\nwant: %q", string(restored), saved)
	}
	lastCmd := cmds[len(cmds)-1]
	if !reflect.DeepEqual(lastCmd, []string{sshClientPath, "reload", "--if-exists", "sshd"}) {
		t.Fatalf("expected reload of sshd on rollback, got %#v", lastCmd)
	}
}

func TestSSHExternalConfigAndPackageDefaults(t *testing.T) {
	saveSSHGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	sshConfigDir = dir
	jailDir := filepath.Join(dir, "jail.d")
	if err := os.MkdirAll(jailDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sshDropInPath = filepath.Join(jailDir, "99-easy-ha-proxy-sshd.local")
	if err := os.WriteFile(sshDropInPath, []byte(sshConfigText(false, nil, "", nil, nil)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Unmodified Ubuntu defaults-debian.conf accepted only with matching dpkg checksum.
	stock := "[DEFAULT]\nbanaction = nftables\nbanaction_allports = nftables[type=allports]\nbackend = systemd\n\n[sshd]\nenabled = true\n"
	sum := md5.Sum([]byte(stock))
	checksum := hex.EncodeToString(sum[:])
	defaults := filepath.Join(jailDir, "defaults-debian.conf")
	if err := os.WriteFile(defaults, []byte(stock), 0o644); err != nil {
		t.Fatal(err)
	}
	conffiles := " " + defaults + " " + checksum + "\n"
	sshQuickFunc = func(argv ...string) (int, string) { return 0, conffiles }
	ext, err := sshExternalConfig()
	if err != nil || ext {
		t.Fatalf("expected unmodified package defaults accepted, got ext=%v err=%v", ext, err)
	}
	// Local edit detected
	if err := os.WriteFile(defaults, []byte(strings.ReplaceAll(stock, "enabled = true", "enabled = false")), 0o644); err != nil {
		t.Fatal(err)
	}
	ext, err = sshExternalConfig()
	if err != nil || !ext {
		t.Fatalf("expected modified defaults detected as external")
	}
	// Obsolete marker rejected
	if err := os.WriteFile(defaults, []byte(stock), 0o644); err != nil {
		t.Fatal(err)
	}
	sshQuickFunc = func(argv ...string) (int, string) { return 0, strings.TrimRight(conffiles, "\n") + " obsolete\n" }
	if ext, _ := sshExternalConfig(); !ext {
		t.Fatal("expected obsolete conffile rejected")
	}
	// Custom administrator rule in admin.local
	_ = os.Remove(defaults)
	admin := filepath.Join(jailDir, "admin.local")
	if err := os.WriteFile(admin, []byte("[remote-access]\nfilter = sshd[mode=aggressive]\nenabled = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ext, _ := sshExternalConfig(); !ext {
		t.Fatal("expected custom sshd filter in admin.local to be detected as external")
	}
}

func TestSSHTrustedAndCLIMultiTrustedArgs(t *testing.T) {
	got, err := sshTrustedAddresses([]string{"2001:db8::1/64", "2001:db8::/64", "192.0.2.4"})
	if err != nil || !reflect.DeepEqual(got, []string{"2001:db8::/64", "192.0.2.4"}) {
		t.Fatalf("got %#v, err=%v", got, err)
	}
	for _, bad := range []string{"192.0.2.4\nenabled = false", "fe80::1%eth0", "--config", "192.0.2.4/33"} {
		if _, err := sshTrustedAddresses([]string{bad}); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	// Verify nargs='*' CLI parsing for --trusted ip1 ip2 ...
	parsed, err := parseSSHCLIArgs([]string{
		"enable", "--maintenance-lock", "/tmp/x.lock", "--request-id", "abc",
		"--trusted", "192.0.2.1", "2001:db8::/64", "--policy", `{"maxretry":5,"findtime":600,"bantime":3600}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.action != "enable" || !reflect.DeepEqual(parsed.trusted, []string{"192.0.2.1", "2001:db8::/64"}) || !parsed.hasPolicy {
		t.Fatalf("unexpected CLI parse: %+v", parsed)
	}
}

func TestSSHMonitorWithoutFail2banMatchesBrokerShortcut(t *testing.T) {
	saveSSHGlobals(t)
	dir := t.TempDir()
	sshConfigDir = filepath.Join(dir, "fail2ban")
	if err := os.MkdirAll(filepath.Join(sshConfigDir, "jail.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	sshClientPath = filepath.Join(dir, "fail2ban-client")
	sshDropInPath = filepath.Join(sshConfigDir, "jail.d", "99-easy-ha-proxy-sshd.local")
	sshQuickFunc = func(argv ...string) (int, string) {
		t.Fatalf("no command expected when fail2ban absent, got %v", argv)
		return 1, ""
	}
	res := SSHSnapshot(true)
	if res["state"] != "not_installed" || res["managed"] != false {
		t.Fatalf("unexpected snapshot: %#v", res)
	}
	if _, hasErr := res["error"]; hasErr {
		t.Fatalf("unexpected error: %v", res["error"])
	}
}

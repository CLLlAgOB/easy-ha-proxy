package haproxymigrate

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxypkg"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
	"gopkg.in/yaml.v3"
)

var (
	refreshAptFunc = func() (map[string]any, error) {
		return tools.RefreshAptMetadata(tools.AptMetadataState, "/etc/apt", 100*time.Second)
	}
	adminHostRe = regexp.MustCompile(`(?m)^\s+acl host_admin hdr\(host\) -i ([A-Za-z0-9.-]+)\s*$`)
	authHostRe  = regexp.MustCompile(`(?m)^\s+acl host_authelia hdr\(host\) -i ([A-Za-z0-9.-]+)\s*$`)
)

func (e *Engine) quiet() error {
	for _, unit := range []string{"haproxy-state-dump.service", "certbot.service", "snap.certbot.renew.service"} {
		if e.Host.Active(unit) {
			return migErr("A state dump or certificate renewal is running; retry after it completes")
		}
	}
	cj := strVal(e.State["control_journal"])
	if cj == "" {
		cj = e.Paths.ControlState
	}
	if lexists(cj) {
		raw, err := os.ReadFile(cj)
		if err != nil {
			return err
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil {
			return err
		}
		switch strVal(data["state"]) {
		case "prepared", "pending_confirmation", "rolling_back", "rollback_failed":
			return migErr("Resolve the active configuration transaction before migrating")
		}
	}
	return nil
}

func (e *Engine) pause() error {
	for _, svc := range []string{"apt-daily.service", "apt-daily-upgrade.service"} {
		if e.Host.Active(svc) {
			return migErr("A system package maintenance service is running")
		}
	}
	cj, err := e.Host.ControlJournal(e.Paths.ControlState)
	if err != nil {
		return err
	}
	e.State["control_journal"] = cj
	if e.Host.Active("easy-ha-proxy-guardd.service") {
		gdb, err := e.Host.GuardDatabase()
		if err != nil {
			return err
		}
		e.State["guard_database"] = gdb
	}
	if err := e.quiet(); err != nil {
		return err
	}
	var resume []string
	for _, u := range pausedUnits {
		if e.Host.Active(u) {
			resume = append(resume, u)
		}
	}
	e.State["resume_units"] = resume
	if err := e.save("quiescing"); err != nil {
		return err
	}
	for _, u := range resume {
		if err := e.Host.Service("stop", u); err != nil {
			return err
		}
	}
	return e.quiet()
}

func (e *Engine) resume(timers bool) error {
	var units []string
	for _, u := range strSlice(e.State["resume_units"]) {
		if strings.HasSuffix(u, ".timer") == timers {
			units = append(units, u)
		}
	}
	rank := func(u string) int {
		switch u {
		case "haproxy-controld.service":
			return 0
		case "easy-ha-proxy-guardd.service":
			return 2
		default:
			return 1
		}
	}
	sort.SliceStable(units, func(i, j int) bool { return rank(units[i]) < rank(units[j]) })
	for _, u := range units {
		if err := e.Host.Service("start", u); err != nil {
			return err
		}
	}
	for _, u := range units {
		if !e.Host.Active(u) {
			return migErr("A previously active service did not recover: %s", u)
		}
	}
	return nil
}

func (e *Engine) snapshot(source string) error {
	if source == "" {
		source = e.Paths.Socket
	}
	layout := layoutFromState(e.State["layout"])
	counts, err := SnapshotTables(source, filepath.Join(e.Directory, "tables.sqlite"), layout.Tables)
	if err != nil {
		return err
	}
	e.State["table_counts"] = counts
	return e.save("")
}

// CheckGuard verifies persisted guardd bans match the Runtime API snapshot exactly.
func (e *Engine) CheckGuard() error {
	dbPath := strVal(e.State["guard_database"])
	if dbPath == "" {
		return nil
	}
	if !isRegularFile(dbPath) {
		return migErr("The active guard database is missing")
	}
	guard, err := sql.Open("sqlite", readOnlySQLiteURI(dbPath))
	if err != nil {
		return err
	}
	defer guard.Close()
	if _, err := guard.Exec("PRAGMA query_only=ON"); err != nil {
		return err
	}
	snap, err := sql.Open("sqlite", filepath.Join(e.Directory, "tables.sqlite"))
	if err != nil {
		return err
	}
	defer snap.Close()

	cols := map[string]bool{}
	colRows, err := guard.Query("PRAGMA table_info(ip_state)")
	if err != nil {
		return err
	}
	for colRows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			_ = colRows.Close()
			return err
		}
		cols[name] = true
	}
	_ = colRows.Close()

	codeExpr := "40"
	if cols["ban_code"] {
		codeExpr = "COALESCE(NULLIF(ban_code, 0), 40)"
	}
	cutoff := nowFunc().Unix() + 2
	missing := 0

	queries := []struct {
		sql     string
		allowed map[int64]bool
	}{
		{fmt.Sprintf("SELECT ip, %s FROM ip_state WHERE banned_until > ?", codeExpr), map[int64]bool{40: true, 41: true}},
		{"SELECT ip, 50 FROM manual_bans WHERE expires_at > ?", map[int64]bool{50: true}},
	}
	for _, q := range queries {
		rows, err := guard.Query(q.sql, cutoff)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ip string
			var expected int64
			if err := rows.Scan(&ip, &expected); err != nil {
				_ = rows.Close()
				return err
			}
			var gpc int64
			var gpt sql.NullInt64
			err := snap.QueryRow("SELECT gpc0, gpt0 FROM entries WHERE tab=? AND ip=?", "tbl_ban", ip).Scan(&gpc, &gpt)
			if !q.allowed[expected] || err != nil || gpc <= 0 || !gpt.Valid || gpt.Int64 != expected {
				missing++
			}
		}
		_ = rows.Close()
	}
	if missing > 0 {
		return migErr("Persisted guard decisions differ from Runtime API: %d entries; resolve drift first", missing)
	}
	return nil
}

func (e *Engine) checkTables(source string) (map[string]int, error) {
	if source == "" {
		source = e.Paths.Socket
	}
	layout := layoutFromState(e.State["layout"])
	return VerifyTables(source, filepath.Join(e.Directory, "tables.sqlite"), layout.Tables)
}

func (e *Engine) awaitTables(source string) (map[string]int, error) {
	deadline := nowFunc().Add(20 * time.Second)
	var lastErr error
	for nowFunc().Before(deadline) {
		res, err := e.checkTables(source)
		if err == nil {
			return res, nil
		}
		lastErr = err
		sleepFunc(250 * time.Millisecond)
	}
	return nil, migErr("Critical-table handoff did not finish: %v", lastErr)
}

func (e *Engine) dumpServers() error {
	data, err := runtimeCmdFunc(e.Paths.Socket, "show servers state")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(data, "1\n") || !strings.Contains(data, "# be_id") {
		return migErr("The administrative server state could not be saved")
	}
	e.State["server_state"] = data + "\n"
	if err := e.storeServers(); err != nil {
		return err
	}
	return e.save("")
}

func (e *Engine) storeServers() error {
	rec := e.fileRecord(e.Paths.ServerState)
	cfgBytes, err := os.ReadFile(e.Paths.Config)
	if err != nil {
		return migErr("The server state could not be reconciled with the configuration")
	}
	normalized, err := tools.NormalizeServerState(strVal(e.State["server_state"]), string(cfgBytes), true)
	if err != nil {
		return migErr("The server state could not be reconciled with the configuration")
	}
	mode := os.FileMode(0o644)
	uid, gid := 0, 0
	if rec != nil {
		if m := intVal(rec["mode"]); m != 0 {
			mode = os.FileMode(m)
		}
		uid = intVal(rec["uid"])
		gid = intVal(rec["gid"])
	}
	return atomicWrite(e.Paths.ServerState, []byte(normalized), mode, uid, gid)
}

func parseServerStates(text string) (map[[2]string][2]string, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var header []string
	for _, line := range lines {
		if strings.HasPrefix(line, "# be_id") {
			header = strings.Fields(line[2:])
			break
		}
	}
	if len(header) == 0 {
		return nil, migErr("Missing server-state header")
	}
	idxBe, idxSrv, idxAdmin, idxUweight := -1, -1, -1, -1
	for i, h := range header {
		switch h {
		case "be_name":
			idxBe = i
		case "srv_name":
			idxSrv = i
		case "srv_admin_state":
			idxAdmin = i
		case "srv_uweight":
			idxUweight = i
		}
	}
	if idxBe < 0 || idxSrv < 0 || idxAdmin < 0 || idxUweight < 0 {
		return nil, migErr("Incomplete server-state header")
	}
	out := map[[2]string][2]string{}
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") || line == "1" {
			continue
		}
		cols := strings.Fields(line)
		if len(cols) != len(header) {
			return nil, migErr("Incomplete server-state row")
		}
		out[[2]string{cols[idxBe], cols[idxSrv]}] = [2]string{cols[idxAdmin], cols[idxUweight]}
	}
	return out, nil
}

func (e *Engine) checkServers() error {
	cfgBytes, err := os.ReadFile(e.Paths.Config)
	if err != nil {
		return err
	}
	norm, err := tools.NormalizeServerState(strVal(e.State["server_state"]), string(cfgBytes), true)
	if err != nil {
		return err
	}
	expected, err := parseServerStates(norm)
	if err != nil {
		return err
	}
	liveText, err := runtimeCmdFunc(e.Paths.Socket, "show servers state")
	if err != nil {
		return err
	}
	actual, err := parseServerStates(liveText)
	if err != nil {
		return err
	}
	if len(expected) != len(actual) {
		return migErr("Backend administrative state or runtime weights changed")
	}
	for k, v := range expected {
		if actual[k] != v {
			return migErr("Backend administrative state or runtime weights changed")
		}
	}
	return nil
}

func (e *Engine) waitWorker(expectedVersion, previousWorker string) (map[string]string, error) {
	deadline := nowFunc().Add(25 * time.Second)
	for nowFunc().Before(deadline) {
		cur, err := runtimeInfoFunc(e.Paths.Socket)
		if err == nil && cur["Version"] == expectedVersion && cur["Pid"] != "" && cur["Pid"] != previousWorker {
			wd, werr := e.Host.WorkerDigest(cur["Pid"])
			bd, berr := fileDigest(e.Paths.Binary)
			if werr == nil && berr == nil && wd == bd {
				return cur, nil
			}
		}
		sleepFunc(250 * time.Millisecond)
	}
	return nil, migErr("The running worker did not switch to the expected binary")
}

func (e *Engine) reload(expectedVersion string) error {
	if _, err := e.Host.Command([]string{e.Paths.Binary, "-Ws", "-c", "-f", e.Paths.Config}, CmdOpts{Check: true}); err != nil {
		return err
	}
	if err := e.storeServers(); err != nil {
		return err
	}
	prevInfo, err := runtimeInfoFunc(e.Paths.Socket)
	if err != nil {
		return err
	}
	if err := e.Host.Service("reload", "haproxy.service"); err != nil {
		return err
	}
	if _, err := e.waitWorker(expectedVersion, prevInfo["Pid"]); err != nil {
		return err
	}
	if _, err := e.awaitTables(""); err != nil {
		return err
	}
	return e.checkServers()
}

// Health verifies control-plane HTTPS probes and the Runtime API stats contract.
func (e *Engine) Health() error {
	if e.HealthHook != nil {
		return e.HealthHook()
	}
	return e.DefaultHealth()
}

// DefaultHealth runs the standard HTTPS control-plane, auth, and Runtime API checks.
func (e *Engine) DefaultHealth() error {
	raw, err := os.ReadFile(e.Paths.Config)
	if err != nil {
		return err
	}
	text := string(raw)
	adminSet := map[string]bool{}
	for _, m := range adminHostRe.FindAllStringSubmatch(text, -1) {
		adminSet[strings.ToLower(m[1])] = true
	}
	if len(adminSet) != 1 {
		return migErr("No unique administration hostname")
	}
	var admin string
	for h := range adminSet {
		admin = h
	}
	st, err := localProbeFunc(admin, "/api/control-plane-health")
	if err != nil || st != 200 {
		return migErr("The administration control-plane probe failed")
	}
	st2, err := localProbeFunc(admin, "/")
	if err != nil || (st2 != 301 && st2 != 302 && st2 != 303 && st2 != 307 && st2 != 308 && st2 != 401 && st2 != 403) {
		return migErr("Anonymous access to the administration UI changed")
	}
	if authMatch := authHostRe.FindStringSubmatch(text); authMatch != nil {
		ast, aerr := localProbeFunc(authMatch[1], "/api/health")
		if aerr != nil || ast != 200 {
			return migErr("The real authentication service is not healthy")
		}
	}
	statOut, err := runtimeCmdFunc(e.Paths.Socket, "show stat")
	if err != nil {
		return err
	}
	statOut = strings.TrimLeft(statOut, "# ")
	records, err := csv.NewReader(strings.NewReader(statOut)).ReadAll()
	if err != nil || len(records) < 2 {
		return migErr("The Runtime API statistics contract changed")
	}
	pxIdx := -1
	for i, h := range records[0] {
		if h == "pxname" {
			pxIdx = i
			break
		}
	}
	found := false
	if pxIdx >= 0 {
		for _, row := range records[1:] {
			if pxIdx < len(row) && row[pxIdx] == "be_admin" {
				found = true
				break
			}
		}
	}
	if !found {
		return migErr("The Runtime API statistics contract changed")
	}
	return nil
}

func (e *Engine) units() (string, string) {
	id := strVal(e.State["id"])
	if len(id) > 12 {
		id = id[:12]
	}
	suffix := id + "-" + strconv.Itoa(intVal(e.State["generation"]))
	return "easy-ha-proxy-haproxy-seed-" + suffix, "easy-ha-proxy-haproxy-watchdog-" + suffix
}

func (e *Engine) recoveryCommand() (string, string) {
	if digest := strVal(e.State["rollback_engine_digest"]); e.State["operation"] == "rollback" && digest != "" {
		return "rollback-agent", digest
	}
	return "recover-agent", strVal(e.State["engine_digest"])
}

func (e *Engine) arm(operation string) error {
	if operation == "rollback" {
		exe, err := engineBinaryFunc()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		digest := bytesDigest(data)
		if digest != strVal(e.State["engine_digest"]) {
			// Use the same rollback implementation for the watchdog as for
			// the operator, keeping the original migration artifact intact.
			if err := atomicWrite(filepath.Join(e.Directory, "rollback-agent"), data, 0o700, 0, 0); err != nil {
				return err
			}
			e.State["rollback_engine_digest"] = digest
		} else {
			delete(e.State, "rollback_engine_digest")
		}
	}
	e.State["operation"] = operation
	e.State["seed_ready"] = false
	e.State["config_modified"] = false
	e.State["recovery_attempts"] = 0
	e.State["generation"] = intVal(e.State["generation"]) + 1
	if err := e.save("arming"); err != nil {
		return err
	}
	_, watchdog := e.units()
	recoveryBinary, _ := e.recoveryCommand()
	return e.Host.Watchdog(e.Directory, watchdog, recoveryBinary)
}

func (e *Engine) abortDowngrade() error {
	if e.State["config_modified"] == true {
		rec := e.fileRecord(e.Paths.Config)
		if cur, err := fileDigest(e.Paths.Config); err != nil || cur != strVal(rec["digest"]) {
			if err := e.restore(e.Paths.Config); err != nil {
				return err
			}
			if err := e.reload(strVal(e.State["target_runtime_version"])); err != nil {
				return err
			}
		}
	}
	return e.finish("committed")
}

func (e *Engine) bootstrapSeed(expectedVersion string) error {
	layout := layoutFromState(e.State["layout"])
	id := strVal(e.State["id"])
	if len(id) > 12 {
		id = id[:12]
	}
	name := "migration-" + id
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	e.State["seed_port"] = port
	e.State["seed_name"] = name
	seedSock := filepath.Join(e.Directory, "seed.sock")
	if err := atomicWrite(filepath.Join(e.Directory, "seed.cfg"), []byte(SeedConfig(layout, name, port, seedSock)), 0o600, 0, 0); err != nil {
		return err
	}
	if err := e.save("bootstrapping_peer"); err != nil {
		return err
	}
	seed, _ := e.units()
	origCfg, err := e.original(e.Paths.Config)
	if err != nil {
		return err
	}
	candidate, err := AddSeed(string(origCfg), layout, name, port)
	if err != nil {
		return err
	}
	tempCfg := filepath.Join(e.Directory, "with-seed.cfg")
	if err := atomicWrite(tempCfg, []byte(candidate), 0o600, 0, 0); err != nil {
		return err
	}
	if _, err := e.Host.Command([]string{e.Paths.Binary, "-c", "-f", tempCfg}, CmdOpts{Check: true}); err != nil {
		return err
	}
	rec := e.fileRecord(e.Paths.Config)
	e.State["config_modified"] = true
	if err := e.put(e.Paths.Config, []byte(candidate), os.FileMode(intVal(rec["mode"])), intVal(rec["uid"]), intVal(rec["gid"])); err != nil {
		return err
	}
	if err := e.reload(expectedVersion); err != nil {
		return err
	}
	if err := e.Host.StartSeed(e.Directory, seed); err != nil {
		return err
	}
	if _, err := e.awaitTables(seedSock); err != nil {
		return err
	}
	e.State["seed_ready"] = true
	return e.save("peer_ready")
}

func (e *Engine) policyBlock() error {
	if err := e.put(e.Paths.Policy, []byte("#!/bin/sh\n# Temporary HAProxy package migration guard\nexit 101\n"), 0o755, 0, 0); err != nil {
		return err
	}
	e.State["policy_blocked"] = true
	return e.save("")
}

func (e *Engine) repositoryFiles() error {
	if e.Patch {
		return nil
	}
	p := haproxypkg.ReadPlatform(osReleasePath, strVal(e.State["architecture"]))
	if p.Target != e.migrationBranch() {
		return migErr("The prepared migration does not match the host platform")
	}
	repo := p.SourceLine(e.Paths.SigningKey)
	if e.Vendor != "" {
		repo = strings.Replace(repo, p.Repository(), strings.TrimRight(e.Vendor, "/"), 1)
	}
	priorities := haproxypkg.Pin(p.Target)
	if err := e.put(e.Paths.Repository, []byte(repo+"\n"), 0o644, 0, 0); err != nil {
		return err
	}
	if err := e.put(e.Paths.Priorities, []byte(priorities), 0o644, 0, 0); err != nil {
		return err
	}
	keyData, err := os.ReadFile(filepath.Join(e.Directory, "repository.asc"))
	if err != nil {
		return err
	}
	return e.put(e.Paths.SigningKey, keyData, 0o644, 0, 0)
}

func (e *Engine) refreshRepository() {
	if e.Patch {
		return
	}
	_, err := e.Host.Command([]string{
		"/usr/bin/apt-get", "--error-on=any", "update",
		"-o", "Dir::Etc::sourcelist=" + e.Paths.Repository,
		"-o", "Dir::Etc::sourceparts=-",
		"-o", "APT::Get::List-Cleanup=0",
	}, CmdOpts{Check: true, Timeout: 60 * time.Second})
	if err != nil {
		e.State["cleanup_warning"] = "Provider update index needs a refresh: " + err.Error()
	} else {
		e.State["repository_index_refreshed"] = true
	}
	_ = e.save("")
}

func (e *Engine) install(rollback bool) error {
	simRes, err := e.Host.Command(e.packageCommand(true, rollback), CmdOpts{Check: true})
	if err != nil {
		return err
	}
	if _, err := ParseAptPlan(simRes.Stdout, allowedPackages); err != nil {
		return err
	}
	archives := filepath.Join(e.Directory, "archives")
	if err := privateDir(archives); err != nil {
		return err
	}
	var pkgs []PackageRecord
	if rollback {
		oldName := strVal(e.State["old_package"])
		if oldName == "" {
			oldName = "haproxy"
		}
		pkgs = append(pkgs, PackageRecord{Package: oldName, Version: strVal(e.State["old_version"])})
		if oldTLS, ok := pkgRecordOne(e.State["old_tls"]); ok {
			pkgs = append(pkgs, oldTLS)
		}
	} else {
		pkgs = append(pkgRecords(e.State["target_packages"]), pkgRecords(e.State["extra_packages"])...)
	}
	arch := strVal(e.State["architecture"])
	for _, pkg := range pkgs {
		srcName := pkg.Package + ".deb"
		if rollback {
			if pkg.Package == "libssl-awslc" {
				srcName = "tls-old.deb"
			} else {
				srcName = "haproxy-old.deb"
			}
		}
		raw, err := os.ReadFile(filepath.Join(e.Directory, srcName))
		if err != nil {
			return err
		}
		filename := fmt.Sprintf("%s_%s_%s.deb", pkg.Package, pkg.Version, arch)
		if err := atomicWrite(filepath.Join(archives, filename), raw, 0o600, 0, 0); err != nil {
			return err
		}
	}
	before, err := e.Host.Packages()
	if err != nil {
		return err
	}
	e.State["packages_touched"] = true
	if err := e.save(""); err != nil {
		return err
	}
	if _, err := e.Host.Command(e.packageCommand(false, rollback), CmdOpts{
		Check:    true,
		Timeout:  120 * time.Second,
		EnvExtra: map[string]string{"NEEDRESTART_SUSPEND": "1", "NEEDRESTART_MODE": "l"},
	}); err != nil {
		return err
	}
	after, err := e.Host.Packages()
	if err != nil {
		return err
	}
	allNames := map[string]bool{}
	for k := range before {
		allNames[k] = true
	}
	for k := range after {
		allNames[k] = true
	}
	for k := range allNames {
		if before[k] != after[k] && !allowedPackages[k] {
			return migErr("Unexpected package mutation detected")
		}
	}
	if rollback {
		oldName := strVal(e.State["old_package"])
		if oldName == "" {
			oldName = "haproxy"
		}
		if after[oldName] != strVal(e.State["old_version"]) || (!e.Patch && after["haproxy-awslc"] != "") {
			return migErr("The baseline package was not restored")
		}
		if oldTLS, ok := pkgRecordOne(e.State["old_tls"]); ok && after["libssl-awslc"] != oldTLS.Version {
			return migErr("The baseline TLS package was not restored")
		}
		return nil
	}
	targets := pkgRecords(e.State["target_packages"])
	if len(targets) == 0 || after[targets[0].Package] != targets[0].Version {
		return migErr("The target package was not installed")
	}
	for _, pkg := range append(targets, pkgRecords(e.State["extra_packages"])...) {
		if after[pkg.Package] != pkg.Version {
			return migErr("A target dependency version differs from the authenticated preparation")
		}
	}
	return nil
}

func (e *Engine) finish(phase string) error {
	seed, watchdog := e.units()
	if e.State["policy_blocked"] == true {
		if err := e.restore(e.Paths.Policy); err != nil {
			return err
		}
	}
	e.State["policy_blocked"] = false
	if err := e.resume(false); err != nil {
		return err
	}
	if err := e.Health(); err != nil {
		return err
	}
	if err := e.restoreHolds(phase == "rolled_back"); err != nil {
		return err
	}
	if err := e.save(phase); err != nil {
		return err
	}
	resumeErr := e.resume(true)
	stopErr := e.Host.Service("stop", seed+".service")
	if err := errors.Join(resumeErr, stopErr); err != nil {
		e.State["cleanup_warning"] = err.Error()
		_ = e.save("")
	}
	e.Host.CancelWatchdog(watchdog)
	return nil
}

func (e *Engine) oldRuntimeVersion() string {
	if v := strVal(e.State["old_runtime_version"]); v != "" {
		return v
	}
	return strVal(e.State["old_version"])
}

func (e *Engine) masterUsesRemovedConfigDir() bool {
	if _, err := os.Stat(haproxyConfD); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	pid, err := e.Host.MainPID()
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	args := strings.Split(string(raw), "\x00")
	for i := 1; i < len(args); i++ {
		if args[i-1] == "-f" && args[i] == haproxyConfD {
			return true
		}
	}
	return false
}

func (e *Engine) rollbackLocked() error {
	if err := e.save("rolling_back"); err != nil {
		return err
	}
	if e.State["seed_ready"] == true {
		if _, err := e.awaitTables(filepath.Join(e.Directory, "seed.sock")); err != nil {
			return err
		}
	}
	for _, p := range []string{e.Paths.Repository, e.Paths.Priorities, e.Paths.SigningKey} {
		if err := e.restore(p); err != nil {
			return err
		}
	}
	if err := e.policyBlock(); err != nil {
		return err
	}
	curPkgs, err := e.Host.Packages()
	if err != nil {
		return err
	}
	oldName := strVal(e.State["old_package"])
	if oldName == "" {
		oldName = "haproxy"
	}
	curBinDig, binErr := fileDigest(e.Paths.Binary)
	baselineIntact := curPkgs[oldName] == strVal(e.State["old_version"]) &&
		(e.Patch || curPkgs["haproxy-awslc"] == "") &&
		binErr == nil && curBinDig == strVal(e.State["old_binary_digest"])
	if !baselineIntact || e.State["packages_touched"] == true {
		if err := e.install(true); err != nil {
			return err
		}
	}
	if _, err := e.Host.Command([]string{"/usr/bin/systemctl", "daemon-reload"}, CmdOpts{Check: true}); err != nil {
		return err
	}
	if e.State["seed_ready"] == true {
		origCfg, err := e.original(e.Paths.Config)
		if err != nil {
			return err
		}
		cand, err := AddSeed(string(origCfg), layoutFromState(e.State["layout"]), strVal(e.State["seed_name"]), intVal(e.State["seed_port"]))
		if err != nil {
			return err
		}
		rec := e.fileRecord(e.Paths.Config)
		if err := e.put(e.Paths.Config, []byte(cand), os.FileMode(intVal(rec["mode"])), intVal(rec["uid"]), intVal(rec["gid"])); err != nil {
			return err
		}
	} else {
		if err := e.restore(e.Paths.Config); err != nil {
			return err
		}
	}
	if err := e.storeServers(); err != nil {
		return err
	}
	// A master started under the vendor unit can retain "-f conf.d" across
	// reloads. Its package removes that directory during a provider rollback.
	// Start with the restored unit while the seed is still serving the tables.
	if !e.Host.Active("haproxy.service") || (!e.Patch && e.masterUsesRemovedConfigDir()) {
		if _, err := e.Host.Command([]string{e.Paths.Binary, "-Ws", "-c", "-f", e.Paths.Config}, CmdOpts{Check: true}); err != nil {
			return err
		}
		if err := e.Host.Service("restart", "haproxy.service"); err != nil {
			return err
		}
		if _, err := e.waitWorker(e.oldRuntimeVersion(), ""); err != nil {
			return err
		}
	}
	if err := e.reload(e.oldRuntimeVersion()); err != nil {
		return err
	}
	if err := e.restore(e.Paths.Config); err != nil {
		return err
	}
	if err := e.reload(e.oldRuntimeVersion()); err != nil {
		return err
	}
	if err := e.restore(e.Paths.Variables); err != nil {
		return err
	}
	e.State["rollback_verified"] = true
	return e.finish("rolled_back")
}

func updateVarsYAML(original []byte, updates [][2]string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, migErr("Installer variables must be a YAML mapping")
	}
	root := doc.Content[0]
	for _, kv := range updates {
		key, val := kv[0], kv[1]
		updated := false
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				root.Content[i+1].Kind = yaml.ScalarNode
				root.Content[i+1].Tag = "!!str"
				root.Content[i+1].Value = val
				updated = true
				break
			}
		}
		if !updated {
			root.Content = append(root.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
			)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

func (e *Engine) migrationBranch() string {
	if branch := strVal(e.State["target_branch"]); branch != "" {
		return branch
	}
	// Older transactions only targeted Ubuntu 3.4.
	return "3.4"
}

func (e *Engine) migrationVariables(original []byte) ([]byte, error) {
	return updateVarsYAML(original, [][2]string{
		{"haproxy_package_provider", "haproxy-technologies"},
		{"haproxy_package_branch", e.migrationBranch()},
	})
}

func parseVariables(raw []byte) (map[string]any, bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var variables map[string]any
	if decoder.Decode(&variables) != nil || variables == nil {
		return nil, false
	}
	return variables, decoder.Decode(new(yaml.Node)) == io.EOF
}

func (e *Engine) committedVariablesDigest() string {
	if isSymlink(e.Paths.Variables) {
		return ""
	}
	actual, err := os.ReadFile(e.Paths.Variables)
	if err != nil {
		return ""
	}
	digest := strVal(e.State["committed_vars_digest"])
	current := bytesDigest(actual)
	if current == digest {
		return current
	}
	// The installer can serialize the same values differently. Reconstruct
	// the committed document from its verified backup before comparing values.
	original, err := e.original(e.Paths.Variables)
	if err != nil {
		return ""
	}
	expected, err := e.migrationVariables(original)
	if err != nil || bytesDigest(expected) != digest {
		return ""
	}
	want, wantOK := parseVariables(expected)
	got, gotOK := parseVariables(actual)
	if wantOK && gotOK && reflect.DeepEqual(want, got) {
		return current
	}
	return ""
}

func (e *Engine) committedRepositoryFileDigest(path, digest string) string {
	if isSymlink(path) {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	current := bytesDigest(data)
	if current == digest {
		return current
	}
	// Older migrations wrote the same pin without the installer's comments.
	if path != e.Paths.Priorities || e.migrationBranch() != "3.4" {
		return ""
	}
	canonical := haproxypkg.Pin("3.4")
	lines := strings.Split(canonical, "\n")
	legacy := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") {
			legacy = append(legacy, line)
		}
	}
	if current == bytesDigest([]byte(canonical)) && digest == bytesDigest([]byte(strings.Join(legacy, "\n"))) {
		return current
	}
	return ""
}

// Migrate refreshes APT metadata, prepares, and applies a migration under a single lock.
func (e *Engine) Migrate(exerciseRollback bool) (map[string]any, error) {
	var summary map[string]any
	err := e.withLock(func() error {
		meta, err := refreshAptFunc()
		if err != nil || meta["fresh"] != true {
			return migErr("Package metadata refresh failed before the HAProxy transition")
		}
		prepared, err := e.Prepare()
		if err != nil {
			return err
		}
		summary, err = e.Apply(strVal(prepared["id"]), exerciseRollback)
		return err
	})
	return summary, err
}

// Apply executes a prepared transaction with automatic rollback on any failure.
func (e *Engine) Apply(identifier string, exerciseRollback bool) (map[string]any, error) {
	var summary map[string]any
	err := e.withLock(func() error {
		if err := e.load(identifier); err != nil {
			return err
		}
		if strVal(e.State["phase"]) != "prepared" {
			return migErr("Apply requires a freshly prepared transaction")
		}
		if err := e.checkArtifacts(true); err != nil {
			return err
		}
		if err := e.unchangedServiceDropins(); err != nil {
			return err
		}
		for _, p := range []string{
			e.Paths.Config, e.Paths.Variables, e.Paths.Policy,
			e.Paths.Repository, e.Paths.Priorities, e.Paths.SigningKey,
		} {
			if err := e.unchanged(p); err != nil {
				return err
			}
		}
		_, packages, err := e.nativePreflight()
		if err != nil {
			return err
		}
		oldName := strVal(e.State["old_package"])
		if oldName == "" {
			oldName = "haproxy"
		}
		binDig, err := fileDigest(e.Paths.Binary)
		if err != nil || packages[oldName] != strVal(e.State["old_version"]) || binDig != strVal(e.State["old_binary_digest"]) {
			return migErr("The baseline package changed after preparation")
		}
		if eb, ok := e.State["extra_baseline"].(map[string]any); ok {
			for name, ver := range eb {
				want := strVal(ver)
				if packages[name] != want {
					return migErr("A system dependency changed after preparation")
				}
			}
		}
		if packages["libssl-awslc"] != strVal(e.State["tls_baseline"]) {
			return migErr("The TLS dependency changed after preparation")
		}
		if err := e.Health(); err != nil {
			return err
		}
		if e.BeforeChangeHook != nil {
			if err := e.BeforeChangeHook(); err != nil {
				return err
			}
		}
		if err := e.arm("apply"); err != nil {
			return err
		}
		_, watchdog := e.units()
		applyErr := func() error {
			if err := e.pause(); err != nil {
				return err
			}
			if err := e.unchangedServiceDropins(); err != nil {
				return err
			}
			for _, p := range []string{
				e.Paths.Config, e.Paths.Variables, e.Paths.Policy,
				e.Paths.Repository, e.Paths.Priorities, e.Paths.SigningKey,
			} {
				if err := e.unchanged(p); err != nil {
					return err
				}
			}
			if err := e.snapshot(""); err != nil {
				return err
			}
			if err := e.CheckGuard(); err != nil {
				return err
			}
			if err := e.dumpServers(); err != nil {
				return err
			}
			if err := e.bootstrapSeed(e.oldRuntimeVersion()); err != nil {
				return err
			}
			if err := e.policyBlock(); err != nil {
				return err
			}
			if err := e.repositoryFiles(); err != nil {
				return err
			}
			if err := e.save("installing_target"); err != nil {
				return err
			}
			prevPID, err := e.Host.MainPID()
			if err != nil {
				return err
			}
			if err := e.install(false); err != nil {
				return err
			}
			curPID, pidErr := e.Host.MainPID()
			curInfo, infoErr := runtimeInfoFunc(e.Paths.Socket)
			if pidErr != nil || infoErr != nil || curPID != prevPID || curInfo["Version"] != e.oldRuntimeVersion() {
				return migErr("An APT hook unexpectedly restarted the live service")
			}
			if _, err := e.Host.Command([]string{"/usr/bin/systemctl", "daemon-reload"}, CmdOpts{Check: true}); err != nil {
				return err
			}
			if err := e.reload(strVal(e.State["target_runtime_version"])); err != nil {
				return err
			}
			if err := e.Health(); err != nil {
				return err
			}
			e.State["target_verified"] = true
			if err := e.save("target_verified"); err != nil {
				return err
			}
			if exerciseRollback {
				return &RollbackExercise{Msg: "Requested post-switch rollback exercise"}
			}
			if err := e.snapshot(""); err != nil {
				return err
			}
			if _, err := e.awaitTables(filepath.Join(e.Directory, "seed.sock")); err != nil {
				return err
			}
			if err := e.restore(e.Paths.Config); err != nil {
				return err
			}
			if err := e.reload(strVal(e.State["target_runtime_version"])); err != nil {
				return err
			}
			if !e.Patch {
				origVars, err := e.original(e.Paths.Variables)
				if err != nil {
					return err
				}
				updated, err := e.migrationVariables(origVars)
				if err != nil {
					return err
				}
				rec := e.fileRecord(e.Paths.Variables)
				if err := e.put(e.Paths.Variables, updated, os.FileMode(intVal(rec["mode"])), intVal(rec["uid"]), intVal(rec["gid"])); err != nil {
					return err
				}
			}
			varsDig, err := fileDigest(e.Paths.Variables)
			if err != nil {
				return err
			}
			e.State["committed_vars_digest"] = varsDig
			repoDigs := map[string]any{}
			for _, p := range []string{e.Paths.Repository, e.Paths.Priorities, e.Paths.SigningKey} {
				if lexists(p) {
					if d, err := fileDigest(p); err == nil {
						repoDigs[p] = d
					}
				}
			}
			e.State["committed_repository_digests"] = repoDigs
			return e.finish("committed")
		}()
		if applyErr != nil {
			if strVal(e.State["phase"]) == "committed" {
				return migErr("Migration committed; inspect the journal for a post-commit cleanup failure")
			}
			e.State["failure"] = applyErr.Error()
			_ = e.save("")
			rbErr := func() error {
				for _, u := range strSlice(e.State["resume_units"]) {
					if e.Host.Active(u) {
						if err := e.Host.Service("stop", u); err != nil {
							return err
						}
					}
				}
				if _, hasState := e.State["server_state"]; hasState {
					return e.rollbackLocked()
				}
				if e.State["policy_blocked"] == true {
					if err := e.restore(e.Paths.Policy); err != nil {
						return err
					}
				}
				if err := e.resume(false); err != nil {
					return err
				}
				if err := e.resume(true); err != nil {
					return err
				}
				if err := e.save("aborted"); err != nil {
					return err
				}
				e.Host.CancelWatchdog(watchdog)
				return nil
			}()
			if rbErr != nil {
				e.State["rollback_failure"] = rbErr.Error()
				_ = e.save("rollback_failed")
				return migErr("Automatic rollback needs operator recovery; preserve the transaction directory")
			}
			var re *RollbackExercise
			if !errors.As(applyErr, &re) {
				if strVal(e.State["phase"]) == "aborted" {
					return migErr("Migration aborted before the package switch; existing configuration preserved")
				}
				return migErr("Migration failed; the baseline was restored and verified")
			}
		}
		if strVal(e.State["phase"]) == "committed" {
			e.refreshRepository()
		}
		summary = e.Summary()
		return nil
	})
	return summary, err
}

func (e *Engine) committedUnchanged() error {
	packages, err := e.Host.Packages()
	if err != nil {
		return err
	}
	for _, pkg := range pkgRecords(e.State["target_packages"]) {
		if packages[pkg.Package] != pkg.Version {
			return migErr("The installed target packages changed; qualify a fresh downgrade")
		}
	}
	if d, err := fileDigest(e.Paths.Binary); err != nil || d != strVal(e.State["target_binary_digest"]) {
		return migErr("The installed target packages changed; qualify a fresh downgrade")
	}
	cfgRec := e.fileRecord(e.Paths.Config)
	if d, err := fileDigest(e.Paths.Config); err != nil || d != strVal(cfgRec["digest"]) {
		return migErr("Configuration changed since migration; qualify a fresh downgrade")
	}
	varsDigest := e.committedVariablesDigest()
	if varsDigest == "" {
		return migErr("Installer variables changed since migration; qualify a fresh downgrade")
	}
	verified := map[string]string{e.Paths.Variables: varsDigest}
	if repoDigs, ok := e.State["committed_repository_digests"].(map[string]any); ok {
		for p, exp := range repoDigs {
			digest := e.committedRepositoryFileDigest(p, strVal(exp))
			if digest == "" {
				return migErr("Repository configuration changed since migration")
			}
			verified[p] = digest
		}
	}
	if err := e.unchanged(e.Paths.Policy); err != nil {
		return err
	}
	// Authorize only the exact bytes already verified above. Persist them with
	// the rollback journal so the saved watchdog can restore the same files.
	written, _ := e.State["written_files"].(map[string]any)
	if written == nil {
		written = map[string]any{}
		e.State["written_files"] = written
	}
	for path, digest := range verified {
		written[path] = digest
	}
	return nil
}

// Rollback manually rolls back a committed transaction while source files remain unchanged.
func (e *Engine) Rollback(identifier string) (map[string]any, error) {
	var summary map[string]any
	err := e.withLock(func() error {
		if err := e.load(identifier); err != nil {
			return err
		}
		phase := strVal(e.State["phase"])
		if phase == "rolled_back" || phase == "aborted" {
			summary = e.Summary()
			return nil
		}
		if phase != "committed" {
			return migErr("Rollback requires a committed migration; use recover for an interrupted operation")
		}
		if err := e.committedUnchanged(); err != nil {
			return err
		}
		curInfo, err := runtimeInfoFunc(e.Paths.Socket)
		if err != nil || curInfo["Version"] != strVal(e.State["target_runtime_version"]) {
			return migErr("The target was upgraded since this transaction; qualify a fresh downgrade")
		}
		// A later agent can roll back a committed transaction in the supported
		// journal format. The watchdog still uses the verified saved binary.
		if err := e.checkArtifacts(false); err != nil {
			return err
		}
		if err := e.Health(); err != nil {
			return err
		}
		if err := e.arm("rollback"); err != nil {
			return err
		}
		prepErr := func() error {
			if err := e.pause(); err != nil {
				return err
			}
			if err := e.committedUnchanged(); err != nil {
				return err
			}
			if err := e.save(""); err != nil {
				return err
			}
			if err := e.snapshot(""); err != nil {
				return err
			}
			if err := e.CheckGuard(); err != nil {
				return err
			}
			if err := e.dumpServers(); err != nil {
				return err
			}
			return e.bootstrapSeed(strVal(e.State["target_runtime_version"]))
		}()
		if prepErr != nil {
			_ = e.abortDowngrade()
			return prepErr
		}
		if err := e.checkArtifacts(false); err != nil {
			return err
		}
		if err := e.rollbackLocked(); err != nil {
			e.State["rollback_failure"] = err.Error()
			_ = e.save("rollback_failed")
			return err
		}
		summary = e.Summary()
		return nil
	})
	return summary, err
}

// Recover resumes or rolls back an interrupted migration or rollback transaction.
func (e *Engine) Recover(identifier string) (map[string]any, error) {
	var summary map[string]any
	err := e.withLock(func() error {
		if err := e.load(identifier); err != nil {
			return err
		}
		seed, watchdog := e.units()
		phase := strVal(e.State["phase"])
		if phase == "preparing" {
			if err := e.save("aborted"); err != nil {
				return err
			}
			summary = e.Summary()
			return nil
		}
		if phase == "committed" || phase == "rolled_back" || phase == "aborted" || phase == "prepared" {
			if err := e.resume(false); err != nil {
				return err
			}
			if err := e.resume(true); err != nil {
				return err
			}
			_, _ = e.Host.Command([]string{"/usr/bin/systemctl", "stop", seed + ".service"}, CmdOpts{Check: false})
			e.Host.CancelWatchdog(watchdog)
			summary = e.Summary()
			return nil
		}
		attempts := intVal(e.State["recovery_attempts"])
		if attempts >= 3 {
			e.State["operator_recovery_required"] = true
			if err := e.save("recovery_exhausted"); err != nil {
				return err
			}
			summary = e.Summary()
			return nil
		}
		e.State["recovery_attempts"] = attempts + 1
		if err := e.save(""); err != nil {
			return err
		}
		if strVal(e.State["operation"]) == "rollback" && e.State["seed_ready"] != true {
			if err := e.abortDowngrade(); err != nil {
				return err
			}
		} else if _, hasState := e.State["server_state"]; !hasState {
			if e.State["policy_blocked"] == true {
				if err := e.restore(e.Paths.Policy); err != nil {
					return err
				}
			}
			if err := e.resume(false); err != nil {
				return err
			}
			if err := e.resume(true); err != nil {
				return err
			}
			if err := e.save("aborted"); err != nil {
				return err
			}
			e.Host.CancelWatchdog(watchdog)
		} else {
			if err := e.checkArtifacts(true); err != nil {
				return err
			}
			if err := e.rollbackLocked(); err != nil {
				return err
			}
		}
		summary = e.Summary()
		return nil
	})
	return summary, err
}

// Summary returns the public, non-secret summary persisted in last-migration.json / last-update.json.
func (e *Engine) Summary() map[string]any {
	keys := []string{
		"id", "kind", "phase", "architecture", "created_at", "engine_digest",
		"old_version", "old_runtime_version", "target_runtime_version", "target_packages",
		"extra_packages", "failure", "rollback_verified", "target_verified", "table_counts",
		"cleanup_warning", "updated_at",
	}
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		out[k] = e.State[k]
	}
	return out
}

package stages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// A Redis that cannot read its session dump does not take the sign-in page
// down. Redis keeps only Authelia's sessions, and Redis 8 reads what 7.4
// wrote but 7.4 refuses what 8 wrote ("Can't handle RDB format version") and
// exits. Before the stack is recreated, the Redis image about to run checks
// the dump with redis-check-rdb; a dump it cannot read is set aside -- after
// the running Redis has stopped, because Redis writes the dump again on the
// way down.
//
// The guard runs for real here, against a docker stand-in that answers the
// check with the exit code a case needs and records what it was asked.

const guardImage = "redis:8.10.3-alpine"

type guardRun struct {
	data   string
	calls  []string // "dump-present|dump-absent docker args..."
	result []engine.Result
}

func runRedisGuard(t *testing.T, checkCode int, withDump bool) guardRun {
	t.Helper()
	data := filepath.Join(t.TempDir(), "redis")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(data, "dump.rdb")
	if withDump {
		if err := os.WriteFile(dump, []byte("REDIS0015 sessions"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	part := Part{Name: "authelia/start", Role: "authelia", File: "start"}
	set := mustSetWith(t, repoRoot(t), part, map[string]any{
		"authelia_redis_image": guardImage, "authelia_redis_data_dir": data,
		"authelia_redis_uid": 19011, "authelia_redis_gid": 19011,
	})
	run := guardRun{data: data}
	host := engine.Host()
	sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
		if name != "docker" {
			return host.Exec(name, args...) // mv
		}
		present := "dump-absent"
		if _, err := os.Stat(dump); err == nil {
			present = "dump-present"
		}
		run.calls = append(run.calls, present+" "+strings.Join(args, " "))
		if args[0] == "run" {
			return "", checkCode, nil
		}
		return "", 0, nil
	}}
	b := &Builder{Set: set, Sys: sys}
	steps := autheliaRedisGuard(b, true)
	if b.err != nil {
		t.Fatal(b.err)
	}
	r := engine.NewRun(engine.Apply, sys, nil)
	if err := r.Do("authelia/start", steps); err != nil {
		t.Fatal(err)
	}
	run.result = r.Results
	return run
}

func verbs(calls []string) []string {
	var out []string
	for _, call := range calls {
		out = append(out, strings.Fields(call)[1])
	}
	return out
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range list {
		names = append(names, entry.Name())
	}
	return names
}

func TestRedisGuardLeavesAReadableDumpAndARunningRedis(t *testing.T) {
	run := runRedisGuard(t, 0, true)
	if got := verbs(run.calls); strings.Join(got, ",") != "run" {
		t.Fatalf("docker calls %q", run.calls)
	}
	if got := entries(t, run.data); strings.Join(got, ",") != "dump.rdb" {
		t.Fatalf("data dir %q", got)
	}
}

func TestRedisGuardChecksWithTheTargetImageOnAReadOnlyCopy(t *testing.T) {
	check := runRedisGuard(t, 0, true).calls[0]
	for _, part := range []string{"--pull never", "--network none", "--read-only", "--cap-drop ALL",
		"--user 19011:19011", "/redis:/data:ro", "--entrypoint redis-check-rdb", guardImage + " /data/dump.rdb"} {
		if !strings.Contains(check, part) {
			t.Errorf("the check %q lacks %q", check, part)
		}
	}
}

func TestRedisGuardSetsAnUnreadableDumpAsideAfterRedisStopped(t *testing.T) {
	run := runRedisGuard(t, 1, true)
	if got := verbs(run.calls); strings.Join(got, ",") != "run,stop" {
		t.Fatalf("docker calls %q", run.calls)
	}
	// Still in place when Redis was stopped: moved only afterwards, so the
	// dump the old Redis writes on its way down is the one set aside.
	if !strings.HasPrefix(run.calls[1], "dump-present stop authelia-redis") {
		t.Fatalf("stop came after the move: %q", run.calls[1])
	}
	names := entries(t, run.data)
	if len(names) != 1 || !strings.HasPrefix(names[0], "dump.rdb.unreadable-") {
		t.Fatalf("data dir %q", names)
	}
	if raw, _ := os.ReadFile(filepath.Join(run.data, names[0])); string(raw) != "REDIS0015 sessions" {
		t.Fatalf("set-aside dump holds %q", raw)
	}
	said := false
	for _, res := range run.result {
		said = said || strings.Contains(res.Summary, "Signed-in users have to sign in again")
	}
	if !said {
		t.Fatalf("nobody was told why: %+v", run.result)
	}
}

func TestRedisGuardTakesADockerFailureForNoVerdictOnTheDump(t *testing.T) {
	for _, code := range []int{125, 126, 127} {
		run := runRedisGuard(t, code, true)
		if got := verbs(run.calls); strings.Join(got, ",") != "run" {
			t.Errorf("rc %d: docker calls %q", code, run.calls)
		}
		if got := entries(t, run.data); strings.Join(got, ",") != "dump.rdb" {
			t.Errorf("rc %d: data dir %q", code, got)
		}
	}
}

func TestRedisGuardWithoutADumpChecksNothing(t *testing.T) {
	if run := runRedisGuard(t, 1, false); len(run.calls) != 0 {
		t.Fatalf("docker calls %q", run.calls)
	}
}

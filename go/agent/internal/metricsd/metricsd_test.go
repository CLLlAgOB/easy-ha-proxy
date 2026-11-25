package metricsd

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func TestDatabaseRoundTrip(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fe, _ := db.ObjectID("frontend", "fe", "", 100)
	be, _ := db.ObjectID("backend", "be_app", "", 100)
	rows := map[int64]map[string]int64{
		fe: {"samples": 6, "requests": 120, "conn_cur_avg": 4, "conn_cur_max": 9},
		be: {"samples": 6, "requests": 60, "response_ms_avg": 30, "response_ms_max": 80},
	}
	if err := db.writeBuckets(600, rows, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.writeBuckets(600, rows, true, nil); err != nil {
		t.Fatal(err)
	}
	s, err := db.series("requests", "", 0, 3600, true)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := pyyaml.JSONDumps(s, false, false)
	if !strings.Contains(out, `"points": [600], "series": {"requests": [240]}`) {
		t.Fatalf("series: %s", out)
	}
	lat, _ := db.series("latency", "be_app", 0, 3600, true)
	out, _ = pyyaml.JSONDumps(lat, false, false)
	if !strings.Contains(out, `"response_ms_avg": [30], "response_ms_max": [80]`) {
		t.Fatalf("latency: %s", out)
	}
	if n, _ := db.rollupHours(3600); n != 2 {
		t.Fatalf("rollup wrote %d", n)
	}
}

func TestHelpers(t *testing.T) {
	if v, ok := histogramPercentile([]int64{0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0.5); !ok || v != 8 {
		t.Fatalf("p50 %d", v)
	}
	if n, ok := parseSize("5GiB", 0, false); !ok || n != 5*gib {
		t.Fatal("parse size")
	}
	if _, ok := parseSize("auto", 0, false); ok {
		t.Fatal("auto is runtime")
	}
	if table, step := chooseResolution(30 * 86400); table != "metric_1h" || step != 3600 {
		t.Fatalf("%s %d", table, step)
	}
	if fromStorage("cpu", int64(125)) != 12.5 || fromStorage("temperature", int64(0)) != nil {
		t.Fatal("from storage")
	}
	if componentName("easy-ha-proxy-updated-job-abc123") != "easy-ha-proxy-updated" {
		t.Fatal("component name")
	}
}

func TestConcurrentMonitorUpdates(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := NewCollector(Config{}, db, nil)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, key := range []string{"disk", "network"} {
		wg.Go(func() {
			<-start
			for range 8 {
				if _, err := c.setMonitors(map[string]bool{key: false}); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()
	if c.monitors["disk"] || c.monitors["network"] || db.getState(monitorsKey, "") != monitorsJSON(c.monitors) {
		t.Fatal("monitor changes were lost")
	}
}

func TestUnavailableMetricStorage(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := db.stats(); err == nil {
		t.Fatal("expected database read to fail")
	}
	c := NewCollector(Config{}, db, nil)
	if _, err := c.machineBucket(hostKind, "", "", 1); err == nil {
		t.Fatal("expected object creation to fail")
	}
}

func TestIncompleteCgroupMemoryStat(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{"memory.current": "1024", "memory.stat": "inactive_file "} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, memory := readCgroup(dir); memory != nil {
		t.Fatalf("unexpected incomplete reading: %d", *memory)
	}
}

package metricsd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyyaml"
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

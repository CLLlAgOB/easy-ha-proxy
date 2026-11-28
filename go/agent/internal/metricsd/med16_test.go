package metricsd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

type blockingAlertSink struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (s *blockingAlertSink) Enabled() bool { return true }

func (s *blockingAlertSink) Observe(_ context.Context, _ alerts.Observation) bool {
	s.calls.Add(1)
	if s.started != nil {
		select {
		case <-s.started:
		default:
			close(s.started)
		}
	}
	if s.release != nil {
		<-s.release
	}
	return true
}

func TestFlushDoesNotHoldCollectorLockDuringSlowAlertd(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDatabase(filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sink := &blockingAlertSink{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	cfg := Config{
		PollIntervalSeconds:    10,
		AlertMinRequests:       1,
		AlertErrorRatioPercent: 50,
	}
	c := NewCollector(cfg, db, sink)

	id, err := db.ObjectID("backend", "be_site", "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.objectIDs[objectKey{"backend", "be_site", ""}] = id
	c.hasBucket = true
	c.bucketTS = 1000
	b := newBucket()
	b.Samples = 1
	b.addCounter("requests", 10)
	b.addCounter("resp_5xx", 8)
	c.buckets[id] = b
	c.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := c.flush(true)
		done <- err
	}()

	select {
	case <-sink.started:
	case <-time.After(3 * time.Second):
		t.Fatal("alert sink did not receive traffic observation")
	}

	// While alertd is blocked, reading Collector.health() must succeed immediately.
	healthDone := make(chan *OMap, 1)
	go func() {
		healthDone <- c.health()
	}()
	select {
	case h := <-healthDone:
		if h == nil {
			t.Fatal("expected non-nil health map")
		}
	case <-time.After(500 * time.Millisecond):
		close(sink.release)
		t.Fatal("Collector.health() was blocked while alertd delivery was slow")
	}

	close(sink.release)
	if err := <-done; err != nil {
		t.Fatalf("flush failed: %v", err)
	}
	if got := sink.calls.Load(); got != 1 {
		t.Fatalf("expected 1 alert observation, got %d", got)
	}
}

func TestFlushRetryDoesNotDuplicateTrafficAlert(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDatabase(filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	sink := &blockingAlertSink{}
	cfg := Config{
		PollIntervalSeconds:    10,
		AlertMinRequests:       1,
		AlertErrorRatioPercent: 50,
	}
	c := NewCollector(cfg, db, sink)
	id, err := db.ObjectID("backend", "be_retry", "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.objectIDs[objectKey{"backend", "be_retry", ""}] = id
	c.hasBucket = true
	c.bucketTS = 1000
	b := newBucket()
	b.Samples = 1
	b.addCounter("requests", 10)
	b.addCounter("resp_5xx", 9)
	c.buckets[id] = b
	c.mu.Unlock()

	// Close DB so writeBuckets fails while bucket stays queued for retry.
	db.Close()
	if _, err := c.flush(true); err == nil {
		t.Fatal("expected flush to fail on closed DB")
	}
	// Retry flush: must NOT send a duplicate alert for the same bucket.
	if _, err := c.flush(true); err == nil {
		t.Fatal("expected second flush to fail on closed DB")
	}
	if got := sink.calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 alert delivery across retries, got %d", got)
	}
}

func TestSitesAPIReturns500OnDatabaseFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDatabase(filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(Config{PollIntervalSeconds: 10}, db, nil)
	srv := &Server{Collector: c, DB: db}

	// Empty DB returns 200 with empty sites array.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/sites", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200 on healthy empty DB, got %d: %s", rec.Code, rec.Body.String())
	}

	// Closed DB must return 500 rather than silently returning 200 [].
	db.Close()
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/sites", nil))
	if rec2.Code != 500 {
		t.Fatalf("expected 500 on failed DB, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// Endpoints using s.site(query) must also fail with 500 when DB fails.
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary?site=be_web", nil))
	if rec3.Code != 500 {
		t.Fatalf("expected 500 on summary with failed DB, got %d: %s", rec3.Code, rec3.Body.String())
	}
}

package healthd

import (
	"testing"
	"time"
)

// A panic while collecting is recovered by net/http for that one request; the
// collection lock must not stay held, or every later status request hangs.
func TestForceRefreshReleasesLockAfterPanic(t *testing.T) {
	ok := fakeRunner(t)
	panicking := true
	st := NewState(testConfig(t), DefaultHealthUnit, func(timeout time.Duration, argv ...string) (int, string, string) {
		if panicking {
			panic("collector bug")
		}
		return ok(timeout, argv...)
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the collector did not panic")
			}
		}()
		st.ForceRefresh()
	}()

	panicking = false
	done := make(chan map[string]any, 1)
	go func() { done <- st.ForceRefresh() }()
	select {
	case snap := <-done:
		units, _ := snap["systemd"].(map[string]any)["units"].(map[string]any)
		if len(units) == 0 {
			t.Fatalf("no units after recovery: %v", snap)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ForceRefresh still blocked on the collection lock after a panic")
	}
}

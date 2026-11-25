package updated

import (
	"sync"
	"testing"
	"time"
)

// A request that found the Linux settings being read returned the cached
// answer without a lock while the reader replaced it; -race catches that.
func TestLinuxSettingsCacheIsReadUnderItsLock(t *testing.T) {
	d := newTestDaemon(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := d.osSecurityLiveSettings(); got == nil {
					t.Error("no answer")
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// What the OS security worker does when it finishes.
				d.inspectMu.Lock()
				d.inspectCacheMu.Lock()
				d.inspectAt, d.inspectValue = time.Time{}, nil
				d.inspectCacheMu.Unlock()
				d.inspectMu.Unlock()
			}
		}()
	}
	wg.Wait()
}

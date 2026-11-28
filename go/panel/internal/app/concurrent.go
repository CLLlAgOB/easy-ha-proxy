package app

import "sync"

// concurrently runs independent reads at the same time and returns once all
// have finished: a page that waits on a daemon and a log file need not wait
// for them one after the other. Each function writes only its own results.
// A panic in any of them is raised again here, in the request's goroutine,
// where the handler's recovery turns it into the same 500 page Flask gives.
func concurrently(fns ...func()) {
	var wg sync.WaitGroup
	panics := make([]any, len(fns))
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { panics[i] = recover() }()
			fn()
		}()
	}
	wg.Wait()
	for _, p := range panics {
		if p != nil {
			panic(p)
		}
	}
}

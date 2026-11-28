package app

import (
	"testing"
	"time"
)

func TestConcurrentlyRunsTogetherAndReraisesPanics(t *testing.T) {
	start := time.Now()
	var a, b int
	concurrently(func() { time.Sleep(150 * time.Millisecond); a = 1 },
		func() { time.Sleep(150 * time.Millisecond); b = 2 })
	if a != 1 || b != 2 {
		t.Fatalf("results lost: %d %d", a, b)
	}
	if took := time.Since(start); took > 280*time.Millisecond {
		t.Fatalf("ran one after the other: %v", took)
	}

	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("panic not raised in the caller: %v", r)
		}
	}()
	concurrently(func() {}, func() { panic("boom") })
	t.Fatal("unreachable")
}

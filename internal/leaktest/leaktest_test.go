// SPDX-License-Identifier: MIT

package leaktest

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// recorder is a testing.TB that keeps its cleanups and errors.
type recorder struct {
	testing.TB
	cleanups []func()
	errors   []string
}

func (r *recorder) Helper()          {}
func (r *recorder) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }
func (r *recorder) Errorf(format string, a ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, a...))
}

func (r *recorder) finish() {
	for _, v := range slices.Backward(r.cleanups) {
		v()
	}
}

func shortWait(t *testing.T) {
	old := Wait
	Wait = 200 * time.Millisecond
	t.Cleanup(func() { Wait = old })
}

func TestNoLeak(t *testing.T) {
	shortWait(t)
	r := &recorder{TB: t}
	Check(r)
	done := make(chan struct{})
	go func() { <-done }()
	close(done) // the goroutine ends within Wait
	r.finish()
	if len(r.errors) != 0 {
		t.Fatalf("errors without a leak: %v", r.errors)
	}
}

func TestGoroutineLeak(t *testing.T) {
	shortWait(t)
	r := &recorder{TB: t}
	Check(r)
	stop := make(chan struct{})
	defer close(stop)
	go func() { <-stop }()
	r.finish()
	if len(r.errors) != 1 || !strings.Contains(r.errors[0], "goroutines after the test") {
		t.Fatalf("errors %q, want the leaked goroutine", r.errors)
	}
}

func TestFDLeak(t *testing.T) {
	if _, ok := openFDs(); !ok {
		t.Skipf("no file descriptor count on %s", runtime.GOOS)
	}
	shortWait(t)
	r := &recorder{TB: t}
	Check(r)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r.finish()
	if len(r.errors) != 1 || !strings.Contains(r.errors[0], "file descriptors after the test") {
		t.Fatalf("errors %q, want the open file", r.errors)
	}
}

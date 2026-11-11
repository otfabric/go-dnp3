// SPDX-License-Identifier: MIT

// Package leaktest checks that a test leaves no goroutines and, on Linux
// and macOS, no open file descriptors behind it. It is test
// infrastructure: no package of the library imports it outside its tests.
package leaktest

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// Wait is how long the check waits for the goroutines and descriptors of
// a test to end after its cleanups have run.
var Wait = 5 * time.Second

// Check records the goroutines and open file descriptors now and
// registers a cleanup that fails t when, within Wait, their numbers do
// not return to what they were. Call it first in the test: cleanups run
// in the reverse order of their registration, so this one runs after the
// test's deferred calls and the cleanups registered after it, Close
// included. It must not be used in a parallel test, whose goroutines are
// counted with the others'.
func Check(t testing.TB) {
	t.Helper()
	warmUp()
	goroutines := runtime.NumGoroutine()
	fds, countFDs := openFDs()
	t.Cleanup(func() {
		deadline := time.Now().Add(Wait)
		for {
			g := runtime.NumGoroutine()
			f, _ := openFDs()
			if g <= goroutines && (!countFDs || f <= fds) {
				return
			}
			if time.Now().After(deadline) {
				if g > goroutines {
					buf := make([]byte, 1<<20)
					t.Errorf("leaktest: %d goroutines after the test, %d before:\n%s", g, goroutines, buf[:runtime.Stack(buf, true)])
				}
				if countFDs && f > fds {
					t.Errorf("leaktest: %d open file descriptors after the test, %d before", f, fds)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// warmUp opens and closes a listener, so that the descriptors the network
// poller keeps once it has started are open before the count.
func warmUp() {
	if l, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = l.Close()
	}
}

// openFDs returns the number of open file descriptors of the process and
// whether it could count them: on Linux and macOS, from /dev/fd. Other
// systems are not checked.
func openFDs() (int, bool) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return 0, false
	}
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}

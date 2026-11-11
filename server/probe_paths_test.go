// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Tests of the paths of the clause 13.2.3.3 probe that depend on the
// order in which an association's goroutine sees what happened: the tests
// hold that goroutine still while the connections change, so that every
// event is queued, in a known order, before it runs. Also the dual end
// point's wait and the master IP address checks of a Group. Page numbers
// are printed pages.

// onAssoc runs f on the goroutine of a and returns its result.
func onAssoc[T any](t *testing.T, a *association, f func() T) T {
	t.Helper()
	c := make(chan T, 1)
	a.post(func() { c <- f() })
	select {
	case v := <-c:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("the association did not run the function")
		var zero T
		return zero
	}
}

// blockAssoc holds the goroutine of a until the returned function is
// called (at the latest when the test ends): what reaches the association
// meanwhile waits in its queue, in the order it came.
func blockAssoc(t *testing.T, a *association) func() {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	a.post(func() {
		close(entered)
		<-release
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the association did not run the function")
	}
	var once sync.Once
	done := func() { once.Do(func() { close(release) }) }
	t.Cleanup(done)
	return done
}

// waitQueued waits until at least n functions wait in the queue of a.
func waitQueued(t *testing.T, a *association, n int) {
	t.Helper()
	eventually(t, fmt.Sprintf("%d functions queued", n), func() bool { return len(a.fn) >= n })
}

// answerProbe answers the outstation's keep-alive on the connection of m.
func (m *rawMaster) answerProbe() {
	m.t.Helper()
	m.write(link.Frame{Dir: true, Function: link.SecondaryLinkStatus, Dest: 10, Src: 1})
}

// probed reads the next frame, the outstation's keep-alive.
func (m *rawMaster) probed() {
	m.t.Helper()
	if f := m.next(); f.Function != link.PrimaryRequestLinkStatus || f.Src != 10 || f.Dest != 1 || f.Dir {
		m.t.Fatalf("got %s, want the keep-alive", f.String())
	}
}

// goroutines returns the stack of every goroutine.
func goroutines() []string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Split(string(buf[:n]), "\n\n")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// waitsIn reports whether a goroutine waits in state (such as "select")
// in fn, its innermost function outside the runtime.
func waitsIn(state, fn string) bool {
	for _, g := range goroutines() {
		lines := strings.Split(g, "\n")
		if len(lines) < 2 || !strings.Contains(lines[0], "["+state) {
			continue
		}
		for _, l := range lines[1:] {
			if strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "runtime.") {
				continue
			}
			if strings.Contains(l, fn) {
				return true
			}
			break
		}
	}
	return false
}

// runs reports whether a goroutine has fn on its stack.
func runs(fn string) bool {
	for _, g := range goroutines() {
		if strings.Contains(g, fn) {
			return true
		}
	}
	return false
}

// TestDialAndServeEndsWhileWaiting: DialAndServe, waiting while a master
// is connected to the listener (the master's connection has priority,
// clause 13.2.3.1.3, p. 379), returns ctx.Err() when ctx ends and nil when
// the server is closed.
func TestDialAndServeEndsWhileWaiting(t *testing.T) {
	start := func(t *testing.T) (*Server, context.CancelFunc, chan error) {
		t.Helper()
		s := newServer(t)
		m := dialLinkMaster(t, serveTCP(t, s))
		m.send(readIIN(1))
		m.recvFunc(app.FuncResponse)
		eventually(t, "the master's connection", s.streamConnected)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		done := make(chan error, 1)
		go func() { done <- s.DialAndServe(ctx, "127.0.0.1:1", Redial{MinDelay: time.Hour}) }()
		eventually(t, "DialAndServe waiting", func() bool { return waitsIn("select", "(*Server).DialAndServe(") })
		return s, cancel, done
	}
	result := func(t *testing.T, done chan error) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(3 * time.Second):
			t.Fatal("DialAndServe did not return")
			return nil
		}
	}
	t.Run("context", func(t *testing.T) {
		_, cancel, done := start(t)
		cancel()
		if err := result(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("DialAndServe: %v", err)
		}
	})
	t.Run("close", func(t *testing.T) {
		s, _, done := start(t)
		_ = s.Close()
		if err := result(t, done); err != nil {
			t.Fatalf("DialAndServe after Close: %v", err)
		}
	})
}

// TestMasterIPsNonIPAddress: an address without an IP address, as a Unix
// socket's or none, lies in no prefix: with WithMasterIPs it is refused,
// without it every address is taken.
func TestMasterIPsNonIPAddress(t *testing.T) {
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	restricted, open := &options{masterIPs: all}, &options{}
	for _, a := range []net.Addr{nil, &net.UnixAddr{Name: "/run/dnp3.sock", Net: "unix"}} {
		if ip, ok := ipOf(a); ok {
			t.Errorf("ipOf(%v) = %v", a, ip)
		}
		if inPrefixes(all, a) || restricted.masterIPAllowed(a) {
			t.Errorf("%v taken with WithMasterIPs", a)
		}
		if !open.masterIPAllowed(a) {
			t.Errorf("%v refused without WithMasterIPs", a)
		}
	}
	for _, a := range []net.Addr{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1")}} {
		if !inPrefixes(all, a) {
			t.Errorf("%v in no prefix", a)
		}
	}
}

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

// TestSpec13_2_3_3_ThirdConnectionDuringProbe checks clause 13.2.3.3 (p.
// 382) and its NOTE 2: while the keep-alive probes the master's current
// connection for a second connection, a third one of the master is
// rejected at once, without waiting for the probe; the answered probe
// rejects the second one, and the current connection keeps serving.
func TestSpec13_2_3_3_ThirdConnectionDuringProbe(t *testing.T) {
	addr := serveTCP(t, newServer(t, WithMasters(1), WithLink(Link{Timeout: 30 * time.Second})))
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	if f := old.response(10); f.Control.Seq != 1 {
		t.Fatalf("response %s", f)
	}
	second := dialRaw(t, "tcp", addr)
	old.probed() // unanswered for now: the probe runs
	third := dialRaw(t, "tcp", addr)
	if fs := third.closed(); len(fs) != 0 {
		t.Fatalf("frames to the third connection: %v", fs)
	}
	old.answerProbe()
	if fs := second.closed(); len(fs) != 0 {
		t.Fatalf("frames to the second connection: %v", fs)
	}
	old.request(10, readIIN(2))
	if f := old.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpec13_2_3_3_HeldRequestsBounded: the requests a new connection of
// the master sends while the current one is probed (clause 13.2.3.3 NOTE
// 2, p. 382) are held, at most maxHeld of them; once the probe fails and
// the new connection is taken (Table 13-2 row 4, p. 383), the held ones are
// answered in the order they came, and those beyond the bound are lost, as
// on the line.
func TestSpec13_2_3_3_HeldRequestsBounded(t *testing.T) {
	s := newServer(t, WithMasters(1), WithLink(Link{Timeout: 30 * time.Second}))
	addr := serveTCP(t, s)
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	old.response(10)
	second := dialRaw(t, "tcp", addr)
	old.probed()
	a := s.association(1)
	release := blockAssoc(t, a)
	for i := range maxHeld + 2 {
		second.request(10, readIIN(uint8(i)))
	}
	waitQueued(t, a, maxHeld+2)
	// The current connection goes: the probe fails after the requests.
	_ = old.conn.Close()
	waitQueued(t, a, maxHeld+3)
	release()
	for i := range maxHeld {
		if f := second.response(10); f.Control.Seq != uint8(i) {
			t.Fatalf("held request %d: response %s", i, f)
		}
	}
	second.request(10, readIIN(12))
	if f := second.response(10); f.Control.Seq != 12 {
		t.Fatalf("response %s: a request beyond the %d held was answered", f, maxHeld)
	}
}

// TestSpec13_2_3_3_CurrentConnectionGoneDuringProbe: when the master's
// current connection goes while it is probed for a new connection (clause
// 13.2.3.3 NOTE 2, p. 382), and another connection of the master took its
// place before the probe's result was handled, the new connection is
// measured against that one: it is probed in turn and, the probe answered,
// the new connection is rejected.
func TestSpec13_2_3_3_CurrentConnectionGoneDuringProbe(t *testing.T) {
	s := newServer(t, WithMasters(1), WithLink(Link{Timeout: 30 * time.Second}))
	addr := serveTCP(t, s)
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	old.response(10)
	second := dialRaw(t, "tcp", addr)
	old.probed()
	a := s.association(1)
	release := blockAssoc(t, a)
	third := dialRaw(t, "tcp", addr)
	waitQueued(t, a, 1) // the third connection, queued before the probe's result
	_ = old.conn.Close()
	waitQueued(t, a, 2)
	release()
	// The third connection took the gone one's place, and is probed for
	// the second, whose probe ended without deciding.
	third.probed()
	third.answerProbe()
	if fs := second.closed(); len(fs) != 0 {
		t.Fatalf("frames to the second connection: %v", fs)
	}
	third.request(10, readIIN(2))
	if f := third.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpec13_2_3_3_ConnectionGoneBeforeTaken: a connection of the master
// that is already closed when the association comes to take it is not
// taken: the current connection keeps serving, and is not probed (clause
// 13.2.3.3 NOTE 2, p. 382, probes for a new connection that stands).
func TestSpec13_2_3_3_ConnectionGoneBeforeTaken(t *testing.T) {
	s := newServer(t, WithMasters(1))
	addr := serveTCP(t, s)
	m := dialRaw(t, "tcp", addr)
	m.request(10, readIIN(1))
	m.response(10)
	a := s.association(1)
	release := blockAssoc(t, a)
	late := dialRaw(t, "tcp", addr)
	waitQueued(t, a, 1)
	_ = late.conn.Close()
	eventually(t, "the late connection closed", func() bool { return s.connections() == 1 })
	release()
	if onAssoc(t, a, func() bool { return a.probing }) {
		t.Fatal("the current connection is probed for a closed one")
	}
	m.request(10, readIIN(2))
	if f := m.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpecTable13_1_DatagramTakesOverFromGoneConnection checks clause
// 13.2.3.3 (p. 382) with Table 13-1 (p. 381) for a master that speaks over
// TCP and UDP: its datagram is not taken while its TCP connection stands
// (the probe of the connection is answered, and the request it carried is
// dropped); once the connection is gone, its next datagram takes the
// association and is answered.
func TestSpecTable13_1_DatagramTakesOverFromGoneConnection(t *testing.T) {
	s := newServer(t)
	tcpAddr := serveTCP(t, s)
	udpAddr, _ := serveUDP(t, s)
	tcp := dialRaw(t, "tcp", tcpAddr)
	tcp.request(10, readIIN(1))
	tcp.response(10)
	a := s.association(1)
	udp := dialRaw(t, "udp", udpAddr)
	udp.request(10, readIIN(2))
	tcp.probed()
	tcp.answerProbe()
	eventually(t, "the probe decided", func() bool { return !onAssoc(t, a, func() bool { return a.probing }) })
	_ = tcp.conn.Close()
	eventually(t, "the TCP connection gone", func() bool { return onAssoc(t, a, func() bool { return a.sess == nil }) })
	udp.request(10, readIIN(3))
	if f := udp.response(10); f.Control.Seq != 3 {
		t.Fatalf("response %s, want the one to the datagram after the connection went", f)
	}
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

// TestSpec13_2_3_1_4_MasterIPsGroup checks clause 13.2.3.1.4 a (p. 379,
// should: validate connection requests from masters by IP address) for a
// Group: a connection is taken only from an address every outstation of
// the group allows; one that any of them refuses is closed without an
// answer.
func TestSpec13_2_3_1_4_MasterIPsGroup(t *testing.T) {
	lp := netip.MustParsePrefix
	serve := func(t *testing.T, servers ...*Server) string {
		t.Helper()
		g, err := NewGroup(servers...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = g.Close() })
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = g.Serve(l) }()
		return l.Addr().String()
	}
	denied := dialRaw(t, "tcp", serve(t, newServer(t, WithAddress(10)), newServer(t, WithAddress(11), WithMasterIPs(lp("192.0.2.0/24")))))
	if fs := denied.closed(); len(fs) != 0 {
		t.Fatalf("frames to a refused master: %v", fs)
	}
	allowed := dialRaw(t, "tcp", serve(t, newServer(t, WithAddress(10)), newServer(t, WithAddress(11), WithMasterIPs(lp("127.0.0.0/8")))))
	for _, o := range []link.Address{10, 11} {
		allowed.write(rls(o))
		allowed.linkStatus(o)
	}
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

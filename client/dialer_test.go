// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
)

// errRefusedByPolicy stands for the sentinel of an address allowlist in a
// caller's dialer.
var errRefusedByPolicy = errors.New("address not allowed")

// closeTracker is a connection that records that it was closed.
type closeTracker struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTracker) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// TestDialerReceives: the dialer is called with network "tcp", the
// address given to New and the context of Connect, with its deadline.
func TestDialerReceives(t *testing.T) {
	_, addr := outstation(t)
	var (
		mu       sync.Mutex
		network  string
		got      string
		deadline time.Time
		hasDL    bool
	)
	var nd net.Dialer
	d := dialerFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
		mu.Lock()
		network, got = n, a
		deadline, hasDL = ctx.Deadline()
		mu.Unlock()
		return nd.DialContext(ctx, n, a)
	})
	c, err := New(addr, WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if network != "tcp" || got != addr {
		t.Errorf("dialer called with %q %q, want tcp %q", network, got, addr)
	}
	if !hasDL || !deadline.Equal(want) {
		t.Errorf("dialer deadline %v (%v), want the caller's %v", deadline, hasDL, want)
	}
}

// TestDialerDialTimeout: without a deadline of the caller, the dialer's
// context carries the dial timeout of 10 seconds.
func TestDialerDialTimeout(t *testing.T) {
	_, addr := outstation(t)
	var (
		mu       sync.Mutex
		deadline time.Time
		hasDL    bool
	)
	var nd net.Dialer
	d := dialerFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
		mu.Lock()
		deadline, hasDL = ctx.Deadline()
		mu.Unlock()
		return nd.DialContext(ctx, n, a)
	})
	c, err := New(addr, WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	before := time.Now()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !hasDL || deadline.Before(before.Add(dialTimeout)) || deadline.After(time.Now().Add(dialTimeout)) {
		t.Errorf("dialer deadline %v (%v), want %v after the dial", deadline, hasDL, dialTimeout)
	}
}

// TestDialerNilKeepsDefault: WithDialer(nil) keeps the default
// net.Dialer (otfabric policy 1.5, API-R03).
func TestDialerNilKeepsDefault(t *testing.T) {
	_, addr := outstation(t)
	c, err := New(addr, WithDialer(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	nd, ok := c.opts.dialer.(*net.Dialer)
	if !ok || nd.Timeout != dialTimeout {
		t.Fatalf("dialer %T %+v, want a net.Dialer with a %v timeout", c.opts.dialer, c.opts.dialer, dialTimeout)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestDialerCancel: a dialer that honours ctx ends when the caller
// cancels Connect.
func TestDialerCancel(t *testing.T) {
	entered := make(chan struct{})
	d := dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c, err := New("192.0.2.1:20000", WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-entered; cancel() }()
	err = c.Connect(ctx)
	if !errors.Is(err, dnp3.ErrConnectFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect cancelled in the dialer: %v", err)
	}
}

// TestDialerErrorWrapped: the dialer's error reaches the caller of
// Connect wrapped in dnp3.ErrConnectFailed, and errors.Is finds it.
func TestDialerErrorWrapped(t *testing.T) {
	d := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errRefusedByPolicy
	})
	c, err := New("192.0.2.1:20000", WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	err = c.Connect(testCtx(t))
	if !errors.Is(err, dnp3.ErrConnectFailed) || !errors.Is(err, errRefusedByPolicy) {
		t.Fatalf("Connect with a refusing dialer: %v", err)
	}
}

// TestDialerNilConnection: a dialer that returns neither a connection
// nor an error fails the dial instead of panicking.
func TestDialerNilConnection(t *testing.T) {
	d := dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, nil })
	c, err := New("192.0.2.1:20000", WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	err = c.Connect(testCtx(t))
	if !errors.Is(err, dnp3.ErrConnectFailed) || !errors.Is(err, errNoConn) {
		t.Fatalf("Connect with a dialer returning nil, nil: %v", err)
	}
}

// TestDialerConnectionWithError: a connection the dialer returns together
// with an error is closed, and the error returned.
func TestDialerConnectionWithError(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	tc := &closeTracker{Conn: a}
	d := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return tc, errRefusedByPolicy
	})
	c, err := New("192.0.2.1:20000", WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); !errors.Is(err, errRefusedByPolicy) {
		t.Fatalf("Connect: %v", err)
	}
	if !tc.closed.Load() {
		t.Fatal("the connection returned with an error was not closed")
	}
}

// TestDialerFaultMidSession: a transport fault injected through the
// dialer (its connection closed during the session) ends the channel,
// and the reconnect dials through the same dialer and works again.
func TestDialerFaultMidSession(t *testing.T) {
	srv, _ := outstation(t)
	var (
		mu    sync.Mutex
		peers []net.Conn
	)
	d := dialerFunc(func(_ context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("unexpected network " + network)
		}
		mine, theirs := net.Pipe()
		mu.Lock()
		peers = append(peers, theirs)
		mu.Unlock()
		go func() { _ = srv.ServeConn(theirs, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}) }()
		return mine, nil
	})
	c, err := New("outstation:20000", WithDialer(d),
		WithReconnect(Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 20 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx := testCtx(t)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.IntegrityPoll(ctx); err != nil {
		t.Fatalf("poll before the fault: %v", err)
	}
	mu.Lock()
	_ = peers[0].Close()
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(peers)
		mu.Unlock()
		if n >= 2 && c.State() == dnp3.StateConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reconnect through the dialer: %d dials, state %v", n, c.State())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.IntegrityPoll(ctx); err != nil {
		t.Fatalf("poll after the reconnect: %v", err)
	}
}

// TestUDPWithDialer: the dialer of UDPWithDialer is called with network
// "udp" and the address, and held to the dialer contract.
func TestUDPWithDialer(t *testing.T) {
	ctx := testCtx(t)
	var network, addr string
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	var nd net.Dialer
	d := dialerFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
		network, addr = n, a
		return nd.DialContext(ctx, n, a)
	})
	s, remote, err := UDPWithDialer(d, pc.LocalAddr().String())(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if network != "udp" || addr != pc.LocalAddr().String() || remote.String() != pc.LocalAddr().String() {
		t.Errorf("dialer called with %q %q, remote %v", network, addr, remote)
	}
	if _, ok := s.(interface{ ReadDatagram() ([]byte, error) }); !ok {
		t.Errorf("stream %T does not read datagrams", s)
	}

	// The default dialer.
	s2, _, err := UDPWithDialer(nil, pc.LocalAddr().String())(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Close()

	// The contract: an error, nil and nil, a connection with an error.
	refuse := dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errRefusedByPolicy })
	if _, _, err := UDPWithDialer(refuse, "x:1")(ctx); !errors.Is(err, errRefusedByPolicy) {
		t.Errorf("refusing dialer: %v", err)
	}
	none := dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, nil })
	if _, _, err := UDPWithDialer(none, "x:1")(ctx); !errors.Is(err, errNoConn) {
		t.Errorf("dialer returning nil, nil: %v", err)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	tc := &closeTracker{Conn: a}
	both := dialerFunc(func(context.Context, string, string) (net.Conn, error) { return tc, errRefusedByPolicy })
	if _, _, err := UDPWithDialer(both, "x:1")(ctx); !errors.Is(err, errRefusedByPolicy) || !tc.closed.Load() {
		t.Errorf("connection with an error: %v, closed %v", err, tc.closed.Load())
	}

	// Through a client, the error is wrapped in dnp3.ErrConnectFailed.
	c, err := New("x:1", WithStream(UDPWithDialer(refuse, "x:1")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(ctx); !errors.Is(err, dnp3.ErrConnectFailed) || !errors.Is(err, errRefusedByPolicy) {
		t.Errorf("Connect over UDPWithDialer: %v", err)
	}
}

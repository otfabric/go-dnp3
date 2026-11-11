// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/client"
)

type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

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

// TestDialerReceives: the dialer of DialAndServe is called with network
// "tcp", the address given to DialAndServe and a context that carries
// the dial timeout and ends with the context of DialAndServe.
func TestDialerReceives(t *testing.T) {
	type call struct {
		network, addr string
		deadline      time.Time
		hasDeadline   bool
		at            time.Time
	}
	calls := make(chan call, 1)
	d := dialerFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
		dl, ok := ctx.Deadline()
		calls <- call{n, a, dl, ok, time.Now()}
		<-ctx.Done() // honours ctx: the caller's cancel ends the dial
		return nil, ctx.Err()
	})
	srv, err := New(WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.DialAndServe(ctx, "master.example:20000", Redial{MinDelay: time.Minute}) }()
	var c call
	select {
	case c = <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("dialer not called")
	}
	if c.network != "tcp" || c.addr != "master.example:20000" {
		t.Errorf("dialer called with %q %q", c.network, c.addr)
	}
	if !c.hasDeadline {
		t.Error("the dialer's context has no deadline")
	} else if left := c.deadline.Sub(c.at); left <= 0 || left > handshakeTimeout {
		t.Errorf("dial deadline %v ahead, want within the dial timeout %v", left, handshakeTimeout)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialAndServe after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not end the dial")
	}
}

// TestDialerContract: the dialer's error is wrapped with
// dnp3.ErrConnectFailed; nil, nil fails the attempt; a connection
// returned with an error is closed.
func TestDialerContract(t *testing.T) {
	ctx := context.Background()
	refuse, err := New(WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errRefusedByPolicy
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refuse.Close() }()
	if _, err := refuse.dial(ctx, "m:1"); !errors.Is(err, dnp3.ErrConnectFailed) || !errors.Is(err, errRefusedByPolicy) {
		t.Errorf("refusing dialer: %v", err)
	}

	none, err := New(WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, nil })))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = none.Close() }()
	if _, err := none.dial(ctx, "m:1"); !errors.Is(err, dnp3.ErrConnectFailed) || !errors.Is(err, errNoConn) {
		t.Errorf("dialer returning nil, nil: %v", err)
	}

	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	tc := &closeTracker{Conn: a}
	both, err := New(WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return tc, errRefusedByPolicy
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = both.Close() }()
	if _, err := both.dial(ctx, "m:1"); !errors.Is(err, errRefusedByPolicy) || !tc.closed.Load() {
		t.Errorf("connection with an error: %v, closed %v", err, tc.closed.Load())
	}

	// DialAndServe goes on redialling after such attempts.
	var n atomic.Int64
	srv, err := New(WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		n.Add(1)
		return nil, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	tctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if err := srv.DialAndServe(tctx, "m:1", Redial{MinDelay: 5 * time.Millisecond, MaxDelay: 5 * time.Millisecond}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialAndServe: %v", err)
	}
	if n.Load() < 2 {
		t.Fatalf("%d attempts, want redials", n.Load())
	}
}

// TestDialerNilKeepsDefault: WithDialer(nil) keeps the net.Dialer.
func TestDialerNilKeepsDefault(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	srv, err := New(WithDialer(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	conn, err := srv.dial(context.Background(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

// TestDialerTLS: with WithTLS the handshake runs over the dialer's
// connection.
func TestDialerTLS(t *testing.T) {
	cert := selfSignedCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	handshaken := make(chan error, 1)
	d := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		mine, theirs := net.Pipe()
		go func() {
			tc := tls.Server(theirs, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			handshaken <- tc.Handshake()
			_, _ = io.Copy(io.Discard, tc)
		}()
		return mine, nil
	})
	srv, err := New(WithDialer(d), WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	conn, err := srv.dial(context.Background(), "127.0.0.1:20000")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("connection %T, want TLS", conn)
	}
	if err := <-handshaken; err != nil {
		t.Fatalf("master's handshake: %v", err)
	}

	// A failed handshake over the dialer's connection wraps
	// dnp3.ErrConnectFailed.
	plain := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		mine, theirs := net.Pipe()
		go func() { _ = theirs.Close() }()
		return mine, nil
	})
	bad, err := New(WithDialer(plain), WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	if _, err := bad.dial(context.Background(), "127.0.0.1:20000"); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("handshake with a closed peer: %v", err)
	}
}

// TestDialerFaultMidSession: a master talks to the outstation over the
// dialer's connection; the connection fails mid-session (its master end
// is closed), DialAndServe dials again through the dialer, and the next
// master is served.
func TestDialerFaultMidSession(t *testing.T) {
	masters := make(chan net.Conn, 4)
	var dials atomic.Int64
	d := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		mine, theirs := net.Pipe()
		masters <- theirs
		return mine, nil
	})
	srv, err := New(WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- srv.DialAndServe(ctx, "master:20000", Redial{MinDelay: 10 * time.Millisecond, MaxDelay: 10 * time.Millisecond})
	}()
	tctx, tcancel := context.WithTimeout(ctx, 10*time.Second)
	defer tcancel()
	for i := range 2 {
		var conn net.Conn
		select {
		case conn = <-masters:
		case <-tctx.Done():
			t.Fatalf("dial %d not made", i+1)
		}
		var once sync.Once
		open := func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
			var s io.ReadWriteCloser
			once.Do(func() { s = conn })
			if s == nil {
				return nil, nil, errors.New("one connection only")
			}
			return s, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}, nil
		}
		c, err := client.New("outstation", client.WithStream(open))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Connect(tctx); err != nil {
			t.Fatalf("master %d: %v", i+1, err)
		}
		if _, err := c.IntegrityPoll(tctx); err != nil {
			t.Fatalf("master %d poll: %v", i+1, err)
		}
		// The fault: the connection breaks under the session.
		_ = conn.Close()
		_ = c.Close()
	}
	if dials.Load() < 2 {
		t.Fatalf("%d dials", dials.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("DialAndServe: %v", err)
	}
}

// TestRedialJitterInvalid: a jitter outside [0, 1] fails DialAndServe
// with dnp3.ErrInvalidOption before any dial.
func TestRedialJitterInvalid(t *testing.T) {
	var dials atomic.Int64
	srv, err := New(WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errRefusedByPolicy
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	for _, j := range []float64{-0.1, 1.5, math.NaN(), math.Inf(1)} {
		if err := srv.DialAndServe(context.Background(), "m:1", Redial{Jitter: j}); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("jitter %v: %v", j, err)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("%d dials with an invalid jitter", dials.Load())
	}
}

// TestJitteredBounds: every jittered delay lies in [(1-f)·d, d], the draws
// spread over that range, and without jitter the delay is exact.
func TestJitteredBounds(t *testing.T) {
	const d = 800 * time.Millisecond
	for _, f := range []float64{0.01, 0.25, 0.5, 1} {
		lo := d - time.Duration(f*float64(d))
		minSeen, maxSeen := d, time.Duration(0)
		for range 2000 {
			w := jittered(d, f)
			if w < lo || w > d {
				t.Fatalf("jitter %v: delay %v outside [%v, %v]", f, w, lo, d)
			}
			minSeen, maxSeen = min(minSeen, w), max(maxSeen, w)
		}
		if spread := maxSeen - minSeen; spread < (d-lo)/2 {
			t.Errorf("jitter %v: delays spread over %v of %v", f, spread, d-lo)
		}
	}
	for _, d := range []time.Duration{0, time.Millisecond, time.Minute} {
		if w := jittered(d, 0); w != d {
			t.Fatalf("jittered(%v, 0) = %v", d, w)
		}
	}
	if w := jittered(0, 1); w != 0 {
		t.Fatalf("jittered(0, 1) = %v", w)
	}
}

// TestRedialWithJitter: with Jitter the pause before each redial lies in
// [(1-Jitter)·d, d] of the doubling delay d.
func TestRedialWithJitter(t *testing.T) {
	const (
		minDelay = 40 * time.Millisecond
		maxDelay = 160 * time.Millisecond
		jitter   = 0.5
	)
	var mu sync.Mutex
	var dials []time.Time
	srv, err := New(WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, time.Now())
		mu.Unlock()
		return nil, errRefusedByPolicy
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	_ = srv.DialAndServe(ctx, "m:1", Redial{MinDelay: minDelay, MaxDelay: maxDelay, Jitter: jitter})

	mu.Lock()
	defer mu.Unlock()
	if len(dials) < 5 {
		t.Fatalf("%d attempts in 900 ms, want at least 5", len(dials))
	}
	const slack = 60 * time.Millisecond // scheduling, under -race
	d := minDelay
	for i := 1; i < len(dials); i++ {
		gap := dials[i].Sub(dials[i-1])
		lo := d - time.Duration(jitter*float64(d))
		if gap < lo || gap > d+slack {
			t.Errorf("attempt %d after %v, want within [%v, %v]", i+1, gap, lo, d)
		}
		d = min(2*d, maxDelay)
	}
}

// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedListener is a net.Listener that returns its scripted results in
// order, then net.ErrClosed.
type scriptedListener struct {
	results chan acceptResult
}

type acceptResult struct {
	c   net.Conn
	err error
}

func newScriptedListener(rs ...acceptResult) *scriptedListener {
	l := &scriptedListener{results: make(chan acceptResult, len(rs))}
	for _, r := range rs {
		l.results <- r
	}
	return l
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	select {
	case r := <-l.results:
		return r.c, r.err
	default:
		return nil, net.ErrClosed
	}
}

func (l *scriptedListener) Close() error { return nil }
func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

// addrlessConn is a connection whose RemoteAddr panics, or returns nil
// with nilAddr.
type addrlessConn struct {
	net.Conn
	nilAddr bool
	closed  atomic.Bool
}

func (c *addrlessConn) RemoteAddr() net.Addr {
	if c.nilAddr {
		return nil
	}
	panic("no address")
}

func (c *addrlessConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func pipeConn(t *testing.T, nilAddr bool) *addrlessConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &addrlessConn{Conn: a, nilAddr: nilAddr}
}

// TestServeListenerContract: Serve, Group.Serve and ServeByMasterIP take an Accept that
// returns neither a connection nor an error as an Accept error, close a
// connection whose RemoteAddr panics, and refuse one without an address
// when WithMasterIPs is set; they go on accepting after each.
func TestServeListenerContract(t *testing.T) {
	srv, err := New(WithMasters(1), WithMasterIPs(netip.MustParsePrefix("127.0.0.1/32")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	member, err := New(WithAddress(2), WithMasters(1), WithMasterIPs(netip.MustParsePrefix("127.0.0.1/32")))
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGroup(member)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	serves := map[string]func(net.Listener) error{
		"Serve":       srv.Serve,
		"Group.Serve": g.Serve,
		"ServeByMasterIP": func(l net.Listener) error {
			return ServeByMasterIP(l, Route{Masters: netip.MustParsePrefix("0.0.0.0/0"), Server: srv})
		},
	}
	for name, serve := range serves {
		panicking, nilAddr := pipeConn(t, false), pipeConn(t, true)
		l := newScriptedListener(acceptResult{}, acceptResult{c: panicking}, acceptResult{c: nilAddr})
		done := make(chan error, 1)
		go func() { done <- serve(l) }()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not end", name)
		}
		if !panicking.closed.Load() {
			t.Errorf("%s: connection whose RemoteAddr panics not closed", name)
		}
		if !nilAddr.closed.Load() {
			t.Errorf("%s: connection without an address not refused", name)
		}
	}
}

// TestAcceptConnNilAddress: a connection with a nil address is accepted,
// with its nil address, for the caller to decide.
func TestAcceptConnNilAddress(t *testing.T) {
	c := pipeConn(t, true)
	got, remote, err := acceptConn(nil, newScriptedListener(acceptResult{c: c}))
	if err != nil || got != c || remote != nil {
		t.Fatalf("acceptConn: %v %v %v", got, remote, err)
	}
	if _, _, err := acceptConn(nil, newScriptedListener(acceptResult{})); !errors.Is(err, errNoAccept) {
		t.Fatalf("Accept with neither: %v", err)
	}
}

// TestDialedConnWithoutAddress: DialAndServe closes a dialed connection
// whose RemoteAddr panics and dials again.
func TestDialedConnWithoutAddress(t *testing.T) {
	c := pipeConn(t, false)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(WithDialer(dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return c, nil
		}
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	err = srv.DialAndServe(ctx, "master.example:20000", Redial{MinDelay: time.Millisecond, MaxDelay: time.Millisecond})
	if !errors.Is(err, context.Canceled) || !c.closed.Load() || calls.Load() < 2 {
		t.Fatalf("DialAndServe: %v, closed %v, %d dials", err, c.closed.Load(), calls.Load())
	}
}

// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/server"
)

// onceFailingListener fails its first Accept with an error other than
// net.ErrClosed, as a listener out of file descriptors does.
type onceFailingListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *onceFailingListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

// TestDualEndpointAcceptError: an Accept error of the dual end point's
// listener is waited out; the outstation's connection is taken after it.
func TestDualEndpointAcceptError(t *testing.T) {
	inner := listenTCP(t)
	l := &onceFailingListener{Listener: inner}
	c, err := New(deadAddr(t), WithDualEndpoint(l, nil), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("Connect to nobody: %v", err)
	}
	dualServer(t, inner)
	waitFor(t, "the outstation's connection", func() bool { return c.State() == dnp3.StateConnected })
	readOne(t, c)
	if !l.failed.Load() {
		t.Fatal("the failing Accept was not called")
	}
}

// TestDualEndpointTLSHandshakeFails: a connection on a TLS dual end point
// that fails its handshake is closed, and the client stays disconnected
// until an outstation completes one.
func TestDualEndpointTLSHandshakeFails(t *testing.T) {
	cert := selfSigned(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	l := listenTCP(t)
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	c, err := New(deadAddr(t), WithDualEndpoint(tl, nil), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.Connect(testCtx(t))

	plain, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	// A link frame instead of a ClientHello.
	if _, err := plain.Write([]byte{0x05, 0x64, 0x05, 0xC9, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, plain)
	if s := c.State(); s == dnp3.StateConnected {
		t.Fatal("connected over a connection whose TLS handshake failed")
	}

	dualServer(t, l, server.WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	waitFor(t, "the outstation's TLS connection", func() bool { return c.State() == dnp3.StateConnected })
	readOne(t, c)
}

// scriptedListener hands out the connections of conns, then blocks until
// it is closed. calls counts the Accept calls.
type scriptedListener struct {
	conns chan net.Conn
	calls atomic.Int32
	done  chan struct{}
	once  sync.Once
}

func newScriptedListener(conns ...net.Conn) *scriptedListener {
	l := &scriptedListener{conns: make(chan net.Conn, len(conns)), done: make(chan struct{})}
	for _, c := range conns {
		l.conns <- c
	}
	return l
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	select {
	case c := <-l.conns:
		return c, nil
	default:
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// failAtClose is a listener whose Accept fails, with an error other than
// net.ErrClosed, once closing is closed.
type failAtClose struct{ closing <-chan struct{} }

func (l failAtClose) Accept() (net.Conn, error) {
	<-l.closing
	return nil, errors.New("accept: too many open files")
}

func (failAtClose) Close() error   { return nil }
func (failAtClose) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// startAccept starts the dual end point's accept loop as the first open
// does.
func startAccept(c *Client) {
	c.dual.once.Do(func() {
		c.wg.Add(1)
		go c.dual.accept()
	})
}

func (d *dualEndpoint) state() (closed bool, queued net.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed, d.queued
}

// TestDualEndpointCloseDuringDial: a Close while the client's own dial is
// in progress wins over the dial: the connection the dial returns is
// closed, and Connect fails with dnp3.ErrClosed.
func TestDualEndpointCloseDuringDial(t *testing.T) {
	var c *Client
	closed := make(chan struct{})
	peer := make(chan net.Conn, 1)
	dial := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		go func() { _ = c.Close(); close(closed) }()
		waitFor(t, "Close", func() bool { closed, _ := c.dual.state(); return closed })
		a, b := net.Pipe()
		peer <- b
		return a, nil
	})
	c, err := New("192.0.2.1:20000", quiet(WithDualEndpoint(listenTCP(t), nil), WithDialer(dial))...)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("Connect closed during its dial: %v", err)
	}
	<-closed
	expectEOF(t, <-peer)
}

// TestDualEndpointOutstationDuringFailedDial: an outstation that connects
// to the dual end point while the client's own dial is in progress is taken
// by the Connect when the dial fails (IEEE 1815-2012 clause 13.2.3.1.3,
// Figure 13-7).
func TestDualEndpointOutstationDuringFailedDial(t *testing.T) {
	l := listenTCP(t)
	var c *Client
	dial := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dualServer(t, l)
		waitFor(t, "the outstation's connection", func() bool { _, q := c.dual.state(); return q != nil })
		return nil, errors.New("connection refused")
	})
	c, err := New("192.0.2.1:20000", quiet(WithDualEndpoint(l, nil), WithDialer(dial))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); err != nil {
		t.Fatalf("Connect with the outstation's connection: %v", err)
	}
	readOne(t, c)
}

// TestDualEndpointQueuedConnections: while a Connect is in progress, a
// newer connection of the outstation replaces one not yet taken, which is
// closed, and wakes the Connect only once. Close closes the connection
// still waiting; after Close a connection of the outstation is not taken.
func TestDualEndpointQueuedConnections(t *testing.T) {
	a, peerA := net.Pipe()
	b, peerB := net.Pipe()
	l := newScriptedListener(a, b)
	c, err := New("192.0.2.1:20000", quiet(WithDualEndpoint(l, nil))...)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.dialing = true // a Connect in progress takes the connection itself
	c.mu.Unlock()
	startAccept(c)
	expectEOF(t, peerA)
	waitFor(t, "the newer connection queued", func() bool { return l.calls.Load() == 3 })
	if _, q := c.dual.state(); q != b {
		t.Fatalf("queued %v, want the newer connection", q)
	}
	if len(c.dual.wake) != 1 {
		t.Fatal("the Connect in progress was not woken")
	}
	c.mu.Lock()
	c.dialing = false
	c.mu.Unlock()
	_ = c.Close()
	expectEOF(t, peerB)
	c.takeIncoming()
	c.mu.Lock()
	dialing := c.dialing
	c.mu.Unlock()
	if dialing {
		t.Fatal("a closed client takes a connection")
	}
}

// TestDualEndpointConnectionAfterClose: a connection the outstation
// establishes once Close has begun is closed, not queued.
func TestDualEndpointConnectionAfterClose(t *testing.T) {
	c, err := New(deadAddr(t), quiet()...)
	if err != nil {
		t.Fatal(err)
	}
	a, peer := net.Pipe()
	l := newScriptedListener(a)
	d := &dualEndpoint{c: c, l: l, wake: make(chan struct{}, 1), closed: true}
	c.wg.Add(1)
	go d.accept()
	expectEOF(t, peer)
	_ = l.Close()
	_ = c.Close()
	if _, q := d.state(); q != nil {
		t.Fatal("a connection queued after Close")
	}
}

// TestDualEndpointAcceptBackoffEndsAtClose: Close ends the wait after an
// Accept error of the dual end point's listener.
func TestDualEndpointAcceptBackoffEndsAtClose(t *testing.T) {
	c, err := New(deadAddr(t), quiet()...)
	if err != nil {
		t.Fatal(err)
	}
	d := &dualEndpoint{c: c, l: failAtClose{closing: c.closeCh}, wake: make(chan struct{}, 1)}
	c.wg.Add(1)
	go d.accept()
	done := make(chan struct{})
	go func() { _ = c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not end the accept loop")
	}
}

// readSignal is a connection that signals its first Read.
type readSignal struct {
	net.Conn
	once    sync.Once
	reading chan struct{}
}

func (c *readSignal) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(b)
}

// TestDualEndpointCloseDuringHandshake: Close ends the TLS handshake of a
// connection the outstation established while the client was idle, and
// the client stays disconnected.
func TestDualEndpointCloseDuringHandshake(t *testing.T) {
	a, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	conn := &readSignal{Conn: a, reading: make(chan struct{})}
	tl := tls.NewListener(newScriptedListener(conn), &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12})
	c, err := New("192.0.2.1:20000", quiet(WithDualEndpoint(tl, nil))...)
	if err != nil {
		t.Fatal(err)
	}
	startAccept(c)
	select {
	case <-conn.reading: // the handshake waits for the ClientHello
	case <-time.After(3 * time.Second):
		t.Fatal("no handshake")
	}
	_ = c.Close()
	expectEOF(t, peer)
	if s := c.State(); s != dnp3.StateDisconnected {
		t.Fatalf("state %v after Close", s)
	}
}

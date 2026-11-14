// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/leaktest"
)

// queuedListener is a net.Listener whose connections the test queues. It
// counts the calls of Accept: once Accept has been called n+1 times, the
// accept loop has dealt with the first n connections.
type queuedListener struct {
	conns   chan net.Conn
	accepts atomic.Int64
	done    chan struct{}
	once    sync.Once
}

func newQueuedListener(conns ...net.Conn) *queuedListener {
	l := &queuedListener{conns: make(chan net.Conn, len(conns)+1), done: make(chan struct{})}
	for _, c := range conns {
		l.conns <- c
	}
	return l
}

func (l *queuedListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *queuedListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *queuedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

// waitAccepts waits until Accept has been called n times.
func (l *queuedListener) waitAccepts(t *testing.T, n int64) {
	t.Helper()
	waitUntil(t, "the accept loop", func() bool { return l.accepts.Load() >= n })
}

// waitUntil polls cond, failing the test when it does not hold within 5 s.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// peerConn is the outstation's end of a net.Pipe from a TCP address, which
// counts when it is closed. The master's end stays silent.
type peerConn struct {
	net.Conn
	closed *atomic.Int64
	once   sync.Once
}

func (c *peerConn) Close() error {
	c.once.Do(func() { c.closed.Add(1) })
	return c.Conn.Close()
}

func (c *peerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

// silentPeers returns n connections whose masters never send, each as tls
// wraps it, the count of those the outstation closed, and the masters'
// ends, which the cleanup closes.
func silentPeers(t *testing.T, n int, wrap func(net.Conn) net.Conn) ([]net.Conn, *atomic.Int64) {
	t.Helper()
	closed := &atomic.Int64{}
	var conns []net.Conn
	for range n {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = b.Close() })
		conns = append(conns, wrap(&peerConn{Conn: a, closed: closed}))
	}
	return conns, closed
}

func plainConn(c net.Conn) net.Conn { return c }

func tlsServerConn(t *testing.T) func(net.Conn) net.Conn {
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12}
	return func(c net.Conn) net.Conn { return tls.Server(c, cfg) }
}

// TestMaxConnectionsCountsFromAccept: WithMaxConnections counts a
// connection from the moment it is accepted, through its TLS handshake:
// of connections accepted in a burst, those beyond the limit are closed at
// once, and the others are served.
func TestMaxConnectionsCountsFromAccept(t *testing.T) {
	const limit, burst = 2, 6
	for _, tc := range []struct {
		name string
		wrap func(*testing.T) func(net.Conn) net.Conn
	}{
		{"plain", func(*testing.T) func(net.Conn) net.Conn { return plainConn }},
		{"TLS handshake pending", tlsServerConn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaktest.Check(t)
			srv, err := New(WithMaxConnections(limit))
			if err != nil {
				t.Fatal(err)
			}
			conns, closed := silentPeers(t, burst, tc.wrap(t))
			l := newQueuedListener(conns...)
			served := make(chan error, 1)
			go func() { served <- srv.Serve(l) }()
			l.waitAccepts(t, burst+1)
			if got := closed.Load(); got != burst-limit {
				t.Errorf("%d connections accepted at once, limit %d: %d closed, want %d", burst, limit, got, burst-limit)
			}
			if got := srv.connections(); got != limit {
				t.Errorf("connections() = %d, want %d", got, limit)
			}
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatalf("Serve after Close: %v", err)
			}
			if got := closed.Load(); got != burst {
				t.Errorf("after Close %d of %d connections closed", got, burst)
			}
		})
	}
}

// TestMaxConnectionsFreedAfterHandshake: the place of a connection whose
// TLS handshake fails is free again for the next one.
func TestMaxConnectionsFreedAfterHandshake(t *testing.T) {
	leaktest.Check(t)
	srv, err := New(WithMaxConnections(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	wrap := tlsServerConn(t)
	a, b := net.Pipe()
	_ = b.Close() // the handshake fails at once
	closed := &atomic.Int64{}
	l := newQueuedListener(wrap(&peerConn{Conn: a, closed: closed}))
	go func() { _ = srv.Serve(l) }()
	l.waitAccepts(t, 2)
	waitUntil(t, "the failed handshake to give its place back", func() bool { return srv.connections() == 0 })
	if !srv.reserve() {
		t.Fatal("no place after the failed handshake")
	}
	srv.unreserve()
}

// TestCloseEndsTLSHandshakes (L5): Close ends the TLS handshake of an
// accepted connection whose peer stalls it, at once and not at the
// handshake timeout, for Serve and for ServeByMasterIP with a server or a
// group as the target, and leaves no goroutine behind.
func TestCloseEndsTLSHandshakes(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = time.Minute
	defer func() { handshakeTimeout = old }()
	prefix := netip.MustParsePrefix("127.0.0.0/8")
	for _, tc := range []struct {
		name  string
		serve func(srv *Server, l net.Listener) (closeAll func())
	}{
		{"Serve", func(srv *Server, l net.Listener) func() {
			go func() { _ = srv.Serve(l) }()
			return func() { _ = srv.Close() }
		}},
		{"ServeByMasterIP to a server", func(srv *Server, l net.Listener) func() {
			go func() { _ = ServeByMasterIP(l, Route{Masters: prefix, Server: srv}) }()
			return func() { _ = l.Close(); _ = srv.Close() }
		}},
		{"ServeByMasterIP to a group", func(srv *Server, l net.Listener) func() {
			g, err := NewGroup(srv)
			if err != nil {
				panic(err)
			}
			go func() { _ = ServeByMasterIP(l, Route{Masters: prefix, Group: g}) }()
			return func() { _ = l.Close(); _ = g.Close() }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaktest.Check(t)
			srv, err := New()
			if err != nil {
				t.Fatal(err)
			}
			conns, closed := silentPeers(t, 1, tlsServerConn(t))
			l := newQueuedListener(conns...)
			closeAll := tc.serve(srv, l)
			l.waitAccepts(t, 2)
			done := make(chan struct{})
			go func() {
				closeAll()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Close waits for a stalled TLS handshake")
			}
			waitUntil(t, "the connection to be closed", func() bool { return closed.Load() == 1 })
		})
	}
}

// TestPatternControlCountsMaxControls: every point a pattern control block
// operates counts against WithMaxControls; the block carries out those
// within the limit and is answered with TOO_MANY_OBJS when its mask names
// more.
func TestPatternControlCountsMaxControls(t *testing.T) {
	const limit = 4
	for _, tc := range []struct {
		name      string
		crobs     int // g12v1 objects before the pattern
		set       int // set bits of the mask
		wantCalls int
		want      app.CommandStatus
	}{
		{"no bit set", 0, 0, 0, app.StatusSuccess},
		{"one bit", 0, 1, 1, app.StatusSuccess},
		{"limit-1 bits", 0, limit - 1, limit - 1, app.StatusSuccess},
		{"limit bits", 0, limit, limit, app.StatusSuccess},
		{"limit+1 bits", 0, limit + 1, limit, app.StatusTooManyObjects},
		{"1000 bits", 0, 1000, limit, app.StatusTooManyObjects},
		{"controls before the pattern", 2, limit - 2, limit, app.StatusSuccess},
		{"controls before, one bit too many", 2, limit - 1, limit, app.StatusTooManyObjects},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &countingHandler{}
			m := newMaster(t, WithHandler(h), WithMaxControls(limit))
			var hs []app.Header
			if tc.crobs > 0 {
				var objs []app.Object
				for i := range uint32(tc.crobs) {
					objs = append(objs, app.Object{Index: 100 + i, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
				}
				hs = append(hs, app.Indexed(app.G12V1, objs...))
			}
			bits := make([]app.Value, max(tc.set, 1))
			for i := range bits {
				bits[i] = app.Binary{Value: i < tc.set}
			}
			hs = append(hs, app.Counted(app.G12V2, app.CROB{Op: app.OpLatchOn, Count: 1}), app.Ranged(app.G12V3, 0, bits...))
			m.send(req(1, app.FuncDirectOperate, hs...))
			f := m.recvFunc(app.FuncResponse)
			if got := h.count(); got != tc.wantCalls {
				t.Errorf("Operate called %d times, want %d", got, tc.wantCalls)
			}
			pcb := f.Headers[len(f.Headers)-2]
			if st := pcb.Objects[0].Value.(app.CROB).Status; st != tc.want {
				t.Errorf("pattern block status %s, want %s", st, tc.want)
			}
		})
	}
}

// TestControlHeaderWithoutObjects: a control header whose qualifier names
// no objects (0x06) is answered with IIN2.2, for every control function
// and object, and nothing is carried out or logged as an error.
func TestControlHeaderWithoutObjects(t *testing.T) {
	var logs syncBuffer
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithLogger(dnp3.NewSlogLogger(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))))
	pcb := app.Counted(app.G12V2, app.CROB{Op: app.OpLatchOn, Count: 1})
	cases := []struct {
		name string
		hs   []app.Header
	}{
		{"g12v1", []app.Header{app.AllObjects(app.G12V1)}},
		{"g41v1", []app.Header{app.AllObjects(app.G41V1)}},
		{"g41v2", []app.Header{app.AllObjects(app.G41V2)}},
		{"g41v3", []app.Header{app.AllObjects(app.G41V3)}},
		{"g41v4", []app.Header{app.AllObjects(app.G41V4)}},
		{"g12v2", []app.Header{app.AllObjects(app.G12V2), app.Ranged(app.G12V3, 0, app.Binary{Value: true})}},
		{"g12v3", []app.Header{pcb, app.AllObjects(app.G12V3)}},
	}
	seq := uint8(0)
	for _, fc := range []app.FunctionCode{app.FuncSelect, app.FuncOperate, app.FuncDirectOperate} {
		for _, c := range cases {
			seq = app.NextSeq(seq)
			m.send(req(seq, fc, c.hs...))
			f := m.recvFunc(app.FuncResponse)
			if !f.IIN.Has(app.IINParameterError) {
				t.Errorf("%s %s with qualifier 0x06: IIN %s, want PARAMETER_ERROR", fc, c.name, f.IIN)
			}
		}
	}
	if h.count() != 0 {
		t.Errorf("Operate called %d times", h.count())
	}
	if s := logs.String(); s != "" {
		t.Errorf("errors logged:\n%s", s)
	}
}

// TestWriteFileStatusesFitFragments: a WRITE of many file blocks is
// answered with one g70v6 status per block, spread over response
// fragments that each fit the transmit fragment size.
func TestWriteFileStatusesFitFragments(t *testing.T) {
	for _, n := range []int{1, 150, 200} {
		m := newMaster(t, WithFileServer(FSFileServer{FS: fstest.MapFS{}}))
		var vals []app.Value
		for i := range uint32(n) {
			vals = append(vals, app.FileTransport{Handle: 99, Block: i})
		}
		m.send(req(1, app.FuncWrite, app.FreeFormat(app.G70V5, vals...)))
		statuses := 0
		for {
			f := m.recvFunc(app.FuncResponse)
			b, err := f.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if len(b) > m.srv.opts.maxTxFragment {
				t.Errorf("%d blocks: response fragment of %d octets, limit %d", n, len(b), m.srv.opts.maxTxFragment)
			}
			for _, h := range f.Headers {
				if h.GV == app.G70V6 {
					statuses += len(h.Objects)
				}
			}
			if f.Control.CON {
				m.send(confirm(f.Control.Seq, false))
			}
			if f.Control.FIN {
				break
			}
		}
		if statuses != n {
			t.Errorf("%d blocks: %d statuses", n, statuses)
		}
	}
}

// TestReadBudgetCountsSelectedPoints: the READ budget (four reads of the
// whole database plus 1024 objects) is charged with the points each header
// selects: many headers of one point each are answered, while headers that
// name every point beyond the budget are answered with IIN2.2.
func TestReadBudgetCountsSelectedPoints(t *testing.T) {
	srv, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	const points = 3000 // budget 4*3000 + 1024 = 13024
	for i := range uint32(points) {
		_ = srv.Database().AddAnalogInput(i, PointConfig{}, app.Analog{Flags: app.FlagOnline})
	}
	a := srv.association(1)
	plan := func(hs ...app.Header) readPlan {
		done := make(chan readPlan, 1)
		a.post(func() {
			srv.db.mu.RLock()
			defer srv.db.mu.RUnlock()
			done <- a.planRead(&app.Fragment{Function: app.FuncRead, Headers: hs})
		})
		return <-done
	}
	objects := func(p readPlan) int {
		n := 0
		for _, it := range p.items {
			n += len(it.h.Objects)
		}
		return n
	}
	repeat := func(n int, h func(i int) app.Header) []app.Header {
		hs := make([]app.Header, n)
		for i := range hs {
			hs[i] = h(i)
		}
		return hs
	}
	for _, tc := range []struct {
		name    string
		hs      []app.Header
		objects int
		refused bool
	}{
		{"5 single-point ranges", repeat(5, func(i int) app.Header { return app.IndexRange(app.G30V1, uint32(i*100), uint32(i*100)) }), 5, false},
		{"250 single-point ranges", repeat(250, func(i int) app.Header { return app.IndexRange(app.G30V1, uint32(i), uint32(i)) }), 250, false},
		{"100 single indexes", repeat(100, func(i int) app.Header {
			return app.Header{GV: app.G30V1, Qualifier: app.Qual2ByteIndexCount, Count: 1, Objects: []app.Object{{Index: uint32(i)}}}
		}), 100, false},
		{"4 whole reads", repeat(4, func(int) app.Header { return app.AllObjects(app.G30V0) }), 4 * points, false},
		{"5 whole reads", repeat(5, func(int) app.Header { return app.AllObjects(app.G30V0) }), 4 * points, true},
		{"5 whole ranges", repeat(5, func(int) app.Header { return app.IndexRange(app.G30V1, 0, points-1) }), 4 * points, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := plan(tc.hs...)
			if got := p.iin.Has(app.IINParameterError); got != tc.refused {
				t.Errorf("IIN %s, refused %t, want %t", p.iin, got, tc.refused)
			}
			if got := objects(p); got != tc.objects {
				t.Errorf("%d objects planned, want %d", got, tc.objects)
			}
		})
	}
}

// TestReadSelectedRangeOrder: a READ by range or index list reports the
// points it names in ascending order, the same with and without points
// outside it.
func TestReadSelectedRangeOrder(t *testing.T) {
	srv, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	for _, i := range []uint32{9, 2, 7, 4, 0, 0xFFFFFFFF} {
		_ = srv.Database().AddAnalogInput(i, PointConfig{}, app.Analog{Value: float64(i), Flags: app.FlagOnline})
	}
	db := srv.db
	idx := func(s selector) []uint32 {
		db.mu.RLock()
		defer db.mu.RUnlock()
		return append([]uint32(nil), db.selected(AnalogInput, s)...)
	}
	for _, tc := range []struct {
		s    selector
		want string
	}{
		{selector{all: true}, "[0 2 4 7 9 4294967295]"},
		{selector{start: 2, stop: 7}, "[2 4 7]"},
		{selector{start: 3, stop: 3}, "[]"},
		{selector{start: 10, stop: 0xFFFFFFFF}, "[4294967295]"},
		{selector{start: 0, stop: 0}, "[0]"},
		{selector{indexes: map[uint32]bool{9: true, 1: true, 0: true, 4: true}}, "[0 4 9]"},
	} {
		if got := fmt.Sprint(idx(tc.s)); got != tc.want {
			t.Errorf("selector %+v: %s, want %s", tc.s, got, tc.want)
		}
	}
}

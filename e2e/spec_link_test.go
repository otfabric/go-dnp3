// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// Spec tests: IEEE 1815-2012 clause 13 (DNP3 over TCP and UDP) with the
// client and the server of this module on loopback sockets. Page numbers
// are printed pages.

// until polls cond until it holds, for at most 5 seconds.
func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func binaryInput(db *server.Database) {
	_ = db.AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
}

// TestSpec13_2_3_3_SecondMasterRejected checks clause 13.2.3.3 (p. 382):
// a second master with the same link addresses connects while the first
// polls; the outstation finds the first connection alive and rejects the
// second, and the first polls on without an error.
func TestSpec13_2_3_3_SecondMasterRejected(t *testing.T) {
	p := newPair(t, binaryInput, nil)
	cx := ctx(t)
	stop := make(chan struct{})
	polled := make(chan error, 1)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				if n == 0 {
					polled <- context.DeadlineExceeded // not one poll
					return
				}
				polled <- nil
				return
			default:
			}
			if _, err := p.c.Read(cx, app.AllObjects(app.G1V0)); err != nil {
				polled <- err
				return
			}
			n++
		}
	}()
	lost := make(chan error, 4)
	second, err := client.Dial(cx, p.l.Addr().String(), client.WithAutoIntegrity(false),
		client.WithStateHandler(func(s dnp3.State, err error) {
			if s == dnp3.StateDisconnected {
				lost <- err
			}
		}))
	if err == nil {
		defer func() { _ = second.Close() }()
		select {
		case err := <-lost:
			if !errors.Is(err, dnp3.ErrConnectionLost) {
				t.Fatalf("the second master was disconnected with %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the second master was not rejected")
		}
	}
	for range 3 {
		if _, err := p.c.Read(cx, app.AllObjects(app.G1V0)); err != nil {
			t.Fatalf("the first master after the rejection: %v", err)
		}
	}
	close(stop)
	if err := <-polled; err != nil {
		t.Fatalf("the first master's polls: %v", err)
	}
	if s := p.c.State(); s != dnp3.StateConnected {
		t.Fatalf("the first master is %v", s)
	}
}

// TestSpec13_2_3_2_4_BroadcastSetsIIN checks clause 13.2.3.2.4 (p. 382)
// and Table 13-1 (p. 381): a broadcast is carried out whether the master
// sends it over its TCP connection or over UDP, and the next response on
// the TCP connection sets IIN1.0 each time; the UDP broadcast leaves the
// TCP connection in place.
func TestSpec13_2_3_2_4_BroadcastSetsIIN(t *testing.T) {
	r := &relay{status: app.StatusSuccess}
	p := newPair(t, binaryInput, []server.Option{server.WithHandler(r)}, client.WithAutoClearRestart(false))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.srv.ServeUDP(pc) }()
	cx := ctx(t)
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	u, err := client.Dial(cx, "outstation", client.WithStream(client.UDP(pc.LocalAddr().String())),
		client.WithAutoIntegrity(false), client.WithAutoClearRestart(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	for i, c := range []*client.Client{p.c, u} {
		if err := c.Broadcast(cx, link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, crob); err != nil {
			t.Fatal(err)
		}
		until(t, "the broadcast control", func() bool { _, op, _ := r.snapshot(); return len(op) == i+1 })
		res, err := p.c.Read(cx, app.AllObjects(app.G1V0))
		if err != nil || !res.IIN.Has(app.IINBroadcast) {
			t.Fatalf("broadcast %d: response %v %v", i, res, err)
		}
	}
	if s := p.c.State(); s != dnp3.StateConnected {
		t.Fatalf("the TCP master is %v", s)
	}
}

// countingListener counts the connections it accepted.
type countingListener struct {
	net.Listener
	n atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// liveMetrics counts the connections open at once.
type liveMetrics struct {
	dnp3.NopMetrics
	mu        sync.Mutex
	live, top int
}

func (m *liveMetrics) OnConnect(net.Addr) {
	m.mu.Lock()
	m.live++
	m.top = max(m.top, m.live)
	m.mu.Unlock()
}

func (m *liveMetrics) OnDisconnect(net.Addr, error) {
	m.mu.Lock()
	m.live--
	m.mu.Unlock()
}

// TestSpec13_2_3_1_3_DualEndPoints checks clause 13.2.3.1.3 (p. 379) with
// a dual end point on both sides: the master's client with
// WithDualEndpoint and the outstation's Serve with DialAndServe. While
// the master's own connection stands the outstation does not connect;
// when the master can no longer connect, the outstation's connection is
// taken. There is never more than one connection at a time.
func TestSpec13_2_3_1_3_DualEndPoints(t *testing.T) {
	met := &liveMetrics{}
	srv, err := server.New(server.WithMasters(1), server.WithMetrics(met))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	binaryInput(srv.Database())
	ls, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ls) }()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: raw}
	cx := ctx(t)
	c, err := client.New(ls.Addr().String(), client.WithDualEndpoint(cl, nil), client.WithAutoIntegrity(false),
		client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Connect(cx); err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		if res, err := c.Read(cx, app.AllObjects(app.G1V0)); err != nil || len(res.Measurements()) != 1 {
			t.Fatalf("read: %v %v", res, err)
		}
	}
	read()

	dctx, cancel := context.WithCancel(context.Background())
	dialed := make(chan struct{})
	go func() {
		_ = srv.DialAndServe(dctx, cl.Addr().String(), server.Redial{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond})
		close(dialed)
	}()
	t.Cleanup(func() { cancel(); <-dialed })
	select {
	case <-dialed:
		t.Fatal("DialAndServe returned")
	case <-time.After(200 * time.Millisecond): // ten checks of DialAndServe
	}
	if n := cl.n.Load(); n != 0 {
		t.Fatalf("the outstation connected %d times while the master's connection stood", n)
	}
	read()

	// The master's way in closes: the outstation's connection is used.
	_ = ls.Close()
	srv.CloseConnections()
	until(t, "the outstation's connection", func() bool { return cl.n.Load() > 0 && c.State() == dnp3.StateConnected })
	read()
	met.mu.Lock()
	top := met.top
	met.mu.Unlock()
	if top != 1 {
		t.Fatalf("%d connections at once", top)
	}
}

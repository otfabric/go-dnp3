// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/leaktest"
)

// The rows of the lifecycle contract matrix (TESTING.md, L1 to L16) for the
// outstation that other tests do not cover. Each checks that no goroutine
// is left behind.

// listen serves srv on a loopback listener and returns its address and
// the error Serve returned, once it has.
func listen(t *testing.T, serve func(net.Listener) error) (string, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- serve(l) }()
	return l.Addr().String(), served
}

func directOperate(seq uint8, index uint32) *app.Fragment {
	return req(seq, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: index, Value: app.CROB{Op: app.OpLatchOn, Count: 1}}))
}

// TestConcurrentClose (L2): Close called from several goroutines at once,
// on a server and on a group, each serving a connection: every call
// returns nil, and Serve returns nil.
func TestConcurrentClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		// start returns Serve, Close and whether one connection is served.
		start func(t *testing.T) (serve func(net.Listener) error, closeFn func() error, serving func() bool)
	}{
		{"server", func(t *testing.T) (func(net.Listener) error, func() error, func() bool) {
			srv, err := New()
			if err != nil {
				t.Fatal(err)
			}
			return srv.Serve, srv.Close, func() bool { return srv.connections() == 1 }
		}},
		{"group", func(t *testing.T) (func(net.Listener) error, func() error, func() bool) {
			a, err := New(WithAddress(10))
			if err != nil {
				t.Fatal(err)
			}
			b, err := New(WithAddress(11))
			if err != nil {
				t.Fatal(err)
			}
			g, err := NewGroup(a, b)
			if err != nil {
				t.Fatal(err)
			}
			return g.Serve, g.Close, func() bool {
				g.mu.Lock()
				defer g.mu.Unlock()
				return g.conns == 1
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaktest.Check(t)
			serve, closeFn, serving := tc.start(t)
			addr, served := listen(t, serve)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			waitUntil(t, "the connection to be served", serving)
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for range 8 {
				wg.Go(func() { errs <- closeFn() })
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Errorf("Close: %v", err)
				}
			}
			if err := <-served; err != nil {
				t.Errorf("Serve after Close: %v", err)
			}
			// The connection was closed by Close: the read ends with EOF, or
			// with a reset, depending on what the socket still held. Only a
			// read that is still waiting at the deadline means it was left
			// open.
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(make([]byte, 1))
			var ne net.Error
			if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Errorf("connection after Close: %v, want it closed", err)
			}
		})
	}
}

// TestCloseWithRequestInFlight (L3): Close while a control is being
// carried out, with the handler waiting on its context: the context ends,
// the handler returns, and Close returns.
func TestCloseWithRequestInFlight(t *testing.T) {
	leaktest.Check(t)
	entered := make(chan struct{})
	h := handlerFuncs{operate: func(ctx context.Context, _ Command, _ OperateType) app.CommandStatus {
		close(entered)
		<-ctx.Done()
		return app.StatusSuccess
	}}
	srv, err := New(WithMasters(1), WithHandler(h))
	if err != nil {
		t.Fatal(err)
	}
	addr, served := listen(t, srv.Serve)
	m := connectMaster(t, srv, addr, 1)
	m.send(directOperate(1, 0))
	<-entered
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve after Close: %v", err)
	}
}

// writeGate is a stream whose writes report that they started; its peer
// does not read, so a write blocks.
type writeGate struct {
	net.Conn
	once    sync.Once
	writing chan struct{}
}

func (w *writeGate) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.writing) })
	return w.Conn.Write(b)
}

// TestCloseDuringWrite (L4): Close while the outstation writes to a peer
// that does not read: the write ends with the stream, and ServeConn and
// Close return.
func TestCloseDuringWrite(t *testing.T) {
	leaktest.Check(t)
	srv, err := New(WithMasters(1), WithUnsolicited(Unsolicited{Enabled: true}))
	if err != nil {
		t.Fatal(err)
	}
	near, far := net.Pipe()
	defer func() { _ = far.Close() }()
	gate := &writeGate{Conn: near, writing: make(chan struct{})}
	served := make(chan error, 1)
	// With one master configured, the null unsolicited response goes out
	// at once (IEEE 1815-2012 5.1.1.1.1), into a pipe nobody reads.
	go func() { served <- srv.ServeConn(gate, nil) }()
	<-gate.writing
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Errorf("ServeConn after Close: %v", err)
	}
}

// handlerFuncs is a Handler of functions; nil ones answer SUCCESS.
type handlerFuncs struct {
	operate func(context.Context, Command, OperateType) app.CommandStatus
}

func (handlerFuncs) Select(context.Context, Command) app.CommandStatus { return app.StatusSuccess }

func (h handlerFuncs) Operate(ctx context.Context, c Command, op OperateType) app.CommandStatus {
	if h.operate == nil {
		return app.StatusSuccess
	}
	return h.operate(ctx, c, op)
}

// TestHandlerCallsServer (L9): a handler may call the server's other
// methods: it updates the database and the indications while its control
// is carried out, and the response reports them.
func TestHandlerCallsServer(t *testing.T) {
	leaktest.Check(t)
	var srv *Server
	h := handlerFuncs{operate: func(_ context.Context, c Command, _ OperateType) app.CommandStatus {
		if err := srv.Database().UpdateBinaryOutput(c.Index, app.Binary{Value: true, Flags: app.FlagOnline}); err != nil {
			return app.StatusHardwareError
		}
		srv.SetIndications(app.IINDeviceTrouble, true)
		_ = srv.Now()
		return app.StatusSuccess
	}}
	srv, err := New(WithMasters(1), WithHandler(h))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryOutput(0, PointConfig{}, app.Binary{Flags: app.FlagOnline})
	addr, served := listen(t, srv.Serve)
	m := connectMaster(t, srv, addr, 1)
	m.send(directOperate(1, 0))
	f := m.recvFunc(app.FuncResponse)
	if st := f.Headers[0].Objects[0].Value.(app.CROB).Status; st != app.StatusSuccess {
		t.Errorf("control status %s", st)
	}
	if !f.IIN.Has(app.IINDeviceTrouble) {
		t.Errorf("IIN %s without DEVICE_TROUBLE set by the handler", f.IIN)
	}
	if v, _ := srv.Database().Get(BinaryOutput, 0); !v.(app.Binary).Value {
		t.Error("output status not updated by the handler")
	}
	_ = srv.Close()
	if err := <-served; err != nil {
		t.Errorf("Serve after Close: %v", err)
	}
}

// TestHandlerStartsClose (L10): a handler that wants the server closed
// starts Close on another goroutine (Close waits for the association
// goroutine the handler runs on): Close completes once the handler has
// returned.
func TestHandlerStartsClose(t *testing.T) {
	leaktest.Check(t)
	var srv *Server
	var returned atomic.Bool
	closed := make(chan bool, 1)
	h := handlerFuncs{operate: func(context.Context, Command, OperateType) app.CommandStatus {
		go func() {
			_ = srv.Close()
			closed <- returned.Load()
		}()
		returned.Store(true)
		return app.StatusSuccess
	}}
	srv, err := New(WithMasters(1), WithHandler(h))
	if err != nil {
		t.Fatal(err)
	}
	addr, served := listen(t, srv.Serve)
	m := connectMaster(t, srv, addr, 1)
	m.send(directOperate(1, 0))
	select {
	case after := <-closed:
		if !after {
			t.Error("Close completed before the handler returned")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close started by the handler did not complete")
	}
	if err := <-served; err != nil {
		t.Errorf("Serve after Close: %v", err)
	}
}

// TestSlowHandlerDelaysOneMaster (L11): a handler that is slow for one
// master delays that master's requests only: another master's READ is
// answered while it runs.
func TestSlowHandlerDelaysOneMaster(t *testing.T) {
	leaktest.Check(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h := handlerFuncs{operate: func(context.Context, Command, OperateType) app.CommandStatus {
		close(entered)
		<-release
		return app.StatusSuccess
	}}
	srv, err := New(WithMasters(1, 2), WithHandler(h))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	addr, served := listen(t, srv.Serve)
	slow := connectMaster(t, srv, addr, 1)
	other := connectMaster(t, srv, addr, 2)
	slow.send(directOperate(1, 0))
	<-entered
	other.send(req(1, app.FuncRead, app.AllObjects(app.G1V0)))
	if f := other.recvFunc(app.FuncResponse); len(f.Headers) == 0 {
		t.Errorf("READ of the other master answered without data: %s", f)
	}
	close(release)
	if f := slow.recvFunc(app.FuncResponse); f.Headers[0].Objects[0].Value.(app.CROB).Status != app.StatusSuccess {
		t.Errorf("slow control answered %s", f)
	}
	_ = srv.Close()
	if err := <-served; err != nil {
		t.Errorf("Serve after Close: %v", err)
	}
}

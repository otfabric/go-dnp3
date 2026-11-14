// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
)

// callbackLog is a slog.Handler that records the error entries of
// application code that did not return normally: the callback named, or
// the message of the association's own entry, each with its stack.
type callbackLog struct {
	mu    sync.Mutex
	stack map[string]string
	added chan struct{}
	// onError, when set before the server runs, is called with the key of
	// each error entry, on the goroutine that logs it.
	onError func(key string)
}

func newCallbackLog() *callbackLog {
	return &callbackLog{stack: map[string]string{}, added: make(chan struct{}, 1)}
}

func (h *callbackLog) logger() dnp3.Logger { return dnp3.NewSlogLogger(h) }

func (h *callbackLog) Enabled(context.Context, slog.Level) bool { return true }

func (h *callbackLog) Handle(_ context.Context, r slog.Record) error {
	if r.Level != slog.LevelError {
		return nil
	}
	key, stack := r.Message, ""
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "callback":
			key = a.Value.String()
		case "stack":
			stack = a.Value.String()
		}
		return true
	})
	if h.onError != nil {
		h.onError(key)
	}
	h.mu.Lock()
	h.stack[key] = stack
	h.mu.Unlock()
	select {
	case h.added <- struct{}{}:
	default:
	}
	return nil
}

func (h *callbackLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *callbackLog) WithGroup(string) slog.Handler      { return h }

// wait waits until key was logged with a stack that passes through file.
func (h *callbackLog) wait(t *testing.T, key, file string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		h.mu.Lock()
		stack, ok := h.stack[key]
		h.mu.Unlock()
		if ok {
			if !strings.Contains(stack, file) {
				t.Fatalf("%s logged without the stack through %s:\n%s", key, file, stack)
			}
			return
		}
		select {
		case <-h.added:
		case <-deadline:
			t.Fatalf("%q was not logged", key)
		}
	}
}

// failingMetrics is a dnp3.Metrics and dnp3.ServerMetrics none of whose
// callbacks returns normally.
type failingMetrics struct{}

func (failingMetrics) OnConnect(net.Addr)                              { panic("metrics") }
func (failingMetrics) OnDisconnect(net.Addr, error)                    { panic("metrics") }
func (failingMetrics) OnFrameSent(net.Addr, *link.Frame, int)          { panic("metrics") }
func (failingMetrics) OnFrameReceived(net.Addr, *link.Frame, int)      { panic("metrics") }
func (failingMetrics) OnFramingError(net.Addr, error)                  { panic("metrics") }
func (failingMetrics) OnFragmentSent(net.Addr, *app.Fragment, int)     { panic("metrics") }
func (failingMetrics) OnFragmentReceived(net.Addr, *app.Fragment, int) { panic("metrics") }
func (failingMetrics) OnDecodeError(net.Addr, error)                   { panic("metrics") }
func (failingMetrics) OnHandled(net.Addr, app.FunctionCode, time.Duration) {
	panic("metrics")
}
func (failingMetrics) OnEventsDiscarded(int, int)         { panic("metrics") }
func (failingMetrics) OnUnsolicited(net.Addr, int, error) { panic("metrics") }

// TestServerMetricsThatDoNotReturnNormally: the outstation answers as
// usual when no callback of its metrics returns normally, OnDecodeError and
// OnFragmentSent among them; each is logged with its stack.
func TestServerMetricsThatDoNotReturnNormally(t *testing.T) {
	logs := newCallbackLog()
	srv, err := New(WithMaxAssociations(1), WithMetrics(failingMetrics{}), WithLogger(logs.logger()),
		WithEventLimits(map[PointType]int{BinaryInput: 1}))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	m := newPipeMasters(t, srv)
	if f := m.read(1, 0); f.IIN&dnp3.IINErrorBits != 0 {
		t.Fatalf("READ answered with %s", f.IIN)
	}
	m.send(2, 0) // beyond the limit: OnDecodeError
	// Two events into a buffer of one: OnEventsDiscarded, on this goroutine.
	for _, v := range []bool{true, false} {
		if err := srv.Database().Update(BinaryInput, 0, app.Binary{Value: v, Flags: app.FlagOnline}, EventOnChange); err != nil {
			t.Fatal(err)
		}
	}
	for _, cb := range []string{"Metrics.OnConnect", "Metrics.OnFrameReceived", "Metrics.OnFragmentReceived",
		"ServerMetrics.OnHandled", "Metrics.OnFragmentSent", "Metrics.OnFrameSent", "Metrics.OnDecodeError",
		"ServerMetrics.OnEventsDiscarded"} {
		logs.wait(t, cb, "callbacks_test.go")
	}
	if f := m.read(1, 1); f.IIN&dnp3.IINErrorBits != 0 {
		t.Fatalf("second READ answered with %s", f.IIN)
	}
}

// TestBatchThatDoesNotReturnNormally: a Database.Batch function that does
// not return normally is logged and counts as one that failed: Batch
// returns the error, reports no event, and the database is unlocked.
func TestBatchThatDoesNotReturnNormally(t *testing.T) {
	logs := newCallbackLog()
	srv, err := New(WithLogger(logs.logger()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	db := srv.Database()
	_ = db.AddBinaryInput(0, PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	a := srv.association(1)
	err = db.Batch(func(b *Batch) error {
		_ = b.Update(BinaryInput, 0, app.Binary{Value: true, Flags: app.FlagOnline}, EventOnChange)
		panic("batch function of the application")
	})
	var ce *logx.CallbackError
	if !errors.As(err, &ce) || ce.Callback != "Database.Batch function" {
		t.Fatalf("Batch: %v, want the CallbackError of the function", err)
	}
	logs.wait(t, "Database.Batch function", "callbacks_test.go")
	if n := a.events.pending(1 << 1); n != 0 {
		t.Errorf("%d events reported for the batch that failed", n)
	}
	// Unlocked: the next update and a read go through.
	if err := db.Update(BinaryInput, 0, app.Binary{Flags: app.FlagOnline}, EventOnChange); err != nil {
		t.Fatal(err)
	}
	if v, ok := db.Get(BinaryInput, 0); !ok || v.(app.Binary).Value {
		t.Fatalf("point after the next update: %v %t", v, ok)
	}
	// A Database of no Server, the zero value, has no logger.
	var zero Database
	if err := zero.Batch(func(*Batch) error { panic("batch function of the application") }); !errors.As(err, &ce) {
		t.Fatalf("Batch of the zero Database: %v, want the CallbackError of the function", err)
	}
}

// closeFailingFile is an open file whose Close does not return normally.
type closeFailingFile struct{}

func (closeFailingFile) Read([]byte) (int, error)  { return 0, nil }
func (closeFailingFile) Write([]byte) (int, error) { return 0, nil }
func (closeFailingFile) Size() uint32              { return 0 }
func (closeFailingFile) Close(bool) error          { panic("file Close of the application") }

// TestFileCloseAtAssociationEnd: the files an association has open are
// closed when it ends, at Close; a File whose Close does not return
// normally is logged with its stack and Close returns.
func TestFileCloseAtAssociationEnd(t *testing.T) {
	logs := newCallbackLog()
	srv, err := New(WithLogger(logs.logger()))
	if err != nil {
		t.Fatal(err)
	}
	a := srv.association(1)
	opened := make(chan struct{})
	a.post(func() {
		a.files[1] = &openFile{f: closeFailingFile{}, name: "f", mode: app.FileModeRead, used: time.Now()}
		close(opened)
	})
	<-opened
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	logs.wait(t, "panic while serving a request", "callbacks_test.go")
}

// dialerCalls is a Dialer that does not return normally the first time and
// refuses after that; it reports each call.
type dialerCalls chan int

func (d dialerCalls) DialContext(context.Context, string, string) (net.Conn, error) {
	n := len(d) + 1
	d <- n
	if n == 1 {
		panic("dialer of the application")
	}
	return nil, errRefusedByPolicy
}

// TestServerDialerThatDoesNotReturnNormally: an attempt of DialAndServe
// whose dialer does not return normally fails, is logged with the stack,
// and DialAndServe tries again; it returns when its context ends.
func TestServerDialerThatDoesNotReturnNormally(t *testing.T) {
	logs := newCallbackLog()
	calls := make(dialerCalls, 8)
	srv, err := New(WithDialer(calls), WithLogger(logs.logger()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.DialAndServe(ctx, "192.0.2.1:20000", Redial{MinDelay: time.Millisecond}) }()
	<-calls
	logs.wait(t, "Dialer.DialContext", "callbacks_test.go")
	<-calls // the next attempt
	cancel()
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Fatalf("DialAndServe: %v, want context.Canceled", err)
	}
}

// TestTLSHandshakeThatDoesNotReturnNormally: a TLS handshake whose
// tls.Config callback, the application's, does not return normally fails
// as a failed handshake does: an accepted connection is closed and the
// listener goes on, a connection of DialAndServe is an attempt that failed.
func TestTLSHandshakeThatDoesNotReturnNormally(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		logs := newCallbackLog()
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			panic("GetCertificate of the application")
		}}
		srv, err := New(WithLogger(logs.logger()))
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- srv.Serve(tls.NewListener(l, cfg)) }()
		for range 2 { // the listener takes the next connection too
			c, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
			if err == nil {
				_ = c.Close()
				t.Fatal("handshake succeeded")
			}
		}
		logs.wait(t, "TLS handshake", "callbacks_test.go")
		_ = srv.Close()
		if err := <-served; err != nil {
			t.Fatalf("Serve: %v", err)
		}
	})
	t.Run("DialAndServe", func(t *testing.T) {
		logs := newCallbackLog()
		master, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = master.Close() }()
		accepted := make(chan struct{}, 8)
		go func() {
			for {
				c, err := master.Accept()
				if err != nil {
					return
				}
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
				accepted <- struct{}{}
			}
		}()
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
			VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { panic("VerifyPeerCertificate of the application") }}
		srv, err := New(WithTLS(cfg), WithLogger(logs.logger()))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = srv.Close() }()
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() { served <- srv.DialAndServe(ctx, master.Addr().String(), Redial{MinDelay: time.Millisecond}) }()
		<-accepted
		<-accepted // a second attempt after the first failed
		logs.wait(t, "TLS handshake", "callbacks_test.go")
		cancel()
		if err := <-served; !errors.Is(err, context.Canceled) {
			t.Fatalf("DialAndServe: %v, want context.Canceled", err)
		}
	})
}

// failingListener is a listener whose first Accept does not return
// normally, and whose Close does not either with closeFails. Accept then
// waits for Close.
type failingListener struct {
	accepts    chan int
	closeFails bool
	done       chan struct{}
	once       sync.Once
}

func newFailingListener(closeFails bool) *failingListener {
	return &failingListener{accepts: make(chan int, 8), closeFails: closeFails, done: make(chan struct{})}
}

func (l *failingListener) Accept() (net.Conn, error) {
	n := len(l.accepts) + 1
	l.accepts <- n
	if n == 1 {
		panic("Accept of the application")
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *failingListener) Close() error {
	l.once.Do(func() { close(l.done) })
	if l.closeFails {
		panic("listener Close of the application")
	}
	return nil
}

func (l *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

// TestListenerThatDoesNotReturnNormally: an Accept of the application's
// listener that does not return normally is an Accept error: it is logged
// with the stack and the listener is asked again. A Close of it that does
// not return normally is logged, and Close of the server or group returns.
func TestListenerThatDoesNotReturnNormally(t *testing.T) {
	route := netip.MustParsePrefix("0.0.0.0/0")
	if (Route{Masters: route, Group: &Group{}}).log() != nil {
		t.Fatal("a Group not made by NewGroup has a logger")
	}
	for _, tc := range []struct {
		name string
		// serve serves l with s; close, when not nil, closes what serves l.
		setup func(t *testing.T, s *Server) (serve func(net.Listener) error, close func() error)
	}{
		{"Server", func(_ *testing.T, s *Server) (func(net.Listener) error, func() error) {
			return s.Serve, s.Close
		}},
		{"Group", func(t *testing.T, s *Server) (func(net.Listener) error, func() error) {
			g, err := NewGroup(s)
			if err != nil {
				t.Fatal(err)
			}
			return g.Serve, g.Close
		}},
		{"ServeByMasterIP", func(_ *testing.T, s *Server) (func(net.Listener) error, func() error) {
			return func(l net.Listener) error { return ServeByMasterIP(l, Route{Masters: route, Server: s}) }, nil
		}},
		{"ServeByMasterIP to a group", func(t *testing.T, s *Server) (func(net.Listener) error, func() error) {
			g, err := NewGroup(s)
			if err != nil {
				t.Fatal(err)
			}
			return func(l net.Listener) error { return ServeByMasterIP(l, Route{Masters: route, Group: g}) }, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := newCallbackLog()
			srv, err := New(WithLogger(logs.logger()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = srv.Close() }()
			serve, closeAll := tc.setup(t, srv)
			l := newFailingListener(closeAll != nil)
			served := make(chan error, 1)
			go func() { served <- serve(l) }()
			<-l.accepts
			logs.wait(t, "net.Listener.Accept", "callbacks_test.go")
			<-l.accepts // asked again
			if closeAll == nil {
				_ = l.Close()
				if err := <-served; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ServeByMasterIP: %v, want net.ErrClosed", err)
				}
				return
			}
			if err := closeAll(); err != nil {
				t.Fatal(err)
			}
			logs.wait(t, "net.Listener.Close", "callbacks_test.go")
			if err := <-served; err != nil {
				t.Fatalf("Serve after Close: %v", err)
			}
		})
	}
}

// heldByCaller reports whether the goroutine that calls it holds mu: mu is
// taken on another goroutine, waited for for at most 5 s. A lock another
// goroutine holds for a moment is taken once that one lets go; a lock the
// caller holds while it waits is not, and the wait ends without it.
func heldByCaller(mu sync.Locker) bool {
	got := make(chan struct{})
	go func() {
		mu.Lock()
		close(got) // taken
		mu.Unlock()
	}()
	select {
	case <-got:
		return false
	case <-time.After(5 * time.Second):
		return true
	}
}

// TestFailuresLoggedAfterUnlock: a listener Close or a Database.Batch
// function that does not return normally is logged after the server, the
// group or the database released its lock, so that a logger that calls
// into them returns. The logger here takes the lock when it is called, on
// another goroutine and within a bounded wait.
func TestFailuresLoggedAfterUnlock(t *testing.T) {
	for _, tc := range []struct {
		name, callback string
		// run sets the lock the failure must not be logged under, then
		// makes the callback fail.
		run func(t *testing.T, srv *Server, lock func(func() bool))
	}{
		{"Server.Close", "net.Listener.Close", func(t *testing.T, srv *Server, lock func(func() bool)) {
			lock(func() bool { return heldByCaller(&srv.mu) })
			l := newFailingListener(true)
			served := make(chan error, 1)
			go func() { served <- srv.Serve(l) }()
			<-l.accepts
			<-l.accepts // Serve holds the listener
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatalf("Serve after Close: %v", err)
			}
		}},
		{"Group.Close", "net.Listener.Close", func(t *testing.T, srv *Server, lock func(func() bool)) {
			g, err := NewGroup(srv)
			if err != nil {
				t.Fatal(err)
			}
			lock(func() bool { return heldByCaller(&g.mu) })
			l := newFailingListener(true)
			served := make(chan error, 1)
			go func() { served <- g.Serve(l) }()
			<-l.accepts
			<-l.accepts
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatalf("Serve after Close: %v", err)
			}
		}},
		{"Database.Batch", "Database.Batch function", func(t *testing.T, srv *Server, lock func(func() bool)) {
			defer func() { _ = srv.Close() }()
			db := srv.Database()
			lock(func() bool { return heldByCaller(&db.mu) })
			if err := db.Batch(func(*Batch) error { panic("batch function of the application") }); err == nil {
				t.Fatal("Batch succeeded")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := newCallbackLog()
			var probe atomic.Pointer[func() bool]
			underLock := make(chan bool, 1)
			logs.onError = func(key string) {
				if p := probe.Load(); p != nil && key == tc.callback {
					underLock <- (*p)()
				}
			}
			srv, err := New(WithLogger(logs.logger()))
			if err != nil {
				t.Fatal(err)
			}
			tc.run(t, srv, func(f func() bool) { probe.Store(&f) })
			select {
			case h := <-underLock:
				if h {
					t.Fatalf("%s logged while the lock was held", tc.callback)
				}
			default:
				t.Fatalf("%s was not logged", tc.callback)
			}
		})
	}
}

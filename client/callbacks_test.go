// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// callbackLog is a slog.Handler that records the error entries of
// application code that did not return normally, by the callback named,
// each with its stack.
type callbackLog struct {
	mu    sync.Mutex
	stack map[string]string
	added chan struct{}
}

func newCallbackLog() *callbackLog {
	return &callbackLog{stack: map[string]string{}, added: make(chan struct{}, 1)}
}

func (h *callbackLog) option() Option { return WithLogger(dnp3.NewSlogLogger(h)) }

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

// wait waits until key was logged with a stack that passes through this
// file.
func (h *callbackLog) wait(t *testing.T, key string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		h.mu.Lock()
		stack, ok := h.stack[key]
		h.mu.Unlock()
		if ok {
			if !strings.Contains(stack, "callbacks_test.go") {
				t.Fatalf("%s logged without the stack of the callback:\n%s", key, stack)
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

// failingMetrics is a dnp3.Metrics, dnp3.RequestMetrics and
// dnp3.ClientMetrics none of whose callbacks returns normally.
type failingMetrics struct{}

func (failingMetrics) OnConnect(net.Addr)                              { panic("metrics") }
func (failingMetrics) OnDisconnect(net.Addr, error)                    { panic("metrics") }
func (failingMetrics) OnFrameSent(net.Addr, *link.Frame, int)          { panic("metrics") }
func (failingMetrics) OnFrameReceived(net.Addr, *link.Frame, int)      { panic("metrics") }
func (failingMetrics) OnFramingError(net.Addr, error)                  { panic("metrics") }
func (failingMetrics) OnFragmentSent(net.Addr, *app.Fragment, int)     { panic("metrics") }
func (failingMetrics) OnFragmentReceived(net.Addr, *app.Fragment, int) { panic("metrics") }
func (failingMetrics) OnDecodeError(net.Addr, error)                   { panic("metrics") }
func (failingMetrics) OnRequest(net.Addr, uint16, app.FunctionCode)    { panic("metrics") }
func (failingMetrics) OnRequestDone(net.Addr, uint16, app.FunctionCode, time.Duration, error) {
	panic("metrics")
}
func (failingMetrics) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) { panic("metrics") }
func (failingMetrics) OnTaskDropped(string)                                   { panic("metrics") }
func (failingMetrics) OnLateResponse(net.Addr, app.FunctionCode)              { panic("metrics") }

// TestClientMetricsThatDoNotReturnNormally: the master reads as usual when
// no callback of its metrics returns normally; each is logged with its
// stack.
func TestClientMetricsThatDoNotReturnNormally(t *testing.T) {
	logs := newCallbackLog()
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		n := req.f.Control.Seq
		return [][]byte{
			frag(ctl(false, true, false, n), app.FuncResponse, 0, event1), // discarded: OnLateResponse
			frag(ctl(true, true, false, n), app.FuncResponse, 0, event0),
		}
	})
	c := specDial(t, o, append(specQuiet, WithMetrics(failingMetrics{}), logs.option())...)
	for range 2 {
		if res, err := c.Read(testCtx(t), app.ClassHeaders(1)...); err != nil || len(res.Fragments) != 1 {
			t.Fatalf("read: %v %v", res, err)
		}
	}
	for _, cb := range []string{"Metrics.OnConnect", "Metrics.OnFrameSent", "Metrics.OnFrameReceived",
		"Metrics.OnFragmentSent", "Metrics.OnFragmentReceived", "RequestMetrics.OnRequest",
		"RequestMetrics.OnRequestDone", "ClientMetrics.OnLateResponse"} {
		logs.wait(t, cb)
	}
}

// TestStateHandlerAtClose: a state handler that does not return normally
// when Close reports the client disconnected, on the caller's goroutine, is
// logged with its stack and Close returns.
func TestStateHandlerAtClose(t *testing.T) {
	logs := newCallbackLog()
	c, _ := pipeClient(t, nil, logs.option(), WithStateHandler(func(s dnp3.State, _ error) {
		if s == dnp3.StateDisconnected {
			panic("state handler of the application")
		}
	}))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	logs.wait(t, "state handler")
	if s := c.State(); s != dnp3.StateDisconnected {
		t.Fatalf("state %v after Close", s)
	}
}

// TestConnectCallbacksThatDoNotReturnNormally: a Dialer, a StreamOpener, a
// listener of Accept or a tls.Config callback of the application that does
// not return normally fails the attempt to connect as an error of it does;
// it is logged with its stack, through the client's logger.
func TestConnectCallbacksThatDoNotReturnNormally(t *testing.T) {
	for _, tc := range []struct {
		callback string
		opts     func(t *testing.T) (addr string, opts []Option)
	}{
		{"Dialer.DialContext", func(*testing.T) (string, []Option) {
			return "192.0.2.1:20000", []Option{WithDialer(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
				panic("dialer of the application")
			}))}
		}},
		{"StreamOpener", func(*testing.T) (string, []Option) {
			return "outstation", []Option{WithStream(func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
				panic("opener of the application")
			})}
		}},
		{"net.Listener.Accept", func(t *testing.T) (string, []Option) {
			l := newFailingListener(false)
			t.Cleanup(func() { _ = l.Close() })
			return "outstation", []Option{WithStream(Accept(l))}
		}},
		{"TLS handshake", func(t *testing.T) (string, []Option) {
			l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			go func() {
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					_ = conn.(*tls.Conn).Handshake()
					_ = conn.Close()
				}
			}()
			return l.Addr().String(), []Option{WithTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
				VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { panic("VerifyPeerCertificate of the application") }})}
		}},
	} {
		t.Run(tc.callback, func(t *testing.T) {
			logs := newCallbackLog()
			addr, opts := tc.opts(t)
			c, err := New(addr, quiet(append(opts, logs.option())...)...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			err = c.Connect(testCtx(t))
			var ce *logx.CallbackError
			if !errors.Is(err, dnp3.ErrConnectFailed) || !errors.As(err, &ce) || ce.Callback != tc.callback {
				t.Fatalf("Connect: %v, want ErrConnectFailed by %s", err, tc.callback)
			}
			logs.wait(t, tc.callback)
		})
	}
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

// TestDualEndpointCallbacksThatDoNotReturnNormally: the listener, allow and
// tls.Config of WithDualEndpoint are the application's. An Accept that does
// not return normally is an Accept error, after which the listener is
// asked again; an allow that does not refuses the connection; a handshake
// that does not fails it, and the connection is closed; a Close that does
// not is logged and Close returns. Each is logged with its stack.
func TestDualEndpointCallbacksThatDoNotReturnNormally(t *testing.T) {
	t.Run("net.Listener", func(t *testing.T) {
		logs := newCallbackLog()
		l := newFailingListener(true)
		c, err := New("192.0.2.1:20000", quiet(WithDualEndpoint(l, nil), logs.option())...)
		if err != nil {
			t.Fatal(err)
		}
		startAccept(c)
		<-l.accepts
		logs.wait(t, "net.Listener.Accept")
		<-l.accepts // asked again
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		logs.wait(t, "net.Listener.Close")
	})
	for _, tc := range []struct {
		callback string
		listener func(l net.Listener) net.Listener
		allow    func(net.Addr) bool
		dial     func(addr string) (net.Conn, error)
	}{
		{"WithDualEndpoint allow", func(l net.Listener) net.Listener { return l }, func(net.Addr) bool { panic("allow of the application") },
			func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }},
		{"TLS handshake", func(l net.Listener) net.Listener {
			return tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				panic("GetCertificate of the application")
			}})
		}, nil, func(addr string) (net.Conn, error) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
			if err == nil {
				_ = conn.Close()
				return nil, errors.New("handshake succeeded")
			}
			return net.Dial("tcp", addr) // the handshake failed; the next connection
		}},
	} {
		t.Run(tc.callback, func(t *testing.T) {
			logs := newCallbackLog()
			l := listenTCP(t)
			c, err := New(deadAddr(t), quiet(WithDualEndpoint(tc.listener(l), tc.allow), logs.option())...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrConnectFailed) {
				t.Fatalf("Connect to nobody: %v", err)
			}
			conn, err := tc.dial(l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			logs.wait(t, tc.callback)
			if tc.allow != nil {
				expectEOF(t, conn)
			}
			if s := c.State(); s == dnp3.StateConnected {
				t.Fatalf("connected over a connection refused by %s", tc.callback)
			}
		})
	}
}

// unreturnedWriter is an io.Writer of the application that does not return
// normally.
type unreturnedWriter struct{}

func (unreturnedWriter) Write([]byte) (int, error) { panic("writer of the application") }

// unreturnedReader is an io.Reader of the application that does not return
// normally after its first n octets.
type unreturnedReader struct{ n int }

func (r *unreturnedReader) Read(b []byte) (int, error) {
	if r.n == 0 {
		panic("reader of the application")
	}
	m := min(len(b), r.n)
	r.n -= m
	return m, nil
}

// TestFileTransferCallbacksThatDoNotReturnNormally: the writer of ReadFile
// and the reader of WriteFile are the application's. One that does not
// return normally fails the transfer, which is aborted, as one that fails
// does; it is logged with its stack, and the next transfer goes through.
func TestFileTransferCallbacksThatDoNotReturnNormally(t *testing.T) {
	logs := newCallbackLog()
	data := bytes.Repeat([]byte("file "), 200)
	fs := &files{m: map[string][]byte{"/f": data}}
	_, addr := outstation(t, server.WithFileServer(fs))
	c, err := Dial(testCtx(t), addr, WithAutoIntegrity(false), logs.option())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx := testCtx(t)
	var ce *logx.CallbackError
	if _, err := c.ReadFile(ctx, "/f", unreturnedWriter{}, FileOptions{MaxBlockSize: 256}); !errors.As(err, &ce) || ce.Callback != "io.Writer of ReadFile" {
		t.Fatalf("ReadFile: %v, want the CallbackError of the writer", err)
	}
	logs.wait(t, "io.Writer of ReadFile")
	if _, err := c.WriteFile(ctx, "/up", &unreturnedReader{n: 300}, 600, FileOptions{MaxBlockSize: 256}); !errors.As(err, &ce) || ce.Callback != "io.Reader of WriteFile" {
		t.Fatalf("WriteFile: %v, want the CallbackError of the reader", err)
	}
	logs.wait(t, "io.Reader of WriteFile")
	if got := fs.get("/up"); got != nil {
		t.Fatalf("the aborted transfer stored %d octets", len(got))
	}
	var buf bytes.Buffer
	if n, err := c.ReadFile(ctx, "/f", &buf, FileOptions{MaxBlockSize: 256}); err != nil || !bytes.Equal(buf.Bytes(), data) {
		t.Fatalf("ReadFile after them: %d %v", n, err)
	}
}

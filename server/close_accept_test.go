package server

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// closingListener's Accept waits until the listener is closed and then
// returns conn, once: a connection accepted as Close closes the listeners.
type closingListener struct {
	conn      net.Conn
	accepting chan struct{}
	closed    chan struct{}
	once      sync.Once
	taken     atomic.Bool
}

func newClosingListener(conn net.Conn) *closingListener {
	return &closingListener{conn: conn, accepting: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (l *closingListener) Accept() (net.Conn, error) {
	select {
	case l.accepting <- struct{}{}:
	default:
	}
	<-l.closed
	if l.taken.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	return nil, net.ErrClosed
}

func (l *closingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *closingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: DefaultPort}
}

// closerConn records the stack of the goroutine that closes it.
type closerConn struct {
	net.Conn
	once   sync.Once
	closed chan string
}

func newCloserConn(t *testing.T) *closerConn {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	return &closerConn{Conn: a, closed: make(chan string, 1)}
}

func (c *closerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func (c *closerConn) Close() error {
	c.once.Do(func() {
		buf := make([]byte, 1<<14)
		c.closed <- string(buf[:runtime.Stack(buf, false)])
	})
	return c.Conn.Close()
}

// TestCloseServesNoConnectionAcceptedMeanwhile: a connection that Accept
// returns once Close has closed the listener is closed by Serve, which
// then returns nil; it is not handed to a goroutine. Such a goroutine
// would start while Close waits for the server's goroutines, or after it
// returned: an Add from zero concurrent with Wait, which sync.WaitGroup
// forbids and the race detector reported.
func TestCloseServesNoConnectionAcceptedMeanwhile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		serve func(t *testing.T, l net.Listener) (serve func() error, close func() error)
	}{
		{"server", func(t *testing.T, l net.Listener) (func() error, func() error) {
			s, err := New()
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return s.Serve(l) }, s.Close
		}},
		{"group", func(t *testing.T, l net.Listener) (func() error, func() error) {
			s, err := New()
			if err != nil {
				t.Fatal(err)
			}
			g, err := NewGroup(s)
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return g.Serve(l) }, g.Close
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newCloserConn(t)
			l := newClosingListener(conn)
			serve, closeFn := tc.serve(t, l)
			served := make(chan error, 1)
			go func() { served <- serve() }()
			<-l.accepting
			if err := closeFn(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-served:
				if err != nil {
					t.Fatalf("Serve: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Serve did not return after Close")
			}
			select {
			case stack := <-conn.closed:
				if !strings.Contains(stack, ".Serve(") || strings.Contains(stack, ".Serve.func") {
					t.Fatalf("the connection was not closed by Serve itself:\n%s", stack)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the connection accepted during Close was not closed")
			}
		})
	}
}

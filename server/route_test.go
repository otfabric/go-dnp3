// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
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

// TestServeByMasterIPRefusals: ServeByMasterIP refuses a connection as the
// target's own Serve would, for a Server and for a Group: a closed target,
// an address outside the target's WithMasterIPs, a full connection limit
// and a failed TLS handshake close the connection without an answer, and
// the target's other connections go on. A TLS connection that completes
// its handshake is served; an Accept error is retried.
func TestServeByMasterIPRefusals(t *testing.T) {
	lp := netip.MustParsePrefix
	listen := func(t *testing.T) net.Listener {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	serve := func(t *testing.T, l net.Listener, routes ...Route) string {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- ServeByMasterIP(l, routes...) }()
		t.Cleanup(func() {
			_ = l.Close()
			if err := <-done; !errors.Is(err, net.ErrClosed) {
				t.Errorf("ServeByMasterIP after Close: %v", err)
			}
		})
		return l.Addr().String()
	}
	// refused dials addr, sends a link status request when speak is set,
	// and expects the connection closed without a frame.
	refused := func(t *testing.T, addr string, speak bool) {
		t.Helper()
		p := dialRaw(t, "tcp", addr)
		if speak {
			p.write(rls(10))
		}
		if fs := p.closed(); len(fs) != 0 {
			t.Fatalf("a refused connection got %v", fs)
		}
	}
	for _, kind := range []string{"server", "group"} {
		route := func(t *testing.T, opts ...Option) Route {
			t.Helper()
			opts = append([]Option{WithAddress(10), WithMasters(1)}, opts...)
			r := Route{Masters: lp("127.0.0.0/8")}
			if kind == "server" {
				r.Server = newServer(t, opts...)
				return r
			}
			g, err := NewGroup(newServer(t, opts...))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = g.Close() })
			r.Group = g
			return r
		}
		t.Run(kind+"/closed", func(t *testing.T) {
			r := route(t)
			if r.Server != nil {
				_ = r.Server.Close()
			} else {
				_ = r.Group.Close()
			}
			refused(t, serve(t, listen(t), r), false)
		})
		t.Run(kind+"/master IP", func(t *testing.T) {
			refused(t, serve(t, listen(t), route(t, WithMasterIPs(lp("192.0.2.0/24")))), false)
		})
		t.Run(kind+"/limit", func(t *testing.T) {
			addr := serve(t, listen(t), route(t, WithMaxConnections(1)))
			p := dialRaw(t, "tcp", addr)
			p.write(rls(10))
			p.linkStatus(10)
			refused(t, addr, false)
			p.write(rls(10))
			p.linkStatus(10)
		})
		t.Run(kind+"/TLS", func(t *testing.T) {
			cert := selfSignedCert(t)
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			addr := serve(t, tls.NewListener(listen(t), cfg), route(t))
			// Link frames instead of a ClientHello: the handshake fails.
			refused(t, addr, true)

			pool := x509.NewCertPool()
			pool.AddCert(cert.Leaf)
			conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			p := &rawMaster{t: t, conn: conn, r: link.NewReader(conn), ra: transport.NewReassembler(0)}
			p.write(rls(10))
			p.linkStatus(10)
		})
	}
	t.Run("accept error", func(t *testing.T) {
		l := &onceFailingListener{Listener: listen(t)}
		addr := serve(t, l, Route{Masters: lp("127.0.0.0/8"), Server: newServer(t, WithMasters(1))})
		p := dialRaw(t, "tcp", addr)
		p.write(rls(10))
		p.linkStatus(10)
		if !l.failed.Load() {
			t.Fatal("the failing Accept was not called")
		}
	})
}

// SPDX-License-Identifier: MIT

package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"

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

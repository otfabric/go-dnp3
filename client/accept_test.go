// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/server"
)

// TestAcceptOverTLS: the outstation establishes a TLS connection to the
// master, which is the TLS server of it.
func TestAcceptOverTLS(t *testing.T) {
	cert := selfSigned(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	srv, err := server.New(server.WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	go func() {
		_ = srv.DialAndServe(context.Background(), l.Addr().String(), server.Redial{MinDelay: 10 * time.Millisecond})
	}()
	defer func() { _ = srv.Close() }()

	c, err := Dial(testCtx(t), "outstation", WithStream(Accept(tl)), WithAutoIntegrity(false),
		WithReconnect(Reconnect{MinDelay: 10 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("read over the outstation's TLS connection: %v %v", res, err)
	}
	// Without the outstation, the client waits for its next connection:
	// Close ends that wait at once.
	_ = srv.Close()
	waitFor(t, "the lost connection", func() bool { return c.State() != dnp3.StateConnected })
	start := time.Now()
	_ = c.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Close while waiting for a connection took %v", d)
	}
	// An Accept whose context ends, on a listener nobody dials.
	idle, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := Accept(idle)(ctx); err == nil {
		t.Fatal("Accept returned without a connection")
	}
	_ = idle.Close()
	if _, _, err := Accept(idle)(context.Background()); err == nil {
		t.Fatal("Accept on a closed listener")
	}
}

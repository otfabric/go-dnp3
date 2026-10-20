// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestDialAndServe: connections the outstation establishes are redialled
// when they end or fail, until the context ends.
func TestDialAndServe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	// A "master" that hangs up every connection at once.
	var accepted atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	srv, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.DialAndServe(ctx, l.Addr().String(), Redial{MinDelay: 5 * time.Millisecond, MaxDelay: time.Millisecond})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for accepted.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if accepted.Load() < 3 {
		t.Fatalf("%d connections, want redials", accepted.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("after cancel: %v", err)
	}

	// TLS: a handshake with a peer that is not TLS fails, and the
	// outstation retries until the context ends.
	tsrv, err := New(WithTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tsrv.Close() }()
	tctx, tcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer tcancel()
	if err := tsrv.DialAndServe(tctx, l.Addr().String(), Redial{MinDelay: 5 * time.Millisecond}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TLS to a peer without TLS: %v", err)
	}
	// A closed server returns nil at once.
	_ = tsrv.Close()
	if err := tsrv.DialAndServe(context.Background(), l.Addr().String(), Redial{}); err != nil {
		t.Fatalf("closed server: %v", err)
	}
}

// TestDialAndServeEnds: Close ends DialAndServe while it waits to redial
// and while it serves; a context that ends closes the connection served.
func TestDialAndServeEnds(t *testing.T) {
	// Nothing listens: the dial fails and DialAndServe waits.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.Addr().String()
	_ = dead.Close()
	srv, err := New()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.DialAndServe(context.Background(), addr, Redial{MinDelay: time.Minute}) }()
	time.Sleep(50 * time.Millisecond)
	_ = srv.Close()
	if err := <-done; err != nil {
		t.Fatalf("Close while waiting to redial: %v", err)
	}

	// A master that keeps the connection open.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	for _, viaCtx := range []bool{false, true} {
		srv, err := New()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { done <- srv.DialAndServe(ctx, l.Addr().String(), Redial{}) }()
		deadline := time.Now().Add(5 * time.Second)
		for srv.connections() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if viaCtx {
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel while serving: %v", err)
			}
		} else {
			_ = srv.Close()
			if err := <-done; err != nil {
				t.Fatalf("Close while serving: %v", err)
			}
		}
		cancel()
		_ = srv.Close()
	}
}

// TestDialAndServeTLS: with WithTLS the outstation is the TLS client and
// verifies the master's certificate for the host it dials.
func TestDialAndServeTLS(t *testing.T) {
	cert := selfSignedCert(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		// The handshake completes on the first read.
		_ = c.(*tls.Conn).Handshake()
		accepted <- c
	}()
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	srv, err := New(WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.DialAndServe(context.Background(), l.Addr().String(), Redial{}) }()
	select {
	case c := <-accepted:
		defer func() { _ = c.Close() }()
	case <-time.After(5 * time.Second):
		t.Fatal("no TLS connection from the outstation")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

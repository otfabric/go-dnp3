// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
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

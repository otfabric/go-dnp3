// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// TestDualEndPoint: the outstation establishes the connection; the master
// waits for it, and both recover when it is lost.
func TestDualEndPoint(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	srv, err := server.New()
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- srv.DialAndServe(ctx, l.Addr().String(), server.Redial{MinDelay: 20 * time.Millisecond, MaxDelay: 50 * time.Millisecond})
	}()

	c, err := client.New("outstation", client.WithStream(client.Accept(l)), client.WithAutoIntegrity(false),
		client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	if err := c.Connect(rctx); err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		var err error
		for range 100 {
			var res *client.Result
			if res, err = c.Read(rctx, app.AllObjects(app.G1V0)); err == nil {
				if len(res.Measurements()) != 1 {
					t.Fatalf("read over the outstation's connection: %v", res.Measurements())
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("read over the outstation's connection: %v", err)
	}
	read()
	// The connection is lost: the outstation dials again, the master
	// takes the new connection.
	srv.CloseConnections()
	read()

	cancel()
	select {
	case err := <-served:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialAndServe after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialAndServe did not return after cancel")
	}
	// After Close it returns nil, also while it waits to redial.
	go func() { served <- srv.DialAndServe(context.Background(), "127.0.0.1:1", server.Redial{}) }()
	time.Sleep(50 * time.Millisecond)
	_ = srv.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("DialAndServe after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialAndServe did not return after Close")
	}
	// Closing the master while it waits for the next connection returns
	// at once.
	start := time.Now()
	_ = c.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Close while waiting for the outstation took %v", d)
	}
	// A master whose context ends while it waits for the outstation.
	wctx, wcancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer wcancel()
	if _, _, err := client.Accept(l)(wctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Accept after its context ended: %v", err)
	}
}

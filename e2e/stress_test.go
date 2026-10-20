// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// TestConcurrentRequests issues many requests from one client at once.
// DNP3 allows one outstanding request, so the client serialises them; all
// must succeed and none interleave.
func TestConcurrentRequests(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(&relay{})}, client.WithQueueLimit(256))
	var wg sync.WaitGroup
	var fail atomic.Int64
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var err error
			switch i % 4 {
			case 0:
				_, err = p.c.IntegrityPoll(ctx)
			case 1:
				_, err = p.c.Read(ctx, app.AllObjects(app.G30V1))
			case 2:
				_, err = p.c.Operate(ctx, client.DirectOperate, client.CROB(1, app.OpLatchOn, 0, 0))
			case 3:
				_, err = p.c.EventPoll(ctx)
			}
			if err != nil {
				fail.Add(1)
				t.Errorf("request %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("%d requests failed", fail.Load())
	}
}

// TestManyMasters connects many masters to one outstation and polls from
// all of them while the database is updated; each master's events are
// independent.
func TestManyMasters(t *testing.T) {
	const masters = 8
	addrs := make([]link.Address, masters)
	for i := range addrs {
		addrs[i] = link.Address(1 + i)
	}
	srv, err := server.New(server.WithMasters(addrs...))
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// A writer updating points throughout.
	go func() {
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = srv.Database().UpdateAnalogInput(0, app.Analog{Value: float64(n), Flags: app.FlagOnline})
				n++
			}
		}
	}()

	errs := make(chan error, masters)
	for i := range masters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, err := client.Dial(ctx, l.Addr().String(),
				client.WithAddresses(addrs[i], 10),
				client.WithResponseTimeout(3*time.Second), client.WithAutoIntegrity(false))
			if err != nil {
				errs <- fmt.Errorf("master %d dial: %w", i, err)
				return
			}
			defer func() { _ = c.Close() }()
			for range 20 {
				if _, err := c.IntegrityPoll(ctx); err != nil {
					errs <- fmt.Errorf("master %d poll: %w", i, err)
					return
				}
				if _, err := c.EventPoll(ctx); err != nil {
					errs <- fmt.Errorf("master %d event poll: %w", i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestReconnect drops the connection repeatedly and checks the client
// re-establishes it and keeps working.
func TestReconnect(t *testing.T) {
	srv, err := server.New(server.WithMasters(1))
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	var states atomic.Int64
	c, err := client.Dial(ctx(t), l.Addr().String(),
		client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 100 * time.Millisecond}),
		client.WithResponseTimeout(2*time.Second),
		client.WithStateHandler(func(s dnp3.State, err error) {
			if s == dnp3.StateConnected {
				states.Add(1)
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	for range 3 {
		if _, err := c.IntegrityPoll(ctx(t)); err != nil {
			t.Fatal(err)
		}
		// Drop every outstation connection; the client reconnects.
		srv.CloseConnections()
		waitUntil(t, "reconnect", func() bool {
			_, err := c.IntegrityPoll(ctx(t))
			return err == nil
		})
	}
	if states.Load() < 2 {
		t.Fatalf("only %d connects observed", states.Load())
	}
}

// TestRapidOpenClose opens and closes clients quickly to surface leaks or
// races in connection teardown.
func TestRapidOpenClose(t *testing.T) {
	masters := make([]link.Address, 24)
	for i := range masters {
		masters[i] = link.Address(1 + i)
	}
	srv, err := server.New(server.WithMasters(masters...), server.WithMaxConnections(64))
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := client.Dial(ctx, l.Addr().String(), client.WithAddresses(masters[i], 10), client.WithResponseTimeout(2*time.Second))
			if err != nil {
				return
			}
			_, _ = c.IntegrityPoll(ctx)
			_ = c.Close()
		}()
	}
	wg.Wait()
	// A fresh client still works.
	c, err := client.Dial(ctx(t), l.Addr().String(), client.WithAddresses(1, 10), client.WithResponseTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.IntegrityPoll(ctx(t)); err != nil {
		t.Fatal(err)
	}
}

// TestContextCancellation cancels requests mid-flight; the client must
// return promptly and stay usable.
func TestContextCancellation(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	for range 20 {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Millisecond)
			cancel()
		}()
		_, err := p.c.IntegrityPoll(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, dnp3.ErrTimeout) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// Still usable.
	if _, err := p.c.IntegrityPoll(ctx(t)); err != nil {
		t.Fatal(err)
	}
}

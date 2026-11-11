// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/secauth"
)

// A reconnect whose session key change failed while the channel was lost
// took that for a failed dial and went on dialling, next to the reconnect of
// the lost channel. An outstation serves one connection per master, so each
// dial closed the other's: the reconnects fed each other after the faults
// had stopped.
func TestOneReconnectAfterStartupFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	var dials atomic.Int64
	var breaking atomic.Bool
	breaking.Store(true)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	var last net.Conn
	defer func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Go(func() {
				if breaking.Load() {
					// The key change goes out, and the connection breaks.
					_, _ = conn.Read(make([]byte, 1))
					_ = conn.Close()
					return
				}
				// One connection per master: this one takes the place of
				// the last.
				mu.Lock()
				if last != nil {
					_ = last.Close()
				}
				last = conn
				mu.Unlock()
				_, _ = io.Copy(io.Discard, conn)
			})
		}
	})

	user := secauth.User{Number: 1, UpdateKey: []byte("0123456789abcdef")}
	c, err := New(l.Addr().String(),
		WithSecureAuthentication(user),
		WithAutoIntegrity(false),
		WithResponseTimeout(30*time.Millisecond),
		WithRetry(Retry{Attempts: 3, Backoff: time.Millisecond}),
		WithReconnect(Reconnect{MinDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The client comes up as a reconnect does: this test has no outstation
	// that completes the Connect.
	c.mu.Lock()
	c.dialing = true
	c.mu.Unlock()
	c.wg.Go(func() {
		c.reconnectLoop()
	})

	time.Sleep(300 * time.Millisecond)
	breaking.Store(false)
	time.Sleep(200 * time.Millisecond)
	before := dials.Load()
	time.Sleep(500 * time.Millisecond)
	if n := dials.Load() - before; n > 0 {
		t.Errorf("%d more connections once the outstation kept them", n)
	}
}

// A Connect whose channel broke during the startup sequence returned the
// error and left the client disconnected, while the watch of that channel
// had started a reconnect: the next Connect then dialled next to it, and
// the connection one of them installed replaced the other's without
// closing it. That orphan went on answering link status requests, so an
// outstation that keeps the connection of a connected master (IEEE
// 1815-2012 clause 13.2.3.3) refused every later one. A failed Connect
// leaves no reconnect behind.
func TestFailedConnectDoesNotReconnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	var wg sync.WaitGroup
	defer func() {
		_ = l.Close()
		wg.Wait()
	}()
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			wg.Go(func() {
				// The startup integrity poll goes out, and the connection
				// breaks.
				_, _ = conn.Read(make([]byte, 1))
				_ = conn.Close()
			})
		}
	})

	c, err := New(l.Addr().String(),
		WithResponseTimeout(time.Second),
		WithReconnect(Reconnect{MinDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err == nil {
		t.Fatal("Connect succeeded over a connection that broke during its startup")
	}
	time.Sleep(300 * time.Millisecond)
	if n := dials.Load(); n != 1 {
		t.Errorf("%d connections after one failed Connect, want 1", n)
	}
	if s := c.State(); s != dnp3.StateDisconnected {
		t.Errorf("state %v after a failed Connect, want disconnected", s)
	}
	c.mu.Lock()
	dialing := c.dialing
	c.mu.Unlock()
	if dialing {
		t.Error("the client is dialing after a failed Connect")
	}
}

// connect never installs a second channel next to one that is open: the
// new one is closed and the attempt fails with dnp3.ErrBusy.
func TestConnectKeepsTheOpenChannel(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedByClient := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		_ = l.Close()
		wg.Wait()
	}()
	wg.Go(func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		close(closedByClient)
	})

	c, err := New(l.Addr().String(), WithStartup(Startup{}), WithTimeSync(TimeSyncNone))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	open := channel.New(a, channel.Config{})
	c.mu.Lock()
	c.ch = open
	c.dialing = true
	c.mu.Unlock()

	ch, err := c.connect(context.Background(), false)
	if !errors.Is(err, dnp3.ErrBusy) || ch != nil {
		t.Fatalf("connect next to an open channel: %v, %v; want ErrBusy", ch, err)
	}
	c.mu.Lock()
	kept := c.ch == open
	c.ch = nil
	c.mu.Unlock()
	if !kept {
		t.Error("the open channel was replaced")
	}
	open.Close(nil)
	select {
	case <-closedByClient:
	case <-time.After(5 * time.Second):
		t.Error("the new connection was left open")
	}
}

// SPDX-License-Identifier: MIT

package client

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

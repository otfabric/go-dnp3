// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// dropFirst is a proxy that, once armed, drops the first link frame from
// the outstation carrying an AUTHENTICATE_RESP.
func dropFirst(t *testing.T, target string, armed *atomic.Bool) string {
	t.Helper()
	var dropped atomic.Bool
	return authDropper(t, target, func() bool { return armed.Load() && dropped.CompareAndSwap(false, true) })
}

// authDropper is a proxy that drops each link frame from the outstation
// carrying an AUTHENTICATE_RESP for which drop returns true.
func authDropper(t *testing.T, target string, drop func() bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				return
			}
			go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
			go func() {
				defer func() { _ = in.Close() }()
				r := link.NewReader(out)
				for {
					f, err := r.ReadFrame()
					if err != nil {
						return
					}
					// Transport header, application control, function.
					if len(f.Data) >= 3 && app.FunctionCode(f.Data[2]) == app.FuncAuthResponse && drop() {
						continue
					}
					b, _ := f.Encode()
					if _, err := in.Write(b); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// TestRekeyAfterFailedKeyChange: a reconnection whose key change fails
// stays up without session keys; the client changes them again soon, not
// at the key change interval, and controls work again. A Connect whose
// key change fails leaves the client disconnected.
func TestRekeyAfterFailedKeyChange(t *testing.T) {
	user := secauth.User{Number: 1, UpdateKey: testUpdateKey}
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	srv, addr := outstation(t, server.WithHandler(accept), server.WithSecureAuthentication(server.SecureAuth{User: user}))
	var armed atomic.Bool
	opts := []Option{WithSecureAuthentication(user), WithKeyChangeInterval(time.Hour),
		WithResponseTimeout(300 * time.Millisecond), WithAutoIntegrity(false), WithAutoClearRestart(false),
		WithReconnect(Reconnect{MinDelay: 10 * time.Millisecond})}

	armed.Store(true)
	failing, err := New(dropFirst(t, addr, &armed), opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = failing.Close() }()
	if err := failing.Connect(testCtx(t)); err == nil {
		t.Fatal("Connect succeeded although the key status was lost")
	}
	if failing.State() != dnp3.StateDisconnected {
		t.Fatalf("after a failed Connect: %s", failing.State())
	}
	if _, err := failing.Read(testCtx(t), app.AllObjects(app.G1V0)); !errors.Is(err, dnp3.ErrNotConnected) {
		t.Fatalf("request after a failed Connect: %v", err)
	}

	var again atomic.Bool
	var connects atomic.Int64
	c, err := New(dropFirst(t, addr, &again), append(opts, WithStateHandler(func(s dnp3.State, _ error) {
		if s == dnp3.StateConnected {
			connects.Add(1)
		}
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	again.Store(true)
	srv.CloseConnections()
	// The new connection's key change loses its answer; the keys come
	// within the retry delay.
	waitFor(t, "the reconnection", func() bool { return connects.Load() >= 2 })
	waitFor(t, "session keys after a failed key change", func() bool { return c.controlKey() != nil })
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("control after the retried key change: %v", err)
	}
}

// keyStatusDropper is a proxy that drops the n-th key status request
// (AUTHENTICATE_REQ with g120v4) the master sends.
func keyStatusDropper(t *testing.T, target string, n int64) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var seen atomic.Int64
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				return
			}
			go func() { _, _ = io.Copy(in, out); _ = in.Close() }()
			go func() {
				defer func() { _ = out.Close() }()
				r := link.NewReader(in)
				for {
					f, err := r.ReadFrame()
					if err != nil {
						return
					}
					// Transport header, application control, function,
					// object group and variation.
					d := f.Data
					if len(d) >= 5 && app.FunctionCode(d[2]) == app.FuncAuthRequest && d[3] == 120 && d[4] == 4 && seen.Add(1) == n {
						continue
					}
					b, _ := f.Encode()
					if _, err := out.Write(b); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// TestKeyChangeCountRetried: IEEE 1815-2012 clause 7.6.1.4.4: the master
// changes the session keys once the key change count is reached. When
// that key change fails (its key status request is lost), the change
// stays due: it is tried again, also without a key change interval, and
// the next one succeeds.
func TestKeyChangeCountRetried(t *testing.T) {
	user := secauth.User{Number: 1, UpdateKey: testUpdateKey}
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept), server.WithSecureAuthentication(server.SecureAuth{User: user}))
	// The first key status request is the connection's; the second the
	// count's.
	c, err := Dial(testCtx(t), keyStatusDropper(t, addr, 2), quiet(WithSecureAuthentication(user), WithKeyChangeInterval(0),
		WithKeyChangeCount(3), WithResponseTimeout(300*time.Millisecond))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// A challenge and its reply are two messages: the second control's
	// challenge is the third.
	for range 2 {
		if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the key change of the count to fail", func() bool {
		return c.SecurityStatistics()[secauth.StatFailedSessionKeyChanges] == 1
	})
	waitFor(t, "the key change of the count to be retried", func() bool {
		return c.SecurityStatistics()[secauth.StatSessionKeyChanges] == 2
	})
	if c.keyChangeDue() {
		t.Fatal("key change still due after it succeeded")
	}
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("control with the new session keys: %v", err)
	}
}

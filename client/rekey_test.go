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

// TestSpecTable7_13_CriticalNotSentWithoutKeys: IEEE 1815-2012 Table 7-13
// row 7 (p.232): a master without valid session keys discards a
// challenge; Table 7-8 row 16 (p.219): an outstation waiting for a reply
// discards a key status request. A critical request sent without keys
// could only fail, and would keep the outstation waiting for the reply
// while the master tries to change the keys: requests sent again at once
// then kept the keys from ever being changed (found by TestChaos). It
// fails at once, unsent, and asks for the key change; a non-critical
// request goes on (clause 7.3.6). The controls repeated meanwhile do not
// keep the keys away.
func TestSpecTable7_13_CriticalNotSentWithoutKeys(t *testing.T) {
	user := secauth.User{Number: 1, UpdateKey: testUpdateKey}
	var executed atomic.Int64
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus {
		executed.Add(1)
		return app.StatusSuccess
	})
	srv, addr := outstation(t, server.WithHandler(accept), server.WithSecureAuthentication(server.SecureAuth{User: user}))
	var lose atomic.Bool
	sent := &sentRecorder{}
	c, err := New(authDropper(t, addr, lose.Load), quiet(WithSecureAuthentication(user), WithKeyChangeInterval(time.Hour),
		WithResponseTimeout(300*time.Millisecond), WithReconnect(Reconnect{MinDelay: 10 * time.Millisecond}), WithMetrics(sent))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	// The reconnection's key change loses every answer: it stays up
	// without session keys (TestRekeyAfterFailedKeyChange).
	lose.Store(true)
	before := len(sent.aggressive(app.FuncDirectOperate))
	srv.CloseConnections()
	waitFor(t, "the reconnection without session keys", func() bool {
		return c.State() == dnp3.StateConnected && c.controlKey() == nil &&
			c.SecurityStatistics()[secauth.StatFailedSessionKeyChanges] >= 1
	})
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("control without session keys: %v", err)
	}
	if n := len(sent.aggressive(app.FuncDirectOperate)); n != before {
		t.Fatalf("%d controls sent without session keys", n-before)
	}
	if _, err := c.Read(testCtx(t), app.AllObjects(app.G1V0)); err != nil {
		t.Fatalf("non-critical read without session keys: %v", err)
	}

	lose.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(testCtx(t), 2*time.Second)
		_, err := c.Operate(ctx, DirectOperate, CROB(0, app.OpLatchOn, 0, 0))
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no control within 5 s of the answers coming through: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if executed.Load() != 1 {
		t.Fatalf("%d controls executed, want 1", executed.Load())
	}
}

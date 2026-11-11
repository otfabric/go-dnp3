// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// TestWithOnlineOtherValue: withOnline sets the flags of the four point
// types whose variations without flags report ONLINE (IEEE 1815-2012
// Table 11-5 NOTE 2) and leaves any other value as it is.
func TestWithOnlineOtherValue(t *testing.T) {
	v := app.AnalogDeadband{Value: 7}
	if got := withOnline(v); got != v {
		t.Fatalf("withOnline changed %v to %v", v, got)
	}
}

// TestMaxWriteBlockAggressive: with WithMaxRequestFragment a file block
// leaves room for the WRITE around it and, when WRITE goes in aggressive
// mode, for the objects of secure authentication as well.
func TestMaxWriteBlockAggressive(t *testing.T) {
	const lim = 300
	for _, tc := range []struct {
		name string
		opts []Option
		want int
	}{
		{"no limit", nil, 0},
		{"limit", []Option{WithMaxRequestFragment(lim)}, lim - writeOverhead},
		{"limit and aggressive WRITE", []Option{WithMaxRequestFragment(lim),
			WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}), WithAggressiveMode(app.FuncWrite)},
			lim - writeOverhead - secauth.AggressiveOverhead},
		{"limit and aggressive OPERATE only", []Option{WithMaxRequestFragment(lim),
			WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}), WithAggressiveMode(app.FuncOperate)},
			lim - writeOverhead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New("127.0.0.1", tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if got := c.maxWriteBlock(); got != tc.want {
				t.Fatalf("block %d, want %d", got, tc.want)
			}
		})
	}
}

// TestUDPFromDialFails: UDPFrom reports a remote address it cannot dial.
func TestUDPFromDialFails(t *testing.T) {
	if _, _, err := UDPFrom("127.0.0.1:0", "127.0.0.1:no-port")(testCtx(t)); err == nil {
		t.Fatal("dialed a remote address without a port number")
	}
}

// TestConnectClosedWhileDialing: a client closed while its stream opens
// does not start a channel on it; Connect returns dnp3.ErrClosed.
func TestConnectClosedWhileDialing(t *testing.T) {
	var c *Client
	var far net.Conn
	open := func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
		go func() { _ = c.Close() }()
		for !c.isClosed() {
			time.Sleep(time.Millisecond)
		}
		a, b := net.Pipe()
		far = b
		return a, a.RemoteAddr(), nil
	}
	c, err := New("127.0.0.1", WithStream(open), WithStartup(Startup{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("Connect: %v, want ErrClosed", err)
	}
	// The stream was closed with the channel: the far end reads EOF.
	_ = far.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := far.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("far end: %v, want EOF", err)
	}
}

// TestSpec5_1_1_2_Rule1_ClearRestartUnanswered: clause 5.1.1.2 Rule 1
// (pp. 102-103) with clause 5.1.1.1.2 Rule 2 (p. 102): a restart the
// outstation reports during the startup sequence is cleared before the
// other steps; a clear-restart WRITE without a response ends the startup,
// and Connect fails.
func TestSpec5_1_1_2_Rule1_ClearRestartUnanswered(t *testing.T) {
	s := &station{restart: true, silent: map[string]bool{"WRITE g80v1": true}}
	o := newSpecOutstation(t, s.answer)
	_, err := Dial(testCtx(t), o.addr, WithStartup(Startup{DisableUnsolicited: true, Integrity: true}),
		WithResponseTimeout(200*time.Millisecond))
	if !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("Connect: %v, want ErrTimeout", err)
	}
	if got := described(o.sent()); len(got) != 2 || got[0] != "DISABLE_UNSOLICITED" || got[1] != "WRITE g80v1" {
		t.Fatalf("startup %v, want [DISABLE_UNSOLICITED WRITE g80v1]", got)
	}
}

// TestRestartProcedureKeyChangeFails: the restart procedure starts with
// the session key change a restart calls for (IEEE 1815-2012 clause
// 7.5.4.2); when it fails the procedure ends there and the change is asked
// for again.
func TestRestartProcedureKeyChangeFails(t *testing.T) {
	c := authClient(t, secauth.User{Number: 1, UpdateKey: testUpdateKey})
	c.proc.restarted(true, c.currentKey())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.restartProcedure(ctx); err == nil {
		t.Fatal("restart procedure without a connection succeeded")
	}
}

// TestRequestUnencodable: a request whose header cannot be encoded fails
// before anything is sent, with or without WithMaxRequestFragment, and
// takes no sequence number (IEEE 1815-2012 clause 4.3 Rule 14).
func TestRequestUnencodable(t *testing.T) {
	bad := app.Ranged(app.G81V1, 0, app.Binary{})
	for _, opts := range [][]Option{specQuiet, append(specQuiet, WithMaxRequestFragment(249))} {
		o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
		c := specDial(t, o, opts...)
		if _, err := c.Request(testCtx(t), app.FuncWrite, bad); err == nil {
			t.Fatal("a g81v1 header with a binary input was sent")
		}
		if _, err := c.Read(testCtx(t), app.ClassHeaders(0)...); err != nil {
			t.Fatal(err)
		}
		if sent := o.sent(); len(sent) != 1 || sent[0].f.Function != app.FuncRead || sent[0].f.Control.Seq != 0 {
			t.Fatalf("requests %v", o.requests())
		}
	}
}

// TestStrayAuthResponseDuringRequest: an AUTH_RESPONSE that arrives while
// a request waits for its response, with another sequence number, answers
// neither the request nor a confirmation; it is discarded and the request
// completes with its own response (IEEE 1815-2012 Table 6-2 row 1).
func TestStrayAuthResponseDuringRequest(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		stray := frag(app.SingleControl(app.NextSeq(req.f.Control.Seq)), app.FuncAuthResponse, 0)
		return [][]byte{stray, empty(req, 0)}
	})
	c := specDial(t, o, specQuiet...)
	if _, err := c.Read(testCtx(t), app.ClassHeaders(0)...); err != nil {
		t.Fatal(err)
	}
	o.none(t, 100*time.Millisecond)
}

// TestSpec4_3_Rule4_BroadcastLimit: clause 4.3 Rule 4 (p. 39) limits every
// request the master sends, broadcasts included: a broadcast over
// WithMaxRequestFragment fails with dnp3.ErrInvalidOption, unsent.
func TestSpec4_3_Rule4_BroadcastLimit(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
	c := specDial(t, o, append(specQuiet, WithMaxRequestFragment(249))...)
	objs := make([]app.Object, 30)
	for i := range objs {
		objs[i] = app.Object{Index: uint32(i), Value: app.CROB{Op: app.OpLatchOn, Count: 1}}
	}
	err := c.Broadcast(testCtx(t), link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, app.Indexed(app.G12V1, objs...))
	if !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("broadcast over the limit: %v", err)
	}
	o.none(t, 100*time.Millisecond)
}

// TestWithSecureAuthenticationInvalidUser: a user that secauth.User.Validate
// refuses, here one with neither an update key nor a session key, fails New
// with dnp3.ErrInvalidOption.
func TestWithSecureAuthenticationInvalidUser(t *testing.T) {
	if _, err := New("127.0.0.1", WithSecureAuthentication(secauth.User{Number: 1})); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("user without keys: %v", err)
	}
}

// TestCloseWhileWaitingToReconnect: Close ends the wait between reconnect
// attempts at once, whatever the delay.
func TestCloseWhileWaitingToReconnect(t *testing.T) {
	srv, addr := outstation(t)
	c, err := Dial(testCtx(t), addr, WithReconnect(Reconnect{MinDelay: time.Hour, MaxDelay: time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	srv.CloseConnections()
	eventually(t, "waiting to reconnect", func() bool { return c.State() == dnp3.StateConnecting })
	done := make(chan struct{})
	go func() {
		_ = c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for the reconnect delay")
	}
	if s := c.State(); s != dnp3.StateDisconnected {
		t.Fatalf("state %v after Close", s)
	}
}

// TestSpec13_2_3_1_3_DualEndpointEndsReconnectWait: clause 13.2.3.1.3 (p.
// 379), dual end point: a master waiting to reconnect after its connection
// was lost takes the connection the outstation establishes meanwhile at
// once, without waiting out its reconnect delay (an hour here).
func TestSpec13_2_3_1_3_DualEndpointEndsReconnectWait(t *testing.T) {
	l := listenTCP(t)
	var mu sync.Mutex
	var states []dnp3.State
	count := func(s dnp3.State) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, x := range states {
			if x == s {
				n++
			}
		}
		return n
	}
	c, err := New(deadAddr(t), WithDualEndpoint(l, nil), WithAutoIntegrity(false),
		WithReconnect(Reconnect{MinDelay: time.Hour, MaxDelay: time.Hour}),
		WithStateHandler(func(s dnp3.State, _ error) {
			mu.Lock()
			states = append(states, s)
			mu.Unlock()
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("Connect to nobody: %v", err)
	}
	srv := dualServer(t, l)
	waitFor(t, "the outstation's connection", func() bool { return count(dnp3.StateConnected) == 1 })
	readOne(t, c)
	srv.CloseConnections()
	waitFor(t, "the outstation's next connection", func() bool { return count(dnp3.StateConnected) == 2 })
	readOne(t, c)
}

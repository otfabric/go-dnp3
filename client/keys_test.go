// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

var testUpdateKey = []byte("0123456789abcdef")

// authCounter counts the AUTHENTICATE_REQ requests that completed.
type authCounter struct {
	dnp3.NopMetrics
	done atomic.Int64
}

func (m *authCounter) OnRequest(net.Addr, uint16, app.FunctionCode)           {}
func (m *authCounter) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) {}
func (m *authCounter) OnRequestDone(_ net.Addr, _ uint16, fc app.FunctionCode, _ time.Duration, err error) {
	if fc == app.FuncAuthRequest && err == nil {
		m.done.Add(1)
	}
}

func TestSessionKeyChange(t *testing.T) {
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: testUpdateKey}}))
	m := &authCounter{}
	c, err := Dial(testCtx(t), addr, WithMetrics(m), WithResponseTimeout(2*time.Second),
		WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}),
		WithKeyChangeInterval(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.controlKey() == nil {
		t.Fatal("no session key after connect")
	}
	if _, err := c.Operate(testCtx(t), SelectBeforeOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("challenged control after the key change: %v", err)
	}
	// The key change interval changes the keys again, and controls go on
	// working with the new ones.
	first := c.controlKey()
	waitFor(t, "periodic key changes", func() bool { return m.done.Load() >= 3 })
	if bytes.Equal(first, c.controlKey()) {
		t.Fatal("session key unchanged after periodic key changes")
	}
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOff, 0, 0)); err != nil {
		t.Fatalf("control after re-keying: %v", err)
	}
}

func TestSessionKeyChangeRefused(t *testing.T) {
	// An outstation without secure authentication refuses the key status
	// request; one with another update key refuses the key change.
	_, plain := outstation(t)
	_, other := outstation(t, server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: []byte("fedcba9876543210")}}))
	user := WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey})

	_, err := Dial(testCtx(t), plain, user, WithResponseTimeout(time.Second))
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINNoFuncCodeSupport) {
		t.Fatalf("outstation without secure authentication: %v", err)
	}
	_, err = Dial(testCtx(t), other, user, WithResponseTimeout(time.Second))
	var ae *dnp3.AuthError
	if !errors.As(err, &ae) || ae.Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("other update key: %v", err)
	}
}

// fakeAuthOutstation answers AUTHENTICATE_REQ with what answer returns
// for each request.
func fakeAuthOutstation(t *testing.T, answer func(req *app.Fragment) []app.Header) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		var sess *channel.Session
		sess = ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1, OnFragment: func(b []byte, _ link.Address) {
			req, err := app.Decode(b)
			if err != nil || req.Function == app.FuncConfirm {
				return
			}
			f := &app.Fragment{Control: app.SingleControl(req.Control.Seq), Function: app.FuncAuthResponse, Headers: answer(req)}
			out, _ := f.Encode()
			_ = sess.Send(context.Background(), out)
		}})
		ch.Start()
		t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	}()
	return l.Addr().String()
}

func TestSessionKeyChangeBadAnswers(t *testing.T) {
	user := WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey})
	status := app.AuthSessionKeyStatus{KSQ: 1, User: 1, KeyWrap: app.KeyWrapAES128, Status: app.KeyStatusNotInit, Challenge: bytes.Repeat([]byte{1}, 32)}

	// No key status object in the answer.
	addr := fakeAuthOutstation(t, func(*app.Fragment) []app.Header { return nil })
	if _, err := Dial(testCtx(t), addr, user, WithResponseTimeout(time.Second)); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("answer without key status: %v", err)
	}
	// A confirmation whose MAC is not over the key change.
	addr = fakeAuthOutstation(t, func(req *app.Fragment) []app.Header {
		if req.Headers[0].GV == app.G120V4 {
			return []app.Header{app.FreeFormat(app.G120V5, status)}
		}
		done := status
		done.Status, done.MAC, done.MACValue = app.KeyStatusOK, app.MACHMACSHA256Trunc16, bytes.Repeat([]byte{9}, 16)
		return []app.Header{app.FreeFormat(app.G120V5, done)}
	})
	if _, err := Dial(testCtx(t), addr, user, WithResponseTimeout(time.Second)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("wrong confirmation MAC: %v", err)
	}
}

func TestWrapSessionKeys(t *testing.T) {
	u := secauth.User{Number: 1, UpdateKey: testUpdateKey}
	st := app.AuthSessionKeyStatus{KSQ: 3, User: 1, KeyWrap: app.KeyWrapAES128, Status: app.KeyStatusOK,
		MAC: app.MACHMACSHA256Trunc16, Challenge: []byte{1, 2, 3, 4}, MACValue: bytes.Repeat([]byte{5}, 16)}
	for _, withMAC := range []bool{true, false} {
		wrapped, control, monitoring, err := wrapSessionKeys(u, st, withMAC)
		if err != nil || len(control) != 16 || len(monitoring) != 16 {
			t.Fatalf("withMAC=%v: %v", withMAC, err)
		}
		plain, err := secauth.KeyUnwrap(testUpdateKey, wrapped)
		if err != nil {
			t.Fatal(err)
		}
		form := st
		if !withMAC {
			form.MACValue = nil
		}
		msg, _ := app.AppendObjectValue(nil, app.G120V5, form)
		c, m, err := secauth.ParseKeyChangeData(plain, msg)
		if err != nil || !bytes.Equal(c, control) || !bytes.Equal(m, monitoring) {
			t.Fatalf("withMAC=%v: the plaintext does not carry the expected key status: %v", withMAC, err)
		}
	}
	// An update key AES cannot use.
	if _, _, _, err := wrapSessionKeys(secauth.User{Number: 1, UpdateKey: make([]byte, 20)}, st, true); err == nil {
		t.Fatal("bad update key accepted")
	}
}

func TestChallengeBeforeKeyChange(t *testing.T) {
	c, err := New("127.0.0.1:1", WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ch := &app.Fragment{Function: app.FuncAuthResponse, Headers: []app.Header{app.FreeFormat(app.G120V1,
		app.AuthChallenge{CSQ: 1, User: 1, MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: []byte{1, 2, 3, 4}})}}
	if _, err := c.onAuthResponse(testCtx(t), nil, ch, nil, nil); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("challenge without session keys: %v", err)
	}
	if _, err := New("127.0.0.1", WithKeyChangeInterval(-time.Second)); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("negative key change interval accepted")
	}
	// 0 disables the interval: the key change count alone (IEEE 1815-2012
	// clause 7.6.1.4.3).
	if c, err := New("127.0.0.1", WithKeyChangeInterval(0)); err != nil {
		t.Fatalf("key change interval 0: %v", err)
	} else {
		_ = c.Close()
	}
	if _, err := New("127.0.0.1", WithAggressiveMode()); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("aggressive mode without secure authentication accepted")
	}
	// Asking twice for a key change while one is pending asks once.
	c.rekeySoon()
	c.rekeySoon()
	if len(c.rekey) != 1 {
		t.Fatalf("%d key changes pending", len(c.rekey))
	}
}

func TestPreSharedSessionKey(t *testing.T) {
	key := []byte("pre-shared session key 32 octets")
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: key}}))
	c, err := Dial(testCtx(t), addr, WithSecureAuthentication(secauth.User{Number: 1, Key: key}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if !bytes.Equal(c.controlKey(), key) {
		t.Fatal("pre-shared key not used as the control key")
	}
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("challenged control with a pre-shared key: %v", err)
	}
}

func TestSessionKeyChangeNoConfirmation(t *testing.T) {
	// The key status request is answered, the key change is not.
	status := app.AuthSessionKeyStatus{KSQ: 1, User: 1, KeyWrap: app.KeyWrapAES128, Status: app.KeyStatusNotInit, Challenge: bytes.Repeat([]byte{1}, 32)}
	addr := fakeAuthOutstation(t, func(req *app.Fragment) []app.Header {
		if req.Headers[0].GV == app.G120V4 {
			return []app.Header{app.FreeFormat(app.G120V5, status)}
		}
		return nil
	})
	_, err := Dial(testCtx(t), addr, WithResponseTimeout(time.Second), WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))
	if !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("key change without confirmation: %v", err)
	}
}

// TestChallengeReplySequence: the reply to a challenge keeps the sequence
// number of the challenge, which is that of the critical request, and the
// response to the request carries it too.
func TestChallengeReplySequence(t *testing.T) {
	key := []byte("pre-shared session key 32 octets")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	replySeq := make(chan uint8, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		var sess *channel.Session
		var critical *app.Fragment
		send := func(f *app.Fragment) {
			b, _ := f.Encode()
			_ = sess.Send(context.Background(), b)
		}
		sess = ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1, OnFragment: func(b []byte, _ link.Address) {
			req, err := app.Decode(b)
			if err != nil {
				return
			}
			switch req.Function {
			case app.FuncDirectOperate:
				critical = req
				send(&app.Fragment{Control: app.SingleControl(req.Control.Seq), Function: app.FuncAuthResponse,
					Headers: []app.Header{app.FreeFormat(app.G120V1, app.AuthChallenge{CSQ: 1, User: 1,
						MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: bytes.Repeat([]byte{7}, 32)})}})
			case app.FuncAuthRequest:
				replySeq <- req.Control.Seq
				send(&app.Fragment{Control: app.SingleControl(req.Control.Seq), Function: app.FuncResponse, Headers: critical.Headers})
			case app.FuncConfirm:
			default:
				send(&app.Fragment{Control: app.SingleControl(req.Control.Seq), Function: app.FuncResponse})
			}
		}})
		ch.Start()
		t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	}()
	c, err := Dial(testCtx(t), l.Addr().String(), WithAutoIntegrity(false), WithResponseTimeout(time.Second),
		WithSecureAuthentication(secauth.User{Number: 1, Key: key}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	seq := c.seq
	c.mu.Unlock()
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("challenged control: %v", err)
	}
	if got := <-replySeq; got != seq {
		t.Fatalf("reply sent with sequence %d, the critical request had %d", got, seq)
	}
}

// authResponses counts the AUTHENTICATE_RESP fragments a master receives.
type authResponses struct {
	dnp3.NopMetrics
	n atomic.Int64
}

func (m *authResponses) OnFragmentReceived(_ net.Addr, f *app.Fragment, _ int) {
	if f.Function == app.FuncAuthResponse {
		m.n.Add(1)
	}
}

func TestAggressiveMode(t *testing.T) {
	key := []byte("pre-shared session key 32 octets")
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: key}}))
	m := &authResponses{}
	c, err := Dial(testCtx(t), addr, WithMetrics(m), WithAggressiveMode(), WithAutoClearRestart(false),
		WithSecureAuthentication(secauth.User{Number: 1, Key: key}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	stats := func() map[uint32]uint32 {
		t.Helper()
		res, err := c.Read(testCtx(t), app.AllObjects(app.G121V0))
		if err != nil {
			t.Fatal(err)
		}
		got := map[uint32]uint32{}
		for _, h := range res.Headers() {
			for _, o := range h.Objects {
				got[o.Index] = o.Value.(app.SecurityStatistic).Value
			}
		}
		return got
	}
	before := stats()
	// The first control is challenged; the next ones carry their MAC.
	for i := range 4 {
		if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
			t.Fatalf("control %d: %v", i, err)
		}
	}
	if n := m.n.Load(); n != 1 {
		t.Fatalf("%d challenges for 4 controls in aggressive mode, want 1", n)
	}
	// A request that does not encode fails before anything is sent.
	if _, err := c.Write(testCtx(t), app.Header{GV: app.GV(12, 1), Qualifier: app.Qual1ByteStartStop,
		Objects: []app.Object{{Index: 0, Value: app.Binary{}}}}); err == nil {
		t.Fatal("WRITE of a header that does not encode succeeded")
	}
	after := stats()
	for _, s := range []secauth.Statistic{secauth.StatSuccessfulAuthentications, secauth.StatCriticalMessagesReceived} {
		if d := after[uint32(s)] - before[uint32(s)]; d != 4 {
			t.Errorf("%s grew by %d over 4 authenticated controls", s, d)
		}
	}
}

// TestRekeyOnAuthError: an authentication error in answer to a request
// fails it. With a pre-shared session key there are no session keys to
// change, so no key change is asked for; with an update key error 1 asks
// for one (TestSpec7_5_3_4RekeyThrottle).
func TestRekeyOnAuthError(t *testing.T) {
	addr := fakeAuthOutstation(t, func(*app.Fragment) []app.Header {
		return []app.Header{app.FreeFormat(app.G120V7, app.AuthError{User: 1, Code: app.AuthErrAuthenticationFailed})}
	})
	c, err := Dial(testCtx(t), addr, WithSecureAuthentication(secauth.User{Number: 1, Key: []byte("pre-shared session key 32 octets")}),
		WithStartup(Startup{}), WithAutoIntegrity(false), WithAutoClearRestart(false), WithResponseTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var ae *dnp3.AuthError
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.As(err, &ae) {
		t.Fatalf("control refused with an authentication error: %v", err)
	}
	if len(c.rekey) != 0 {
		t.Fatal("key change asked for with a pre-shared session key")
	}
}

// TestChallengeMACOfOutstation: the reply to a challenge, and the aggressive
// mode requests after it, use the MAC algorithm the challenge names, not
// the one the client is configured with; WithChallengeMACs limits which.
func TestChallengeMACOfOutstation(t *testing.T) {
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: testUpdateKey, MAC: app.MACHMACSHA1Trunc10}}))
	user := secauth.User{Number: 1, UpdateKey: testUpdateKey} // HMAC-SHA-256/16 by default
	c, err := Dial(testCtx(t), addr, WithSecureAuthentication(user), WithAggressiveMode())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for i := range 2 { // challenged, then in aggressive mode over that challenge
		if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
			t.Fatalf("control %d with the outstation's HMAC-SHA-1/10: %v", i, err)
		}
	}

	strict, err := Dial(testCtx(t), addr, WithSecureAuthentication(user), WithChallengeMACs(app.MACHMACSHA256Trunc16))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = strict.Close() }()
	if _, err := strict.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("challenge outside WithChallengeMACs: %v", err)
	}
}

func TestChallengeMACOptions(t *testing.T) {
	for _, algs := range [][]app.MACAlgorithm{nil, {app.MACAESGMAC}, {app.MACNone}} {
		if _, err := New("127.0.0.1", WithChallengeMACs(algs...)); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("WithChallengeMACs(%v) accepted", algs)
		}
	}
	c, err := New("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for alg, want := range map[app.MACAlgorithm]bool{
		app.MACHMACSHA1Trunc4: false, app.MACHMACSHA1Trunc8: false, app.MACHMACSHA1Trunc10: true,
		app.MACHMACSHA256Trunc8: false, app.MACHMACSHA256Trunc16: true, app.MACAESGMAC: false, app.MACNone: false,
	} {
		if got := c.acceptsMAC(alg); got != want {
			t.Errorf("default acceptsMAC(%s) over TCP = %v", alg, got)
		}
	}
	// Over a serial stream the 8-octet truncations are allowed (IEEE
	// 1815-2012 clauses 7.6.1.1.1, 7.6.1.1.2).
	serial, err := New("line", WithStream(func(context.Context) (io.ReadWriteCloser, net.Addr, error) { return nil, nil, io.EOF }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serial.Close() }()
	for _, alg := range []app.MACAlgorithm{app.MACHMACSHA1Trunc8, app.MACHMACSHA256Trunc8} {
		if !serial.acceptsMAC(alg) {
			t.Errorf("acceptsMAC(%s) over a serial stream = false", alg)
		}
	}
	c, err = New("127.0.0.1", WithChallengeMACs(app.MACHMACSHA1Trunc4))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if !c.acceptsMAC(app.MACHMACSHA1Trunc4) || c.acceptsMAC(app.MACHMACSHA256Trunc16) {
		t.Error("WithChallengeMACs list not applied")
	}
}

// TestUserNumberZero: user number 0, reserved for an unknown user, is
// taken as the default user 1 at both ends.
func TestUserNumberZero(t *testing.T) {
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: testUpdateKey}}))
	c, err := Dial(testCtx(t), addr, WithSecureAuthentication(secauth.User{UpdateKey: testUpdateKey}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.opts.auth.Number != 1 {
		t.Fatalf("user number %d", c.opts.auth.Number)
	}
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("challenged control as user 0: %v", err)
	}

	_, addr = outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{UpdateKey: testUpdateKey}}))
	c2, err := Dial(testCtx(t), addr, WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))
	if err != nil {
		t.Fatalf("outstation configured with user 0: %v", err)
	}
	defer func() { _ = c2.Close() }()
	if _, err := c2.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("challenged control against an outstation configured with user 0: %v", err)
	}
}

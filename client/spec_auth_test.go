// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"sync"
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

// Spec tests of the master's Secure Authentication (IEEE 1815-2012 clause
// 7, A.45). Page numbers are the printed ones.

var specKey = []byte("pre-shared session key 32 octets")

// scriptedOutstation accepts one connection and passes every fragment the
// master sends, decoded and as received, to fn on the connection's
// goroutine, with a function that sends a fragment and returns its
// encoding.
func scriptedOutstation(t *testing.T, fn func(f *app.Fragment, raw []byte, send func(*app.Fragment) []byte)) string {
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
		send := func(f *app.Fragment) []byte {
			b, _ := f.Encode()
			_ = sess.Send(context.Background(), b)
			return b
		}
		sess = ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1, OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil {
				fn(f, b, send)
			}
		}})
		ch.Start()
		t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	}()
	return l.Addr().String()
}

// quiet are the options of a client that sends only what a test asks for.
func quiet(opts ...Option) []Option {
	return append([]Option{WithStartup(Startup{}), WithAutoIntegrity(false), WithAutoClearRestart(false)}, opts...)
}

// sentRecorder keeps the fragments a master sends.
type sentRecorder struct {
	dnp3.NopMetrics
	mu    sync.Mutex
	frags []*app.Fragment
}

func (r *sentRecorder) OnFragmentSent(_ net.Addr, f *app.Fragment, _ int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frags = append(r.frags, f)
}

// aggressive reports, for each request with function fc sent, whether it
// was sent in aggressive mode.
func (r *sentRecorder) aggressive(fc app.FunctionCode) []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []bool
	for _, f := range r.frags {
		if f.Function == fc {
			out = append(out, len(f.Headers) > 0 && f.Headers[0].GV == app.G120V3)
		}
	}
	return out
}

// eventually waits until cond holds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 5 s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSpecTableA_9_AggressiveModeFragment: IEEE 1815-2012 A.45.9 and Table
// A-9, p.742 and p.784: the master's aggressive mode request ends with a
// MAC over the last challenge and every octet of the request before the
// MAC value, the g120v9 object header and size prefix included. The
// golden octets are derived in secauth/spec_test.go, computed outside
// this library.
func TestSpecTableA_9_AggressiveModeFragment(t *testing.T) {
	ch, _ := hex.DecodeString("c383000078015b010c00070000000000040101020304")
	want := "c405780307010800000001000c01170100030100000000000000000078095b011000" + "4466436ed22af51512d682638f8f7689"
	f := &app.Fragment{Control: app.SingleControl(4), Function: app.FuncDirectOperate, Headers: []app.Header{
		app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})}}
	b, err := aggressiveFragment(f, app.MACHMACSHA256Trunc16, specKey, ch, 8, 1)
	if err != nil || hex.EncodeToString(b) != want {
		t.Fatalf("aggressive mode request %x, want %s (%v)", b, want, err)
	}
	if again, _ := f.Encode(); !bytes.Equal(again, b) {
		t.Fatal("the fragment does not encode as the aggressive mode request")
	}
	if _, err := aggressiveFragment(f, app.MACNone, specKey, ch, 8, 1); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("aggressive mode without a MAC algorithm: %v", err)
	}
}

// TestSpec7_5_2_3_3_F_CSQWraps: clause 7.5.2.3.3 d) and f), p.211: an
// aggressive mode request takes the CSQ of the last challenge plus the
// replies and aggressive mode requests sent since; the CSQ wraps from
// 4 294 967 295 to 0.
func TestSpec7_5_2_3_3_F_CSQWraps(t *testing.T) {
	c, err := New("127.0.0.1", WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}), WithAggressiveMode())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.auth.lastChallenge, c.auth.lastMAC, c.auth.csq, c.auth.replied = []byte{1}, app.MACHMACSHA256Trunc16, math.MaxUint32-1, true
	c.mu.Unlock()
	for _, want := range []uint32{math.MaxUint32, 0, 1} {
		req := &app.Fragment{Control: app.SingleControl(1), Function: app.FuncDirectOperate}
		if ok, err := c.aggressive(req); !ok || err != nil {
			t.Fatalf("not aggressive: %v", err)
		}
		if got := req.Headers[0].Objects[0].Value.(app.AuthAggressiveMode).CSQ; got != want {
			t.Fatalf("CSQ %d, want %d", got, want)
		}
	}
	// A function not configured for it, and a refusal of aggressive mode.
	if ok, _ := c.aggressive(&app.Fragment{Function: app.FuncRead}); ok {
		t.Fatal("READ in aggressive mode")
	}
	c.onAuthFailure(app.FuncDirectOperate, true, &dnp3.AuthError{Code: app.AuthErrAggressiveModeNotSupported})
	c.mu.Lock()
	c.auth.lastChallenge, c.auth.replied = []byte{1}, true
	c.mu.Unlock()
	if ok, _ := c.aggressive(&app.Fragment{Function: app.FuncDirectOperate}); ok {
		t.Fatal("aggressive mode after error 4")
	}
}

// TestSpec7_5_3_3_AggressiveAfterKeyChange: clause 7.5.3.3, p.224: a
// responder shall not send an aggressive mode request until it has
// successfully replied to at least one challenge each time the session
// keys change; the first critical request after a key change is sent
// normally.
func TestSpec7_5_3_3_AggressiveAfterKeyChange(t *testing.T) {
	var executed atomic.Int64
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus {
		executed.Add(1)
		return app.StatusSuccess
	})
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: testUpdateKey}}))
	rec := &sentRecorder{}
	c, err := Dial(testCtx(t), addr, quiet(WithMetrics(rec), WithAggressiveMode(), WithKeyChangeInterval(time.Hour),
		WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	operate := func() {
		t.Helper()
		if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	operate()
	operate()
	if err := c.changeSessionKeys(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	operate()
	operate()
	if got := rec.aggressive(app.FuncDirectOperate); len(got) != 4 || got[0] || !got[1] || got[2] || !got[3] {
		t.Fatalf("aggressive mode per control: %v, want [false true false true]", got)
	}
	if executed.Load() != 4 {
		t.Fatalf("%d controls executed", executed.Load())
	}
}

// TestSpec7_5_3_4_AggressiveRefused: clause 7.5.3.4, p.224 and A.45.7,
// p.734: when the outstation answers an aggressive mode request with an
// error, the next critical request is sent normally; after error 4
// (aggressive mode not supported, clause 7.6.1.4.7) aggressive mode is not
// used again.
func TestSpec7_5_3_4_AggressiveRefused(t *testing.T) {
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: specKey}, NoAggressiveMode: true}))
	rec := &sentRecorder{}
	c, err := Dial(testCtx(t), addr, quiet(WithMetrics(rec), WithAggressiveMode(), WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var errs []error
	for range 4 {
		_, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0))
		errs = append(errs, err)
	}
	var ae *dnp3.AuthError
	if errs[0] != nil || !errors.As(errs[1], &ae) || ae.Code != app.AuthErrAggressiveModeNotSupported || errs[2] != nil || errs[3] != nil {
		t.Fatalf("results %v", errs)
	}
	if got := rec.aggressive(app.FuncDirectOperate); len(got) != 4 || got[0] || !got[1] || got[2] || got[3] {
		t.Fatalf("aggressive mode per control: %v, want [false true false false]", got)
	}
}

// TestSpec7_5_3_4_RekeyThrottle: Table 7-6 #4, p.206 and Table 7-8 rows
// 10-11, p.217: the master changes the session keys after an
// authentication failure (error 1, clause 7.5.3.4 c, p.224) until Rekeys
// Due to Authentication Failure reaches Max Authentication Rekeys
// (threshold 3), and again only after the keys were changed for another
// reason.
func TestSpec7_5_3_4_RekeyThrottle(t *testing.T) {
	c, err := New("127.0.0.1", WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	fail := func() {
		c.onAuthFailure(app.FuncDirectOperate, false, &dnp3.AuthError{Code: app.AuthErrAuthenticationFailed})
	}
	rekeys := func() uint32 { return c.SecurityStatistics()[secauth.StatRekeysDueToAuthFailure] }
	for range 5 {
		fail()
	}
	if rekeys() != 3 {
		t.Fatalf("%d rekeys for 5 failures, want 3", rekeys())
	}
	// A key change the failures asked for does not lift the limit.
	c.keysChanged(make([]byte, 16), make([]byte, 16), []byte{1})
	fail()
	if rekeys() != 3 {
		t.Fatalf("%d rekeys after a key change due to failures", rekeys())
	}
	// One for another reason does.
	c.keysChanged(make([]byte, 16), make([]byte, 16), []byte{1})
	fail()
	if rekeys() != 4 {
		t.Fatalf("%d rekeys after a periodic key change", rekeys())
	}
	// Other errors, and authentication requests, do not change the keys.
	c.onAuthFailure(app.FuncDirectOperate, false, &dnp3.AuthError{Code: app.AuthErrUnknownUser})
	c.onAuthFailure(app.FuncAuthRequest, false, &dnp3.AuthError{Code: app.AuthErrAuthenticationFailed})
	if rekeys() != 4 {
		t.Fatalf("%d rekeys", rekeys())
	}
}

// TestSpec7_5_2_3_2_I_NoAckChallenged: clause 7.5.2.3.2 i), p.208: a
// master shall wait to see whether the outstation challenges a no-ack
// request (0x06, 0x08, 0x0A, 0x0C), or send it in aggressive mode; clause
// 7.5.2.3.2 j): it shall answer the challenge.
func TestSpec7_5_2_3_2_I_NoAckChallenged(t *testing.T) {
	var executed atomic.Int64
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus {
		executed.Add(1)
		return app.StatusSuccess
	})
	_, addr := outstation(t, server.WithHandler(accept), server.WithSecureAuthentication(server.SecureAuth{
		User: secauth.User{Number: 1, Key: specKey}, Critical: []app.FunctionCode{app.FuncDirectOperate}}))
	rec := &sentRecorder{}
	c, err := Dial(testCtx(t), addr, quiet(WithMetrics(rec), WithResponseTimeout(300*time.Millisecond),
		WithAggressiveMode(app.FuncDirectOperateNoAck), WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// DIRECT_OPERATE_NR is mandatory critical: challenged, answered,
	// executed. Without a response the master cannot tell whether the
	// reply was accepted, so aggressive mode waits for a challenged
	// request that has one.
	if _, err := c.Operate(testCtx(t), DirectOperateNoAck, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "challenged no-ack control executed", func() bool { return executed.Load() == 1 })
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatal(err)
	}
	// The next one goes in aggressive mode, without waiting.
	start := time.Now()
	if _, err := c.Operate(testCtx(t), DirectOperateNoAck, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= 300*time.Millisecond {
		t.Fatalf("aggressive no-ack control took %v", d)
	}
	eventually(t, "aggressive no-ack control executed", func() bool { return executed.Load() == 3 })
	if got := rec.aggressive(app.FuncDirectOperateNoAck); len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("aggressive mode per no-ack control: %v", got)
	}
	// IMMEDIATE_FREEZE_NR is not critical here: the master waits up to the
	// response timeout, then reports success.
	start = time.Now()
	if err := c.Freeze(testCtx(t), false, true, app.AllObjects(app.G20V0)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("unchallenged no-ack request returned after %v, before the response timeout", d)
	}
}

// TestSpec7_5_2_3_2_E_AggressiveConfirm: clause 7.5.2.3.2 e)-f), p.208,
// 7.5.3.2, p.223-224 and 7.6.1.4.7, p.244: a master that receives a
// response with CON set ending in a challenge shall send the confirmation
// in aggressive mode, also with aggressive mode disabled: g120v3 with the
// challenge's CSQ, the CONFIRM, g120v9 with the MAC over the challenge
// fragment and the confirmation (Table A-9). The same for an unsolicited
// response.
func TestSpec7_5_2_3_2_E_AggressiveConfirm(t *testing.T) {
	type confirmed struct{ challenge, confirm []byte }
	got := make(chan confirmed, 2)
	var last []byte
	ch := app.FreeFormat(app.G120V1, app.AuthChallenge{CSQ: 41, MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: []byte{9, 8, 7, 6}})
	addr := scriptedOutstation(t, func(f *app.Fragment, raw []byte, send func(*app.Fragment) []byte) {
		switch f.Function {
		case app.FuncRead:
			last = send(&app.Fragment{Control: app.Control{FIR: true, FIN: true, CON: true, Seq: f.Control.Seq}, Function: app.FuncResponse, Headers: []app.Header{ch}})
		case app.FuncConfirm:
			got <- confirmed{last, raw}
			if !f.Control.UNS {
				last = send(&app.Fragment{Control: app.Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: 5}, Function: app.FuncUnsolicitedResponse, Headers: []app.Header{ch}})
			}
		default:
		}
	})
	c, err := Dial(testCtx(t), addr, quiet(WithSecureAuthentication(secauth.User{Number: 2, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Read(testCtx(t), app.AllObjects(app.G1V0)); err != nil {
		t.Fatal(err)
	}
	for _, uns := range []bool{false, true} {
		var cf confirmed
		select {
		case cf = <-got:
		case <-time.After(3 * time.Second):
			t.Fatalf("no confirmation (unsolicited %v)", uns)
		}
		f, err := app.Decode(cf.confirm)
		if err != nil || f.Function != app.FuncConfirm || f.Control.UNS != uns || len(f.Headers) != 2 ||
			f.Headers[0].GV != app.G120V3 || f.Headers[1].GV != app.G120V9 {
			t.Fatalf("confirmation (unsolicited %v): %v %v", uns, f, err)
		}
		if am := f.Headers[0].Objects[0].Value.(app.AuthAggressiveMode); am.CSQ != 41 || am.User != 2 {
			t.Fatalf("aggressive mode object %+v", am)
		}
		want, _ := secauth.MAC(app.MACHMACSHA256Trunc16, specKey, secauth.AuthData(cf.challenge, cf.confirm[:len(cf.confirm)-16]))
		if !bytes.Equal(cf.confirm[len(cf.confirm)-16:], want) {
			t.Fatalf("confirmation MAC (unsolicited %v)", uns)
		}
	}
	if s := c.SecurityStatistics(); s[secauth.StatCriticalMessagesSent] != 2 {
		t.Fatalf("critical messages sent %d", s[secauth.StatCriticalMessagesSent])
	}
}

// TestSpec7_5_2_3_2_J_ChallengedConfirm: clause 7.5.2.3.2 j), p.208 and
// Figure 7-25: the replying station shall process any challenge, also one
// of a CONFIRM, which comes after the response: the reply's MAC covers the
// challenge and the CONFIRM (Table A-3).
func TestSpec7_5_2_3_2_J_ChallengedConfirm(t *testing.T) {
	replies := make(chan [2][]byte, 1)
	var challenge, confirmRaw []byte
	addr := scriptedOutstation(t, func(f *app.Fragment, raw []byte, send func(*app.Fragment) []byte) {
		switch f.Function {
		case app.FuncRead:
			send(&app.Fragment{Control: app.Control{FIR: true, FIN: true, CON: true, Seq: f.Control.Seq}, Function: app.FuncResponse})
		case app.FuncConfirm:
			confirmRaw = raw
			challenge = send(&app.Fragment{Control: app.SingleControl(f.Control.Seq), Function: app.FuncAuthResponse, Headers: []app.Header{
				app.FreeFormat(app.G120V1, app.AuthChallenge{CSQ: 3, MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: []byte{1, 2, 3, 4}})}})
		case app.FuncAuthRequest:
			mac := f.Headers[0].Objects[0].Value.(app.AuthReply).MAC
			want, _ := secauth.MAC(app.MACHMACSHA256Trunc16, specKey, secauth.AuthData(challenge, confirmRaw))
			replies <- [2][]byte{mac, want}
		default:
		}
	})
	c, err := Dial(testCtx(t), addr, quiet(WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Read(testCtx(t), app.AllObjects(app.G1V0)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-replies:
		if !bytes.Equal(r[0], r[1]) {
			t.Fatal("the reply's MAC is not over the challenge and the CONFIRM")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("challenge of the CONFIRM not answered")
	}
}

// keyChangeOutstation answers the session key change of user 1 with
// update key uk: a key status whose MAC is computed with the last
// monitoring key over the last key change (A.45.5), spoiled when tamper
// is set, and a confirmation of the key change.
type keyChangeOutstation struct {
	uk                 []byte
	tamper             atomic.Bool
	keyWrap            atomic.Uint32
	user               atomic.Uint32
	ksq                uint32
	status, monitoring []byte
	change             []byte
}

func (o *keyChangeOutstation) answer(f *app.Fragment, raw []byte, send func(*app.Fragment) []byte) {
	if f.Function != app.FuncAuthRequest || len(f.Headers) == 0 {
		return
	}
	reply := func(st app.AuthSessionKeyStatus) {
		send(&app.Fragment{Control: app.SingleControl(f.Control.Seq), Function: app.FuncAuthResponse, Headers: []app.Header{app.FreeFormat(app.G120V5, st)}})
	}
	switch v := f.Headers[0].Objects[0].Value.(type) {
	case app.AuthSessionKeyStatusRequest:
		o.ksq++
		st := app.AuthSessionKeyStatus{KSQ: o.ksq, User: uint16(o.user.Load()), KeyWrap: app.KeyWrap(o.keyWrap.Load()), Status: app.KeyStatusNotInit, Challenge: []byte{1, 2, 3, 4}}
		if o.monitoring != nil {
			st.Status, st.MAC = app.KeyStatusOK, app.MACHMACSHA256Trunc16
		}
		o.status, _ = app.AppendObjectValue(nil, app.G120V5, st) // without the MAC value (Table A-5)
		if o.monitoring != nil {
			st.MACValue, _ = secauth.MAC(st.MAC, o.monitoring, o.change)
			if o.tamper.Load() {
				st.MACValue[0] ^= 1
			}
		}
		reply(st)
	case app.AuthSessionKeyChange:
		plain, err := secauth.KeyUnwrap(o.uk, v.WrappedKeys)
		if err != nil {
			return
		}
		_, mon, err := secauth.ParseKeyChangeData(plain, o.status)
		if err != nil {
			return
		}
		o.monitoring, o.change = mon, raw
		mac, _ := secauth.MAC(app.MACHMACSHA256Trunc16, mon, raw)
		reply(app.AuthSessionKeyStatus{KSQ: o.ksq, User: 1, KeyWrap: app.KeyWrapAES128, Status: app.KeyStatusOK, Challenge: []byte{5, 6, 7, 8},
			MAC: app.MACHMACSHA256Trunc16, MACValue: mac})
	default:
	}
}

// TestSpec7_5_4_2_KeyStatusAuthenticated: clause 7.5.4.2, p.225: the
// master shall consider an attack underway if the MAC of a key status is
// invalid under the most recently valid monitoring direction session key;
// Table 7-13, p.231-234: a Key Status OK that is not authentic is counted
// as an authentication failure and discarded. A.45.5, p.728: the key
// status names the user and the key wrap algorithm, which the master
// checks (A.45.6).
func TestSpec7_5_4_2_KeyStatusAuthenticated(t *testing.T) {
	o := &keyChangeOutstation{uk: testUpdateKey}
	o.keyWrap.Store(uint32(app.KeyWrapAES128))
	o.user.Store(1)
	addr := scriptedOutstation(t, o.answer)
	c, err := Dial(testCtx(t), addr, quiet(WithKeyChangeInterval(time.Hour), WithResponseTimeout(time.Second),
		WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The second key change: an OK key status authenticated with the first
	// one's monitoring key.
	if err := c.changeSessionKeys(testCtx(t)); err != nil {
		t.Fatalf("authentic key status refused: %v", err)
	}
	key := c.controlKey()
	o.tamper.Store(true)
	if err := c.changeSessionKeys(testCtx(t)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("key status with a wrong MAC: %v", err)
	}
	if !bytes.Equal(c.controlKey(), key) {
		t.Fatal("session keys changed after a key status that is not authentic")
	}
	s := c.SecurityStatistics()
	if s[secauth.StatAuthenticationFailures] != 1 || s[secauth.StatSessionKeyChanges] != 2 || s[secauth.StatFailedSessionKeyChanges] != 1 {
		t.Fatalf("statistics %v", s)
	}
	o.tamper.Store(false)
	o.keyWrap.Store(uint32(app.KeyWrapAES256))
	if err := c.changeSessionKeys(testCtx(t)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("key status naming another key wrap algorithm: %v", err)
	}
	o.keyWrap.Store(uint32(app.KeyWrapAES128))
	o.user.Store(2)
	if err := c.changeSessionKeys(testCtx(t)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("key status of another user: %v", err)
	}
}

// TestSpec7_5_4_2_RestartRekey: clause 7.5.4.2, p.225: each master shall
// initialize the session keys when it detects that the outstation has
// restarted; Table 7-8 Outstation Restarted, p.222: IIN1.7 newly set,
// counted as Rekeys Due to Restarts.
func TestSpec7_5_4_2_RestartRekey(t *testing.T) {
	srv, addr := outstation(t, server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: testUpdateKey}}))
	c, err := Dial(testCtx(t), addr, WithAutoIntegrity(false), WithStartup(Startup{}), WithKeyChangeInterval(time.Hour),
		WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The restart indication of the connection's start: cleared, no
	// second key change.
	eventually(t, "restart cleared", func() bool {
		res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0))
		return err == nil && !res.IIN.Has(app.IINDeviceRestart)
	})
	if s := c.SecurityStatistics(); s[secauth.StatSessionKeyChanges] != 1 || s[secauth.StatRekeysDueToRestarts] != 0 {
		t.Fatalf("statistics after the start %v", s)
	}
	srv.Restart()
	if _, err := c.Read(testCtx(t), app.AllObjects(app.G1V0)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "key change after the restart", func() bool {
		return c.SecurityStatistics()[secauth.StatSessionKeyChanges] == 2
	})
	if s := c.SecurityStatistics(); s[secauth.StatRekeysDueToRestarts] != 1 {
		t.Fatalf("rekeys due to restarts %d", s[secauth.StatRekeysDueToRestarts])
	}
	// The clear-restart WRITE, a critical request, succeeds with them.
	eventually(t, "restart cleared again", func() bool {
		res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0))
		return err == nil && !res.IIN.Has(app.IINDeviceRestart)
	})
}

// TestSpec7_6_1_4_4_KeyChangeCount: clause 7.6.1.4.4, p.243: the master
// shall also change the session keys after a configured number of
// authentication messages in either direction; settable from 1, default
// 1000, at most half the KSQ range. Clause 7.6.1.4.3, p.243: it shall be
// possible to disable the interval and use only the count.
func TestSpec7_6_1_4_4_KeyChangeCount(t *testing.T) {
	if DefaultKeyChangeCount != 1000 || MaxKeyChangeCount != 1<<31 {
		t.Fatal("key change count constants")
	}
	for _, n := range []uint32{0, MaxKeyChangeCount + 1} {
		if _, err := New("127.0.0.1", WithKeyChangeCount(n)); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("key change count %d accepted", n)
		}
	}
	if o := defaultOptions(); o.keyChange != 15*time.Minute || o.keyChangeCount != 1000 {
		t.Fatalf("defaults %v %d", o.keyChange, o.keyChangeCount)
	}
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: testUpdateKey}}))
	c, err := Dial(testCtx(t), addr, quiet(WithKeyChangeInterval(0), WithKeyChangeCount(3),
		WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))...)
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
	eventually(t, "key change after the count", func() bool {
		return c.SecurityStatistics()[secauth.StatSessionKeyChanges] == 2
	})
}

// TestSpec7_5_2_2_MasterStatistics: clause 7.5.2.2, p.204: DNP3
// implementations shall count the events of Table 7-6 (p.206); clauses
// 7.5.3.2 and 7.5.3.3, p.224: the responder counts Critical Messages Sent
// for each reply and aggressive mode request; Error Messages Rxed counts
// the error messages received (A.45.7).
func TestSpec7_5_2_2_MasterStatistics(t *testing.T) {
	c0, err := New("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c0.Close() }()
	if s := c0.SecurityStatistics(); len(s) != int(secauth.NumStatistics) || s[secauth.StatTotalMessagesSent] != 0 {
		t.Fatalf("statistics without secure authentication %v", s)
	}
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: specKey}}))
	c, err := Dial(testCtx(t), addr, quiet(WithAggressiveMode(), WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for range 2 {
		if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	s := c.SecurityStatistics()
	if s[secauth.StatCriticalMessagesSent] != 2 || s[secauth.StatTotalMessagesSent] < 3 || s[secauth.StatTotalMessagesReceived] < 3 {
		t.Fatalf("statistics %v", s)
	}
	// A wrong key: an error message received.
	w, err := Dial(testCtx(t), addr, quiet(WithSecureAuthentication(secauth.User{Number: 1, Key: []byte("another session key, 32 octets!")}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	var ae *dnp3.AuthError
	if _, err := w.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.As(err, &ae) {
		t.Fatalf("wrong key: %v", err)
	}
	if s := w.SecurityStatistics(); s[secauth.StatErrorMessagesReceived] != 1 || s[secauth.StatCriticalMessagesSent] != 1 {
		t.Fatalf("statistics after an error %v", s)
	}
}

// TestSpec7_6_1_1_TruncationOverTCP: clauses 7.6.1.1.1 and 7.6.1.1.2,
// p.241-242: over TCP/IP the MAC shall be truncated to 10 (HMAC-SHA-1) or
// 16 (HMAC-SHA-256) octets; 8 octets are for serial links. A challenge
// asking for 8 octets over TCP fails unless WithChallengeMACs allows it.
func TestSpec7_6_1_1_TruncationOverTCP(t *testing.T) {
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithHandler(accept), server.WithSecureAuthentication(server.SecureAuth{
		User: secauth.User{Number: 1, Key: specKey, MAC: app.MACHMACSHA256Trunc8}}))
	c, err := Dial(testCtx(t), addr, quiet(WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("HMAC-SHA-256/8 over TCP: %v", err)
	}
	allowed, err := Dial(testCtx(t), addr, quiet(WithChallengeMACs(app.MACHMACSHA256Trunc8), WithSecureAuthentication(secauth.User{Number: 1, Key: specKey}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = allowed.Close() }()
	if _, err := allowed.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("HMAC-SHA-256/8 allowed explicitly: %v", err)
	}
}

// TestSpecTable7_13_ChallengeWithoutKeys: Table 7-13, Rx Challenge message
// while the session keys are not valid, p.232: the master counts an
// unexpected message, an authentication failure and a discarded message,
// and does not answer.
func TestSpecTable7_13_ChallengeWithoutKeys(t *testing.T) {
	c, err := New("127.0.0.1:1", WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: testUpdateKey}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ch := &app.Fragment{Function: app.FuncAuthResponse, Headers: []app.Header{app.FreeFormat(app.G120V1,
		app.AuthChallenge{CSQ: 1, MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: []byte{1, 2, 3, 4}})}}
	if _, err := c.onAuthResponse(testCtx(t), nil, ch, nil, nil); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("challenge without session keys: %v", err)
	}
	s := c.SecurityStatistics()
	if s[secauth.StatUnexpectedMessages] != 1 || s[secauth.StatAuthenticationFailures] != 1 || s[secauth.StatDiscardedMessages] != 1 || s[secauth.StatCriticalMessagesSent] != 0 {
		t.Fatalf("statistics %v", s)
	}
}

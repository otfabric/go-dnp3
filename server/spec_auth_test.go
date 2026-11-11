// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// Spec tests of the outstation's Secure Authentication (IEEE 1815-2012
// clause 7, A.45-A.47). Page numbers are the printed ones.

var (
	specUpdateKey = []byte("0123456789abcdef")
	specCROB      = app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
)

// saServer starts a server with opts on a TCP listener and returns it with
// its address, for tests that connect more than once.
func saServer(t *testing.T, opts ...Option) (*Server, string) {
	t.Helper()
	srv, err := New(append([]Option{WithMasters(1)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, l.Addr().String()
}

// dialMaster connects a scripted master to the server at addr.
func dialMaster(t *testing.T, srv *Server, addr string) *master {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	m := &master{t: t, in: make(chan *app.Fragment, 32), srv: srv}
	m.ch = channel.New(conn, channel.Config{})
	m.sess = m.ch.AddSession(channel.SessionConfig{Local: 1, Remote: 10, Master: true,
		OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil {
				m.in <- f
			}
		}})
	m.ch.Start()
	t.Cleanup(func() { m.ch.Close(nil); <-m.ch.Done() })
	return m
}

// drain discards what the outstation sends within d.
func (m *master) drain(d time.Duration) {
	for {
		select {
		case <-m.in:
		case <-time.After(d):
			return
		}
	}
}

// close ends the master's connection.
func (m *master) close() {
	m.ch.Close(nil)
	<-m.ch.Done()
}

// keyStatus asks for the key status of user.
func (m *master) keyStatus(seq uint8, user uint16) app.AuthSessionKeyStatus {
	m.t.Helper()
	m.send(req(seq, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: user})))
	return m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus)
}

// scriptedKeys is a session key change made by a scripted master.
type scriptedKeys struct {
	control, monitoring []byte
	change              []byte // the key change fragment as sent
	done                app.Value
}

// changeKeysWith runs a session key change for user 1 with update key uk
// (a key status request with sequence seq, the key change with seq+1)
// and returns the new keys and the outstation's answer.
func (m *master) changeKeysWith(seq uint8, uk []byte, fill byte) scriptedKeys {
	m.t.Helper()
	st := m.keyStatus(seq, 1)
	st.MACValue = nil
	msg, _ := app.AppendObjectValue(nil, app.G120V5, st)
	k := scriptedKeys{control: bytes.Repeat([]byte{fill}, 16), monitoring: bytes.Repeat([]byte{fill + 1}, 16)}
	plain, _ := secauth.KeyChangeData(k.control, k.monitoring, msg)
	wrapped, _ := secauth.KeyWrap(uk, plain)
	k.change, _ = req(app.NextSeq(seq), app.FuncAuthRequest,
		app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: 1, WrappedKeys: wrapped})).Encode()
	m.sendRaw(k.change)
	k.done = m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value
	return k
}

// challenge sends the request f, which must be challenged, and returns
// the challenge fragment, its encoding and the request's encoding.
func (m *master) challenge(f *app.Fragment) (*app.Fragment, []byte, []byte) {
	m.t.Helper()
	critical, _ := f.Encode()
	m.sendRaw(critical)
	chf := m.recvFunc(app.FuncAuthResponse)
	if _, ok := chf.Headers[0].Objects[0].Value.(app.AuthChallenge); !ok {
		m.t.Fatalf("no challenge: %v", chf)
	}
	raw, _ := chf.Encode()
	return chf, raw, critical
}

// reply answers the challenge chf (raw) of critical with key.
func (m *master) reply(chf *app.Fragment, raw, critical, key []byte) {
	m.t.Helper()
	ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	mac, _ := secauth.MAC(ch.MAC, key, secauth.AuthData(raw, critical))
	m.send(req(chf.Control.Seq, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 1, MAC: mac})))
}

// badReply answers the challenge chf with a wrong MAC.
func (m *master) badReply(chf *app.Fragment) {
	m.t.Helper()
	ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	m.send(req(chf.Control.Seq, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 1, MAC: make([]byte, 16)})))
}

// stat reads security statistic s (g121v1).
func (m *master) stat(seq uint8, s secauth.Statistic) app.SecurityStatistic {
	m.t.Helper()
	m.send(req(seq, app.FuncRead, app.IndexRange(app.G121V1, uint32(s), uint32(s))))
	return m.recvFunc(app.FuncResponse).Headers[0].Objects[0].Value.(app.SecurityStatistic)
}

// authErr returns the error message of an authentication response, or
// fails.
func authErr(t *testing.T, f *app.Fragment) app.AuthError {
	t.Helper()
	e, ok := f.Headers[0].Objects[0].Value.(app.AuthError)
	if !ok {
		t.Fatalf("no error message: %v", f)
	}
	return e
}

// TestSpec7_5_2_3_1_ChallengeForm: IEEE 1815-2012 clause 7.5.2.3.1, p.207:
// every challenge shall carry new challenge data and a new CSQ, and never
// be retransmitted; CON shall not be set in an Authentication Response
// (p.207). Clause 7.5.2.3.3 a-b, p.211: the CSQ shall be zero at start-up
// and incremented before each challenge. A.45.1, p.720-721: challenge data
// of at least 4 octets, qualifier 0x5B, reason CRITICAL. Table 7-11, p.226:
// the challenge's USR is 0 (unknown). Clause 7.5.1.3, p.192: the challenge
// takes the sequence number of the challenged request.
func TestSpec7_5_2_3_1_ChallengeForm(t *testing.T) {
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 3, Key: testSessionKey}}))
	var prev app.AuthChallenge
	for i, seq := range []uint8{4, 9} {
		chf, raw, critical := m.challenge(req(seq, app.FuncDirectOperate, specCROB))
		h := chf.Headers[0]
		ch := h.Objects[0].Value.(app.AuthChallenge)
		if chf.Control.Seq != seq || chf.Control.CON || h.Qualifier != app.Qual2ByteSizeFreeFormat || ch.User != 0 ||
			ch.Reason != app.ReasonCritical || len(ch.Data) < 4 || ch.CSQ != uint32(i+1) {
			t.Fatalf("challenge %d: %v %+v", i, chf.Control, ch)
		}
		if i > 0 && bytes.Equal(ch.Data, prev.Data) {
			t.Fatal("challenge data repeated")
		}
		prev = ch
		// The reply names the user (3), which the challenge did not.
		mac, _ := secauth.MAC(ch.MAC, testSessionKey, secauth.AuthData(raw, critical))
		m.send(req(seq, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 3, MAC: mac})))
		if f := m.recvFunc(app.FuncResponse); f.Control.Seq != seq {
			t.Fatalf("response %v", f.Control)
		}
	}
}

// TestSpec7_5_2_3_2_A_MandatoryCritical: clause 7.5.2.3.2 a), p.208: the
// function codes marked MANDATORY in Table 7-7 (p.209) shall be considered
// critical; an outstation shall require masters to authenticate them. A
// SecureAuth.Critical list without them is completed.
func TestSpec7_5_2_3_2_A_MandatoryCritical(t *testing.T) {
	for _, fc := range secauth.MandatoryCritical {
		if !slices.Contains(DefaultCritical, fc) {
			t.Errorf("DefaultCritical lacks the mandatory %s", fc)
		}
	}
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{
		User: secauth.User{Number: 1, Key: testSessionKey}, Critical: []app.FunctionCode{app.FuncDirectOperate}}))
	for i, f := range []*app.Fragment{
		req(1, app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.Now()})),
		req(2, app.FuncEnableUnsolicited, app.AllObjects(app.G60V2)),
		req(3, app.FuncDisableUnsolicited, app.AllObjects(app.G60V2)),
		req(4, app.FuncRecordCurrentTime),
	} {
		chf, raw, critical := m.challenge(f)
		m.reply(chf, raw, critical, testSessionKey)
		if r := m.recv(); r.Function != app.FuncResponse || r.Control.Seq != f.Control.Seq {
			t.Fatalf("mandatory %s (%d) after the reply: %v", f.Function, i, r)
		}
	}
	// A READ is not critical.
	m.send(req(6, app.FuncRead, app.AllObjects(app.G1V0)))
	if f := m.recv(); f.Function != app.FuncResponse {
		t.Fatalf("READ: %v", f)
	}
}

// TestSpec7_5_2_4_ErrorMessagesStop: clause 7.4.1.5, p.175 and 7.5.2.4,
// p.223: a device shall stop transmitting error messages once Error
// Messages Sent exceeds Max Error Messages Sent (Table 7-6 #10 threshold 2,
// p.206; Table 7-8 row 6, p.216: an error is sent while the statistic is
// <= the maximum), and start again after a valid session key change (Table
// 7-8 row 24, p.221: reset Max Error Messages Sent). The error carries the
// challenged request's sequence number (7.5.1.3, p.192), the CSQ and USR
// of the reply and the time of the error (A.45.7, p.734).
func TestSpec7_5_2_4_ErrorMessagesStop(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	m.changeKeysWith(0, specUpdateKey, 0x10)
	errorsSeen := 0
	for i := range 5 {
		seq := uint8(2 + i)
		chf, _, _ := m.challenge(req(seq, app.FuncDirectOperate, specCROB))
		ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
		m.badReply(chf)
		select {
		case f := <-m.in:
			e := authErr(t, f)
			if f.Control.Seq != seq || f.Control.CON || e.Code != app.AuthErrAuthenticationFailed || e.CSQ != ch.CSQ || e.User != 1 || e.Time == 0 {
				t.Fatalf("error %d: %v %+v", i, f.Control, e)
			}
			errorsSeen++
		case <-time.After(150 * time.Millisecond):
		}
	}
	if errorsSeen != 3 || h.count() != 0 {
		t.Fatalf("%d error messages for 5 failures (want 3: sent while Error Messages Sent <= 2), %d executed", errorsSeen, h.count())
	}
	if v := m.stat(7, secauth.StatErrorMessagesSent); v.Value != 3 {
		t.Fatalf("error messages sent %d", v.Value)
	}
	// A valid key change re-enables them.
	m.changeKeysWith(8, specUpdateKey, 0x20)
	chf, _, _ := m.challenge(req(10, app.FuncDirectOperate, specCROB))
	m.badReply(chf)
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("after the key change: %+v", e)
	}
}

// TestSpec7_6_1_4_1_ReplyTimeout: clause 7.6.1.4.1, p.242: the reply
// timeout defaults to 2 seconds. Table 7-8 row 7 (Reply Timeout, p.217):
// the challenged request is discarded, Reply Timeouts and Discarded
// Messages counted; past Max Reply Timeouts (threshold 3, Table 7-6 #3)
// the session keys are invalid, COMM_FAIL (row 9, p.217).
func TestSpec7_6_1_4_1_ReplyTimeout(t *testing.T) {
	if DefaultReplyTimeout != 2*time.Second {
		t.Fatalf("default reply timeout %v", DefaultReplyTimeout)
	}
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey},
		ReplyTimeout: 30 * time.Millisecond}))
	m.changeKeysWith(0, specUpdateKey, 0x10)
	for i := range 4 {
		m.challenge(req(uint8(2+i), app.FuncDirectOperate, specCROB))
		time.Sleep(80 * time.Millisecond) // the timer runs without traffic
	}
	if v := m.stat(6, secauth.StatReplyTimeouts); v.Value != 4 || h.count() != 0 {
		t.Fatalf("reply timeouts %d, %d executed", v.Value, h.count())
	}
	if v := m.stat(7, secauth.StatDiscardedMessages); v.Value < 4 {
		t.Fatalf("discarded %d", v.Value)
	}
	if st := m.keyStatus(8, 1); st.Status != app.KeyStatusCommFail {
		t.Fatalf("key status after 4 reply timeouts: %s", st.Status)
	}
}

// TestSpecTable7_8_Row2_3_WaitForReplyDiscards: Table 7-8 rows 2 and 3,
// p.215-216: in Wait for Reply a non-critical request and another
// critical request are discarded and counted as unexpected and discarded
// messages (the critical one also as Critical Messages Received); row 16,
// p.219: so is a key status request. The challenged request still
// executes after the reply.
func TestSpecTable7_8_Row2_3_WaitForReplyDiscards(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}}))
	chf, raw, critical := m.challenge(req(1, app.FuncDirectOperate, specCROB))
	m.send(req(2, app.FuncRead, app.AllObjects(app.G1V0)))
	m.send(req(3, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 1, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})))
	m.send(req(4, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	m.none(100 * time.Millisecond)
	m.reply(chf, raw, critical, testSessionKey)
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 1 || h.count() != 1 || h.indexes()[0] != 0 {
		t.Fatalf("challenged request: %v, executed %v", f, h.indexes())
	}
	if v := m.stat(5, secauth.StatUnexpectedMessages); v.Value != 3 {
		t.Fatalf("unexpected messages %d", v.Value)
	}
	if v := m.stat(6, secauth.StatDiscardedMessages); v.Value != 3 {
		t.Fatalf("discarded messages %d", v.Value)
	}
	if v := m.stat(7, secauth.StatCriticalMessagesReceived); v.Value != 2 {
		t.Fatalf("critical messages received %d", v.Value)
	}
}

// TestSpecTable7_8_Row13_ErrorReceived: Table 7-8 row 13, p.218: an error
// message from the master is counted (Error Messages Rxed); in Wait for
// Reply the challenged request is discarded. Table 7-3, p.188: an error
// may come as AUTHENTICATE_REQ_NO_ACK (0x21), which is not answered.
func TestSpecTable7_8_Row13_ErrorReceived(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}}))
	chf, raw, critical := m.challenge(req(1, app.FuncDirectOperate, specCROB))
	m.send(req(2, app.FuncAuthRequestNoAck, app.FreeFormat(app.G120V7, app.AuthError{User: 1, Code: app.AuthErrAuthenticationFailed})))
	m.none(100 * time.Millisecond)
	m.reply(chf, raw, critical, testSessionKey) // the challenge was dropped: a stray reply
	m.none(100 * time.Millisecond)
	if h.count() != 0 {
		t.Fatal("the challenged request executed after an error message")
	}
	if v := m.stat(3, secauth.StatErrorMessagesReceived); v.Value != 1 {
		t.Fatalf("error messages received %d", v.Value)
	}
	// Anything else in AUTHENTICATE_REQ_NO_ACK is discarded, unanswered.
	m.send(req(4, app.FuncAuthRequestNoAck, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	m.none(100 * time.Millisecond)
}

// TestSpec7_5_3_3_AggressiveAfterValidReply: clause 7.5.3.3, p.224: a
// responder shall not send an aggressive mode request until it has
// successfully replied to a challenge since the session keys were last
// changed; A.45.3.1, p.724. The outstation refuses one before. Clause
// 7.5.2.3.3 e), p.211: the next challenge's CSQ follows the last accepted
// aggressive mode request.
func TestSpec7_5_3_3_AggressiveAfterValidReply(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	k := m.changeKeysWith(0, specUpdateKey, 0x10)
	chf, raw, critical := m.challenge(req(2, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, k.control)
	m.recvFunc(app.FuncResponse)
	csq := chf.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ
	// Valid now.
	m.send(withAggressiveMAC(req(3, app.FuncDirectOperate, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 1, User: 1}), specCROB), raw, k.control))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 || h.count() != 2 {
		t.Fatalf("aggressive mode after a valid reply: %v", f)
	}
	// After a key change, not until a new challenge was answered.
	k = m.changeKeysWith(4, specUpdateKey, 0x30)
	m.send(withAggressiveMAC(req(6, app.FuncDirectOperate, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 2, User: 1}), specCROB), raw, k.control))
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed || h.count() != 2 {
		t.Fatalf("aggressive mode right after a key change: %+v, %d executed", e, h.count())
	}
	chf, raw, critical = m.challenge(req(7, app.FuncDirectOperate, specCROB))
	if got := chf.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ; got != csq+2 {
		t.Fatalf("challenge CSQ %d after aggressive CSQ %d", got, csq+1)
	}
	m.reply(chf, raw, critical, k.control)
	m.recvFunc(app.FuncResponse)
	csq += 2
	m.send(withAggressiveMAC(req(8, app.FuncDirectOperate, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 1, User: 1}), specCROB), raw, k.control))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 8 || h.count() != 4 {
		t.Fatalf("aggressive mode after the new challenge: %v, %d executed", f, h.count())
	}
}

// TestSpec7_6_1_4_7_NoAggressiveMode: clause 7.6.1.4.7, p.244: it shall be
// possible to disable aggressive mode at the outstation. Table 7-8 rows
// 20-21, p.220: the request is discarded and answered with error 4,
// aggressive mode not supported (A.45.7, p.734).
func TestSpec7_6_1_4_7_NoAggressiveMode(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, NoAggressiveMode: true}))
	last := challenged(t, m, 1, specCROB)
	ch, _ := app.Decode(last)
	csq := ch.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ
	m.send(aggressiveReq(2, csq+1, last, testSessionKey, specCROB))
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAggressiveModeNotSupported || e.CSQ != csq+1 || h.count() != 1 {
		t.Fatalf("aggressive mode disabled: %+v, %d executed", e, h.count())
	}
}

// TestSpecA_45_5_KeyStatus: A.45.5, p.728-729: the KSQ shall be zero at
// start-up and incremented on each key status request and each key change
// received, also a refused one; the key status names the requested user
// and the key wrap algorithm of the update key (AES-256 is 2); without
// session keys ever there is no MAC (MAL 0). Table 7-8 row 25, p.221: an
// invalid key change in Security Idle sets AUTH_FAIL (the keys are no
// longer valid, 7.5.2.3.5); its answer is the error message of Table 7-4,
// p.191, carrying the KSQ.
func TestSpecA_45_5_KeyStatus(t *testing.T) {
	uk := []byte("0123456789abcdef0123456789abcdef")
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: uk}}))
	m.send(req(0, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	f := m.recvFunc(app.FuncAuthResponse)
	st := f.Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus)
	if f.Control.CON || f.Control.Seq != 0 { // clause 7.5.2.3.1, p.207: CON is not set
		t.Fatalf("key status control %v", f.Control)
	}
	if st.KSQ != 1 || st.User != 1 || st.KeyWrap != app.KeyWrapAES256 || st.Status != app.KeyStatusNotInit || st.MAC != app.MACNone || len(st.MACValue) != 0 {
		t.Fatalf("first key status %+v", st)
	}
	if st = m.keyStatus(1, 1); st.KSQ != 2 {
		t.Fatalf("second key status KSQ %d", st.KSQ)
	}
	// A refused key change moves the KSQ.
	m.send(req(2, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: 99, User: 1, WrappedKeys: make([]byte, 40)})))
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.CSQ != 99 || e.Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("refused key change: %+v", e)
	}
	if st = m.keyStatus(3, 1); st.KSQ != 4 || st.Status != app.KeyStatusAuthFail {
		t.Fatalf("key status after a refused key change: %+v", st)
	}
}

// TestSpecTable7_8_Row25_InvalidKeyChange: Table 7-8 row 25, p.221 and
// clause 7.5.2.3.5, p.214: after an invalid key change the session keys
// are not valid: a reply with the old control key is refused and the key
// status is AUTH_FAIL. Clause 7.5.5.3, p.239 and A.45.6, p.730: a key
// change wrapping an earlier key status than the last one sent, or naming
// another user, is refused.
func TestSpecTable7_8_Row25_InvalidKeyChange(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	k := m.changeKeysWith(0, specUpdateKey, 0x10)
	if st, ok := k.done.(app.AuthSessionKeyStatus); !ok || st.Status != app.KeyStatusOK {
		t.Fatalf("key change: %+v", k.done)
	}
	// Two key status requests; a key change over the first.
	first := m.keyStatus(2, 1)
	m.keyStatus(3, 1)
	first.MACValue = nil
	msg, _ := app.AppendObjectValue(nil, app.G120V5, first)
	plain, _ := secauth.KeyChangeData(bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16), msg)
	wrapped, _ := secauth.KeyWrap(specUpdateKey, plain)
	m.send(req(4, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: first.KSQ, User: 1, WrappedKeys: wrapped})))
	authErr(t, m.recvFunc(app.FuncAuthResponse))
	// The old keys are no longer valid.
	chf, raw, critical := m.challenge(req(5, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, k.control)
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed || h.count() != 0 {
		t.Fatalf("reply with the keys of before the invalid key change: %+v", e)
	}
	if st := m.keyStatus(6, 1); st.Status != app.KeyStatusAuthFail {
		t.Fatalf("key status %s", st.Status)
	}
	// Another user in the key change.
	st := m.keyStatus(7, 1)
	st.MACValue = nil
	msg, _ = app.AppendObjectValue(nil, app.G120V5, st)
	plain, _ = secauth.KeyChangeData(bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16), msg)
	wrapped, _ = secauth.KeyWrap(specUpdateKey, plain)
	m.send(req(8, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: 2, WrappedKeys: wrapped})))
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("key change for another user: %+v", e)
	}
}

// TestSpecTable7_8_Row9_CommFail: Table 7-8 row 9, p.217 and clause
// 7.6.1.4.10, p.246: when the connection ends the session keys are no
// longer valid, COMM_FAIL. A.45.5, p.729: the key status MAC is computed
// with the last valid monitoring key over the last key change whether the
// keys are valid or not.
func TestSpecTable7_8_Row9_CommFail(t *testing.T) {
	h := &countingHandler{}
	srv, addr := saServer(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	m := dialMaster(t, srv, addr)
	k := m.changeKeysWith(0, specUpdateKey, 0x10)
	m.close()
	time.Sleep(50 * time.Millisecond)
	n := dialMaster(t, srv, addr)
	st := n.keyStatus(0, 1)
	want, _ := secauth.MAC(st.MAC, k.monitoring, k.change)
	if st.Status != app.KeyStatusCommFail || !secauth.Equal(want, st.MACValue) {
		t.Fatalf("key status after the reconnect: %+v", st)
	}
	chf, raw, critical := n.challenge(req(1, app.FuncDirectOperate, specCROB))
	n.reply(chf, raw, critical, k.control)
	if e := authErr(t, n.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed || h.count() != 0 {
		t.Fatalf("reply with the keys of the last connection: %+v", e)
	}
}

// TestSpec7_6_1_4_5_ExpectedKeyChange: clause 7.6.1.4.5, p.243-244: the
// outstation shall invalidate the session keys if they were not changed
// within the expected interval or message count; Table 7-8 row 15, p.219:
// NOT_INIT. Defaults twice the master's (30 minutes, 2000).
func TestSpec7_6_1_4_5_ExpectedKeyChange(t *testing.T) {
	if DefaultExpectedKeyChangeInterval != 30*time.Minute || DefaultExpectedKeyChangeCount != 2000 {
		t.Fatal("expected key change defaults")
	}
	h := &countingHandler{}
	// By count: a challenge and its reply are two messages.
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey},
		ExpectedKeyChangeCount: 2, ExpectedKeyChangeInterval: -1}))
	k := m.changeKeysWith(0, specUpdateKey, 0x10)
	chf, raw, critical := m.challenge(req(2, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, k.control)
	m.recvFunc(app.FuncResponse)
	chf, raw, critical = m.challenge(req(3, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, k.control)
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed || h.count() != 1 {
		t.Fatalf("past the expected count: %+v, %d executed", e, h.count())
	}
	if st := m.keyStatus(4, 1); st.Status != app.KeyStatusNotInit {
		t.Fatalf("key status past the expected count: %s", st.Status)
	}
	// By interval.
	n := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey},
		ExpectedKeyChangeInterval: 50 * time.Millisecond}))
	n.changeKeysWith(0, specUpdateKey, 0x10)
	time.Sleep(80 * time.Millisecond)
	if st := n.keyStatus(2, 1); st.Status != app.KeyStatusNotInit {
		t.Fatalf("key status past the expected interval: %s", st.Status)
	}
	// A pre-shared session key does not expire.
	p := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey},
		ExpectedKeyChangeCount: 1}))
	for seq := range uint8(2) {
		challenged(t, p, seq+1, specCROB)
	}
}

// syncBuffer is a log sink for tests.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestSpec7_6_1_4_6_MaxKeyStatusRequests: clause 7.6.1.4.6, p.244: past
// the maximum number of session key status requests within the expected
// key change interval the outstation shall alert a human (here: an error
// in the log); the maximum ranges from 2 to 255, default 5.
func TestSpec7_6_1_4_6_MaxKeyStatusRequests(t *testing.T) {
	if DefaultMaxKeyStatusRequests != 5 {
		t.Fatal("default max key status requests")
	}
	for _, n := range []int{1, 256, -1} {
		if _, err := New(WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}, MaxKeyStatusRequests: n})); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("max key status requests %d accepted", n)
		}
	}
	var logs syncBuffer
	m := newMaster(t, WithLogger(dnp3.NewSlogLogger(slog.NewTextHandler(&logs, nil))),
		WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}, MaxKeyStatusRequests: 2}))
	for seq := range uint8(2) {
		m.keyStatus(seq, 1)
	}
	if strings.Contains(logs.String(), "max session key status requests exceeded") {
		t.Fatal("alert within the maximum")
	}
	m.keyStatus(2, 1) // answered all the same
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "max session key status requests exceeded") {
		t.Fatalf("no alert past the maximum: %s", logs.String())
	}
}

// TestSpecTable7_8_Row10_MaxAuthFailures: Table 7-8 rows 10-12, p.217-218:
// once Authentication Failures exceeds Max Authentication Failures, the
// session keys become invalid (AUTH_FAIL) and Rekeys Due to Authentication
// Failure is counted, while it has not exceeded Max Authentication
// Rekeys; past that, a TCP connection is closed. The thresholds are set
// per statistic (clause 7.6.1.4.2, p.242).
func TestSpecTable7_8_Row10_MaxAuthFailures(t *testing.T) {
	for _, th := range []map[secauth.Statistic]uint16{{secauth.StatReplyTimeouts: 0}, {secauth.NumStatistics: 1}} {
		if _, err := New(WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, Thresholds: th})); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("thresholds %v accepted", th)
		}
	}
	if _, err := New(WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, StatisticsThreshold: 70000})); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("statistics threshold 70000 accepted")
	}
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey},
		Thresholds: map[secauth.Statistic]uint16{secauth.StatAuthenticationFailures: 1, secauth.StatRekeysDueToAuthFailure: 1}}))
	m.changeKeysWith(0, specUpdateKey, 0x10)
	seq := uint8(2)
	fail := func() {
		chf, _, _ := m.challenge(req(seq, app.FuncDirectOperate, specCROB))
		seq = app.NextSeq(seq)
		m.badReply(chf)
		m.drain(50 * time.Millisecond) // the error message, while they are sent
	}
	fail()
	if st := m.keyStatus(seq, 1); st.Status != app.KeyStatusOK {
		t.Fatalf("within Max Authentication Failures: %s", st.Status)
	}
	seq = app.NextSeq(seq)
	fail() // 2 > 1: AUTH_FAIL, rekey 1
	if st := m.keyStatus(seq, 1); st.Status != app.KeyStatusAuthFail {
		t.Fatalf("past Max Authentication Failures: %s", st.Status)
	}
	seq = app.NextSeq(seq)
	if v := m.stat(seq, secauth.StatRekeysDueToAuthFailure); v.Value != 1 {
		t.Fatalf("rekeys due to authentication failure %d", v.Value)
	}
	seq = app.NextSeq(seq)
	for range 4 { // rekey 2, then past Max Authentication Rekeys
		fail()
	}
	select {
	case <-m.ch.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the TCP connection was not closed past Max Authentication Rekeys")
	}
}

// TestSpec7_5_2_2_Statistics: Table 7-6, p.206: Total Messages Received
// counts every application fragment, CONFIRMs included (#6); Session Key
// Changes and Failed Session Key Changes are counted (#13, #14). A.46,
// p.759 and 7.5.2.2, p.205: Association ID 0 is the association the
// statistic is reported on. A.47.1, p.760: g122v1 (without time) on
// request.
func TestSpec7_5_2_2_Statistics(t *testing.T) {
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey},
		StatisticsThreshold: 1, StatisticsClass: 2}))
	before := m.stat(0, secauth.StatTotalMessagesReceived)
	m.send(confirm(0, false))
	m.send(confirm(0, true))
	time.Sleep(30 * time.Millisecond)
	if after := m.stat(1, secauth.StatTotalMessagesReceived); after.Value != before.Value+3 || after.Association != 0 {
		t.Fatalf("total messages received %d after %d and two CONFIRMs, association %d", after.Value, before.Value, after.Association)
	}
	m.changeKeysWith(2, specUpdateKey, 0x10)
	m.send(req(4, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: 99, User: 1, WrappedKeys: make([]byte, 40)})))
	m.recvFunc(app.FuncAuthResponse)
	if v := m.stat(5, secauth.StatSessionKeyChanges); v.Value != 1 {
		t.Fatalf("session key changes %d", v.Value)
	}
	if v := m.stat(6, secauth.StatFailedSessionKeyChanges); v.Value != 1 {
		t.Fatalf("failed session key changes %d", v.Value)
	}
	m.send(req(7, app.FuncRead, app.AllObjects(app.G122V1)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) == 0 {
		t.Fatal("no g122v1 events")
	}
	for _, h := range f.Headers {
		if h.GV != app.G122V1 {
			t.Fatalf("event read returned %s", h.GV)
		}
		for _, o := range h.Objects {
			if v := o.Value.(app.SecurityStatistic); v.Association != 0 || v.Flags&app.FlagOnline == 0 {
				t.Fatalf("event %+v", v)
			}
		}
	}
}

// TestSpec7_5_2_3_3_A_RestartZeroes: clause 7.5.2.3.3 a), p.211: the CSQ
// shall be zero on start-up; A.45.5, p.728: so shall the KSQ. Server.Restart
// behaves as a restart: the next challenge takes CSQ 1, the next key
// status KSQ 1.
func TestSpec7_5_2_3_3_A_RestartZeroes(t *testing.T) {
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	k := m.changeKeysWith(0, specUpdateKey, 0x10)
	chf, raw, critical := m.challenge(req(2, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, k.control)
	m.recvFunc(app.FuncResponse)
	m.srv.Restart()
	time.Sleep(30 * time.Millisecond)
	if st := m.keyStatus(3, 1); st.KSQ != 1 || st.Status != app.KeyStatusNotInit {
		t.Fatalf("key status after the restart: %+v", st)
	}
	chf, _, _ = m.challenge(req(4, app.FuncDirectOperate, specCROB))
	if ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge); ch.CSQ != 1 {
		t.Fatalf("challenge CSQ %d after the restart", ch.CSQ)
	}
}

// TestSpecTableA_9_AggressiveMACCoverage: A.45.9 and Table A-9, p.742 and
// p.784: the MAC of an aggressive mode request covers the challenge and
// the whole request up to the MAC value, the g120v9 object header and
// size prefix included. A MAC that stops before the g120v9 object is
// refused.
func TestSpecTableA_9_AggressiveMACCoverage(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}}))
	last := challenged(t, m, 1, specCROB)
	ch, _ := app.Decode(last)
	csq := ch.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ
	// Without the g120v9 header in the MAC: refused.
	short := req(2, app.FuncDirectOperate, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 1, User: 1}), specCROB)
	b, _ := short.Encode()
	mac, _ := secauth.MAC(app.MACHMACSHA256Trunc16, testSessionKey, secauth.AuthData(last, b))
	short.Headers = append(short.Headers, app.FreeFormat(app.G120V9, app.AuthMAC{MAC: mac}))
	m.send(short)
	if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAuthenticationFailed || h.count() != 1 {
		t.Fatalf("MAC without the g120v9 header: %+v, %d executed", e, h.count())
	}
	// Covering it: executed.
	m.send(aggressiveReq(3, csq+1, last, testSessionKey, specCROB))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 || h.count() != 2 {
		t.Fatalf("Table A-9 MAC: %v, %d executed", f, h.count())
	}
}

// TestSpecTable7_8_Row17_22_AggressiveInWaitForReply: Table 7-8 row 17,
// p.219: a valid aggressive mode request in Wait for Reply is executed and
// the challenged request discarded; row 22, p.220: an invalid one in Wait
// for Reply is discarded without an error message, and counted as an
// authentication failure.
func TestSpecTable7_8_Row17_22_AggressiveInWaitForReply(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}}))
	last := challenged(t, m, 1, specCROB)
	ch, _ := app.Decode(last)
	csq := ch.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ
	// A challenge waits; an invalid aggressive mode request.
	chf, raw, critical := m.challenge(req(2, app.FuncDirectOperate, specCROB))
	m.send(aggressiveReq(3, csq+2, last, []byte("another session key, 32 octets!"), specCROB))
	m.none(100 * time.Millisecond)
	// The challenge still waits: its reply executes the request.
	m.reply(chf, raw, critical, testSessionKey)
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 2 || h.count() != 2 {
		t.Fatalf("challenged request after an invalid aggressive one: %v, %d executed", f, h.count())
	}
	if v := m.stat(4, secauth.StatAuthenticationFailures); v.Value != 1 {
		t.Fatalf("authentication failures %d", v.Value)
	}
	// A challenge waits; a valid aggressive mode request, over that last
	// challenge, replaces it.
	chf, raw, _ = m.challenge(req(5, app.FuncDirectOperate, specCROB))
	ch5 := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	m.send(aggressiveReq(6, ch5.CSQ+1, raw, testSessionKey, specCROB))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 6 || h.count() != 3 {
		t.Fatalf("valid aggressive mode request in Wait for Reply: %v, %d executed", f, h.count())
	}
	m.none(100 * time.Millisecond)
}

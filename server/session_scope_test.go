// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// Tests of what a session that is not the master's current one can do to
// the master's association: broadcasts of secure authentication messages,
// refused aggressive mode broadcasts, and the goroutine that watches the
// current session.

// statOf reads statistic s of the association.
func statOf(t *testing.T, a *association, s secauth.Statistic) uint32 {
	t.Helper()
	return onAssoc(t, a, func() uint32 { return a.stats[s] })
}

// waitStat waits until statistic s of the association reaches n.
func waitStat(t *testing.T, a *association, s secauth.Statistic, n uint32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for statOf(t, a, s) < n {
		if time.Now().After(deadline) {
			t.Fatalf("statistic %d: %d, want %d", s, statOf(t, a, s), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// noneQueued fails if the master has received a fragment.
func (m *master) noneQueued() {
	m.t.Helper()
	select {
	case f := <-m.in:
		m.t.Fatalf("unasked fragment %s", f)
	default:
	}
}

// udpPeer serves srv on a UDP socket and returns a session of master 1
// sending to it.
func udpPeer(t *testing.T, srv *Server) *channel.Session {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeUDP(pc) }()
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := udpMaster(t, conn)
	return sess
}

func sendBroadcastOn(t *testing.T, sess *channel.Session, f *app.Fragment) {
	t.Helper()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.SendBroadcast(context.Background(), b, link.BroadcastNoConfirm); err != nil {
		t.Fatal(err)
	}
}

// TestBroadcastAuthRequestDiscarded: AUTHENTICATE_REQ and
// AUTHENTICATE_REQ_NO_ACK to a broadcast address are discarded and
// counted, never answered, and change no key (IEEE 1815-2012 4.7, Table
// 4-16; clause 7.5): from another connection that spoofs the master's
// address, and from the master's own.
func TestBroadcastAuthRequestDiscarded(t *testing.T) {
	h := &countingHandler{}
	srv, addr := saServer(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	m := dialMaster(t, srv, addr)
	k := m.changeKeysWith(0, specUpdateKey, 0x10)
	if s, ok := k.done.(app.AuthSessionKeyStatus); !ok || s.Status != app.KeyStatusOK {
		t.Fatalf("key change: %+v", k.done)
	}
	a := srv.association(1)
	discarded := statOf(t, a, secauth.StatDiscardedMessages)

	junk := req(0, app.FuncAuthRequest, app.FreeFormat(app.G120V6,
		app.AuthSessionKeyChange{KSQ: 77, User: 1, WrappedKeys: make([]byte, 24)}))
	n := dialMaster(t, srv, addr) // another connection with the master's address
	n.sendBroadcast(junk)
	waitStat(t, a, secauth.StatDiscardedMessages, discarded+1)

	// On the master's own connection: a key status request, an error
	// message without acknowledgement and a challenge reply.
	m.sendBroadcast(req(2, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	m.sendBroadcast(req(3, app.FuncAuthRequestNoAck, app.FreeFormat(app.G120V7, app.AuthError{CSQ: 1, User: 1, Code: app.AuthErrAuthenticationFailed})))
	m.sendBroadcast(req(4, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: 1, User: 1, MAC: make([]byte, 16)})))
	waitStat(t, a, secauth.StatDiscardedMessages, discarded+4)
	if got := statOf(t, a, secauth.StatUnexpectedMessages); got < 4 {
		t.Fatalf("unexpected messages %d, want at least 4", got)
	}
	m.noneQueued()

	// The keys still stand: the key status is OK and a challenged
	// operate with them is executed.
	if st := m.keyStatus(5, 1); st.Status != app.KeyStatusOK {
		t.Fatalf("key status after the broadcasts: %v", st.Status)
	}
	chf, raw, critical := m.challenge(req(6, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, k.control)
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 6 || h.count() != 1 {
		t.Fatalf("operate after the broadcasts: %v, %d executed", f, h.count())
	}
	select {
	case <-m.ch.Done():
		t.Fatal("master's connection closed")
	default:
	}
}

// TestBroadcastAuthRequestWithoutSecureAuthentication: without secure
// authentication a broadcast AUTHENTICATE_REQ is not answered either.
func TestBroadcastAuthRequestWithoutSecureAuthentication(t *testing.T) {
	m := newMaster(t)
	m.sendBroadcast(req(0, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	// A READ after it is answered first: the broadcast had no answer.
	m.send(req(1, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 1 {
		t.Fatalf("answer %v", f)
	}
}

// TestRefusedAggressiveBroadcastFromOtherSession: refused aggressive mode
// broadcasts that come on a session other than the master's current one
// are discarded: they do not count as the master's authentication
// failures, so they neither make its keys invalid nor close its TCP
// connection (Table 7-8 rows 10..12). A valid one from there, a master on
// TCP broadcasting over UDP (13.2.3.2.4), is still carried out.
func TestRefusedAggressiveBroadcastFromOtherSession(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}}))
	last := challenged(t, m, 1, specCROB)
	ch, _ := app.Decode(last)
	csq := ch.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ
	a := m.srv.association(1)
	udp := udpPeer(t, m.srv)

	failures := statOf(t, a, secauth.StatAuthenticationFailures)
	discarded := statOf(t, a, secauth.StatDiscardedMessages)
	bad := req(0, app.FuncDirectOperateNoAck,
		app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 1, User: 1}), specCROB,
		app.FreeFormat(app.G120V9, app.AuthMAC{MAC: make([]byte, 16)}))
	// Far past Max Authentication Failures times Max Authentication
	// Rekeys with the default thresholds.
	const n = 60
	for range n {
		sendBroadcastOn(t, udp, bad)
		discarded++
		waitStat(t, a, secauth.StatDiscardedMessages, discarded)
	}
	if got := statOf(t, a, secauth.StatAuthenticationFailures); got != failures {
		t.Fatalf("authentication failures %d, want %d", got, failures)
	}
	if got := statOf(t, a, secauth.StatRekeysDueToAuthFailure); got != 0 {
		t.Fatalf("rekeys due to authentication failures %d", got)
	}
	select {
	case <-m.ch.Done():
		t.Fatal("master's connection closed")
	default:
	}
	m.noneQueued()

	// A valid broadcast in aggressive mode over UDP is carried out.
	sendBroadcastOn(t, udp, withAggressiveMAC(req(0, app.FuncDirectOperateNoAck,
		app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 1, User: 1}), specCROB), last, testSessionKey))
	waitStat(t, a, secauth.StatSuccessfulAuthentications, 2)
	if h.count() != 2 {
		t.Fatalf("%d controls executed, want 2", h.count())
	}
	// The master's connection still works.
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 2 {
		t.Fatalf("read after the broadcasts: %v", f)
	}
}

// TestKeyStatusRequestOtherUserKeepsKSQ: a key status request for a user
// the outstation does not have is answered AUTH_FAIL and does not move the
// KSQ of its user, whose key change that follows succeeds (A.45.5).
func TestKeyStatusRequestOtherUserKeepsKSQ(t *testing.T) {
	srv, addr := saServer(t, WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	m := dialMaster(t, srv, addr)
	st := m.keyStatus(0, 1)
	if other := m.keyStatus(1, 9); other.Status != app.KeyStatusAuthFail || other.User != 9 || other.KSQ != st.KSQ {
		t.Fatalf("other user: %+v, KSQ want %d", other, st.KSQ)
	}
	// The key change answers the first status: same KSQ.
	st.MACValue = nil
	msg, _ := app.AppendObjectValue(nil, app.G120V5, st)
	plain, _ := secauth.KeyChangeData(make([]byte, 16), make([]byte, 16), msg)
	wrapped, _ := secauth.KeyWrap(specUpdateKey, plain)
	m.send(req(2, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: 1, WrappedKeys: wrapped})))
	v, ok := m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus)
	if !ok || v.Status != app.KeyStatusOK || v.KSQ != st.KSQ+1 {
		t.Fatalf("key change after the other user's request: %+v", v)
	}
}

// TestSessionWatcherBounded: the association watches its current session
// with one goroutine. A master that alternates between a TCP connection
// and a long-lived UDP socket does not add one per switch.
func TestSessionWatcherBounded(t *testing.T) {
	srv, err := New(WithMasters(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeUDP(pc) }()
	go func() { _ = srv.Serve(l) }()
	uconn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	usess, in := udpMaster(t, uconn)
	seq := uint8(0)
	read := func() {
		t.Helper()
		seq = app.NextSeq(seq)
		b, _ := req(seq, app.FuncRead, app.ClassHeaders(0)...).Encode()
		if err := usess.Send(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		recvResponse(t, in)
	}
	a := srv.association(1)
	current := func() *channel.Session {
		return onAssoc(t, a, func() *channel.Session { return a.sess })
	}
	wait := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(time.Millisecond)
		}
	}
	read()
	const cycles = 20
	for range cycles {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		wait("TCP connection not taken", func() bool { s := current(); return s != nil && !s.Channel().Datagram() })
		_ = c.Close()
		wait("TCP connection not forgotten", func() bool { return current() == nil })
		read()
		wait("UDP session not taken", func() bool { s := current(); return s != nil && s.Channel().Datagram() })
		wait("watchers not bounded", func() bool { return a.watchers.Load() == 1 })
	}
	_ = srv.Close()
	wait("watchers left after Close", func() bool { return a.watchers.Load() == 0 })
}

// TestUnsolicitedTakesOneFragment: an unsolicited response is one
// fragment; with more events than fit, each response carries the next
// ones in order until every event was reported once.
func TestUnsolicitedTakesOneFragment(t *testing.T) {
	m := newMaster(t, WithMaxFragment(249, 2048), WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1}}))
	n := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(n.Control.Seq, true))
	const events = DefaultEventLimit
	err := m.srv.Database().Batch(func(b *Batch) error {
		for i := range events {
			if err := b.Update(BinaryInput, 0, app.Binary{Value: i%2 == 0, Flags: app.FlagOnline}, EventForce); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, responses := 0, 0
	for got < events {
		f := m.recvFunc(app.FuncUnsolicitedResponse)
		if b, _ := f.Encode(); len(b) > 249 || !f.Control.FIR || !f.Control.FIN {
			t.Fatalf("unsolicited response of %d octets: %s", len(b), f)
		}
		for _, h := range f.Headers {
			for _, o := range h.Objects {
				if v, ok := o.Value.(app.Binary); !ok || v.Value != (got%2 == 0) {
					t.Fatalf("event %d out of order: %+v", got, o.Value)
				}
				got++
			}
		}
		responses++
		m.send(confirm(f.Control.Seq, true))
	}
	if got != events || responses < 2 {
		t.Fatalf("%d events in %d responses", got, responses)
	}
	m.none(100 * time.Millisecond)
}

// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

var testSessionKey = []byte("pre-shared session key 32 octets")

// challenged runs one challenged direct operate and returns the encoded
// challenge, over which aggressive mode MACs are computed.
func challenged(t *testing.T, m *master, seq uint8, crob app.Header) []byte {
	t.Helper()
	critical, _ := req(seq, app.FuncDirectOperate, crob).Encode()
	m.sendRaw(critical)
	chf := m.recvFunc(app.FuncAuthResponse)
	raw, _ := chf.Encode()
	ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	mac, _ := secauth.MAC(app.MACHMACSHA256Trunc16, testSessionKey, secauth.AuthData(raw, critical))
	m.send(req(seq, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 1, MAC: mac})))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != seq {
		t.Fatalf("response to the challenged request with sequence %d, want %d", f.Control.Seq, seq)
	}
	return raw
}

// aggressiveReq builds an aggressive mode request with the MAC over last
// and the request computed with key.
func aggressiveReq(seq uint8, csq uint32, last, key []byte, hs ...app.Header) *app.Fragment {
	f := req(seq, app.FuncDirectOperate, append([]app.Header{app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq, User: 1})}, hs...)...)
	b, _ := f.Encode()
	mac, _ := secauth.MAC(app.MACHMACSHA256Trunc16, key, secauth.AuthData(last, b))
	f.Headers = append(f.Headers, app.FreeFormat(app.G120V9, app.AuthMAC{MAC: mac}))
	return f
}

func TestAggressiveMode(t *testing.T) {
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}}))

	// Before any challenge there is nothing to compute the MAC over.
	m.send(aggressiveReq(1, 1, []byte{1}, testSessionKey, crob))
	if f := m.recvFunc(app.FuncAuthResponse); f.Headers[0].Objects[0].Value.(app.AuthError).Code != app.AuthErrAuthenticationFailed || h.count() != 0 {
		t.Fatalf("aggressive mode before a challenge: %v", f)
	}
	last := challenged(t, m, 2, crob)
	ch, _ := app.Decode(last)
	csq := ch.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ

	// Executed without a challenge; each request takes the next CSQ.
	for i, seq := range []uint8{3, 4} {
		m.send(aggressiveReq(seq, csq+uint32(i)+1, last, testSessionKey, crob))
		if f := m.recvFunc(app.FuncResponse); f.Control.Seq != seq || len(f.Headers) != 1 || f.Headers[0].GV != app.G12V1 {
			t.Fatalf("aggressive mode request %d: %v", i, f)
		}
	}
	if h.count() != 3 {
		t.Fatalf("%d controls executed, want 3", h.count())
	}
	// A repeated CSQ, a wrong key and a MAC over the wrong challenge are
	// refused and execute nothing.
	for name, f := range map[string]*app.Fragment{
		"repeated CSQ":    aggressiveReq(5, csq+2, last, testSessionKey, crob),
		"wrong key":       aggressiveReq(6, csq+3, last, []byte("another session key, 32 octets!"), crob),
		"wrong challenge": aggressiveReq(7, csq+3, []byte("another challenge"), testSessionKey, crob),
	} {
		m.send(f)
		if r := m.recvFunc(app.FuncAuthResponse); r.Headers[0].Objects[0].Value.(app.AuthError).Code != app.AuthErrAuthenticationFailed {
			t.Fatalf("%s: %v", name, r)
		}
	}
	// Without the closing MAC it is malformed.
	m.send(req(8, app.FuncDirectOperate, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 3, User: 1}), crob))
	if r := m.recvFunc(app.FuncAuthResponse); r.Headers[0].GV != app.G120V7 {
		t.Fatalf("aggressive mode without MAC: %v", r)
	}
	if h.count() != 3 {
		t.Fatalf("refused requests executed: %d controls", h.count())
	}
	// A new challenge restarts the sequence from its CSQ.
	last = challenged(t, m, 9, crob)
	ch, _ = app.Decode(last)
	csq = ch.Headers[0].Objects[0].Value.(app.AuthChallenge).CSQ
	m.send(aggressiveReq(10, csq+1, last, testSessionKey, crob))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 10 || h.count() != 5 {
		t.Fatalf("aggressive mode after a new challenge: %v, %d controls", f, h.count())
	}
}

func TestSecurityStatistics(t *testing.T) {
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{
		User: secauth.User{Number: 1, Key: testSessionKey}, StatisticsThreshold: 2, StatisticsClass: 2}))
	challenged(t, m, 1, crob)
	challenged(t, m, 2, crob)
	// A wrong reply: an authentication failure and an error message sent.
	critical, _ := req(3, app.FuncDirectOperate, crob).Encode()
	m.sendRaw(critical)
	ch := m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthChallenge)
	m.send(req(3, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 1, MAC: make([]byte, 16)})))
	m.recvFunc(app.FuncAuthResponse)

	m.send(req(4, app.FuncRead, app.AllObjects(app.G121V0)))
	f := m.recvFunc(app.FuncResponse)
	stats := map[secauth.Statistic]uint32{}
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			stats[secauth.Statistic(o.Index)] = o.Value.(app.SecurityStatistic).Value
		}
	}
	if len(stats) != int(secauth.NumStatistics) {
		t.Fatalf("%d statistics read, want %d", len(stats), secauth.NumStatistics)
	}
	want := map[secauth.Statistic]uint32{
		secauth.StatCriticalMessagesReceived:  3,
		secauth.StatSuccessfulAuthentications: 2,
		secauth.StatAuthenticationFailures:    1,
		secauth.StatErrorMessagesSent:         1,
		secauth.StatSessionKeyChanges:         0,
	}
	for s, v := range want {
		if stats[s] != v {
			t.Errorf("%s = %d, want %d", s, stats[s], v)
		}
	}
	if stats[secauth.StatTotalMessagesReceived] < 7 {
		t.Errorf("total messages received %d", stats[secauth.StatTotalMessagesReceived])
	}
	// A range read, and indexes past the table.
	m.send(req(5, app.FuncRead, app.IndexRange(app.G121V1, 12, 13)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || len(f.Headers[0].Objects) != 2 || f.IIN.Has(app.IINParameterError) {
		t.Fatalf("range read: %v", f)
	}
	m.send(req(6, app.FuncRead, app.IndexRange(app.G121V1, 17, 30)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("read past the table without PARAMETER_ERROR: %v", f)
	}
	m.send(req(6, app.FuncRead, app.IndexList(app.G121V1, 2, 12)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || len(f.Headers[0].Objects) != 2 ||
		f.Headers[0].Objects[0].Index != 2 || f.Headers[0].Objects[1].Index != 12 {
		t.Fatalf("index list read: %v", f)
	}
	m.send(req(6, app.FuncRead, app.IndexRange(app.G121V1, 30, 40)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 || !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("read of no statistic: %v", f)
	}
	if _, err := New(WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, StatisticsClass: 4})); err == nil {
		t.Fatal("statistics class 4 accepted")
	}
	// Every second increment of a statistic is a class 2 event (g122v2).
	m.send(req(7, app.FuncRead, app.AllObjects(app.G60V3)))
	f = m.recvFunc(app.FuncResponse)
	events := map[uint32]bool{}
	for _, h := range f.Headers {
		if h.GV != app.G122V2 {
			t.Fatalf("class 2 read returned %s", h.GV)
		}
		for _, o := range h.Objects {
			events[o.Index] = true
		}
	}
	if !events[uint32(secauth.StatSuccessfulAuthentications)] || !events[uint32(secauth.StatCriticalMessagesReceived)] {
		t.Fatalf("statistic events %v", events)
	}
	// Database points of the type are refused, and without secure
	// authentication there are no statistics.
	o := newMaster(t)
	if err := o.srv.Database().Add(SecurityStatistic, 0, PointConfig{}, app.SecurityStatistic{}); err == nil {
		t.Fatal("security statistic added to the database")
	}
	o.send(req(1, app.FuncRead, app.AllObjects(app.G121V0)))
	if f := o.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("statistics without secure authentication: %v", f)
	}
	if secauth.StatRekeysDueToRestarts.String() != "rekeys due to restarts" || secauth.Statistic(99).String() != "statistic 99" {
		t.Fatal("statistic names")
	}

}

// TestReplyTimeout: a reply that comes after SecureAuth.ReplyTimeout is
// refused, counted, and the critical request is not executed.
func TestReplyTimeout(t *testing.T) {
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{
		User: secauth.User{Number: 1, Key: testSessionKey}, ReplyTimeout: 20 * time.Millisecond}))
	critical, _ := req(1, app.FuncDirectOperate, crob).Encode()
	m.sendRaw(critical)
	chf := m.recvFunc(app.FuncAuthResponse)
	raw, _ := chf.Encode()
	ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	mac, _ := secauth.MAC(app.MACHMACSHA256Trunc16, testSessionKey, secauth.AuthData(raw, critical))
	time.Sleep(50 * time.Millisecond)
	m.send(req(1, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 1, MAC: mac})))
	if f := m.recvFunc(app.FuncAuthResponse); f.Headers[0].GV != app.G120V7 || h.count() != 0 {
		t.Fatalf("late reply: %v, %d executed", f, h.count())
	}
	m.send(req(2, app.FuncRead, app.IndexRange(app.G121V1, uint32(secauth.StatReplyTimeouts), uint32(secauth.StatReplyTimeouts))))
	if v := m.recvFunc(app.FuncResponse).Headers[0].Objects[0].Value.(app.SecurityStatistic); v.Value != 1 {
		t.Fatalf("reply timeouts %d", v.Value)
	}
	// A master's authentication error is counted as received.
	m.send(req(3, app.FuncAuthRequest, app.FreeFormat(app.G120V7, app.AuthError{User: 1, Code: app.AuthErrAuthenticationFailed})))
	m.send(req(4, app.FuncRead, app.IndexRange(app.G121V1, uint32(secauth.StatErrorMessagesReceived), uint32(secauth.StatErrorMessagesReceived))))
	if v := m.recvFunc(app.FuncResponse).Headers[0].Objects[0].Value.(app.SecurityStatistic); v.Value != 1 {
		t.Fatalf("error messages received %d", v.Value)
	}
}

// SPDX-License-Identifier: MIT

package e2e

import (
	"errors"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// End-to-end spec tests of Secure Authentication between this library's
// master and outstation (IEEE 1815-2012 clause 7). Page numbers are the
// printed ones.

// outstationStat reads security statistic s from the outstation (g121).
func outstationStat(t *testing.T, c *client.Client, s secauth.Statistic) uint32 {
	t.Helper()
	res, err := c.Read(ctx(t), app.IndexRange(app.G121V1, uint32(s), uint32(s)))
	if err != nil {
		t.Fatal(err)
	}
	return res.Headers()[0].Objects[0].Value.(app.SecurityStatistic).Value
}

// TestSpec7_5_2_3_2_A_MandatoryCriticalE2E: clause 7.5.2.3.2 a), p.208 and
// Table 7-7, p.209: the MANDATORY function codes are challenged even when
// SecureAuth.Critical does not list them; the master answers and the
// request succeeds.
func TestSpec7_5_2_3_2_A_MandatoryCriticalE2E(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(&relay{}), server.WithSecureAuthentication(server.SecureAuth{
		User: secauth.User{Number: 1, Key: authKey}, Critical: []app.FunctionCode{app.FuncDirectOperate}})},
		client.WithSecureAuthentication(secauth.User{Number: 1, Key: authKey}), client.WithAutoClearRestart(false))
	if err := p.c.ClearRestart(ctx(t)); err != nil { // a WRITE
		t.Fatal(err)
	}
	// Without unsolicited responses configured the outstation answers
	// NO_FUNC_CODE_SUPPORT, after the challenge.
	var ie *dnp3.IINError
	if err := p.c.EnableUnsolicited(ctx(t), 1); !errors.As(err, &ie) {
		t.Fatal(err)
	}
	if n := outstationStat(t, p.c, secauth.StatSuccessfulAuthentications); n != 2 {
		t.Fatalf("%d successful authentications for WRITE and ENABLE_UNSOLICITED", n)
	}
	if n := p.c.SecurityStatistics()[secauth.StatCriticalMessagesSent]; n != 2 {
		t.Fatalf("master: %d critical messages sent", n)
	}
}

// TestSpec7_5_2_3_2_I_NoAckE2E: clause 7.5.2.3.2 i), p.208: the master
// waits for the challenge of a DIRECT_OPERATE_NR and answers it; the
// outstation executes the control.
func TestSpec7_5_2_3_2_I_NoAckE2E(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: authKey}})},
		client.WithSecureAuthentication(secauth.User{Number: 1, Key: authKey}))
	if _, err := p.c.Operate(ctx(t), client.DirectOperateNoAck, client.CROB(2, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "no-ack control executed", func() bool { _, op, _ := r.snapshot(); return len(op) == 1 })
	if _, _, ops := r.snapshot(); ops[0] != server.DirectOperateNoAck {
		t.Fatalf("operate type %v", ops[0])
	}
}

// TestSpec7_5_4_2_RestartRecovery: clause 7.5.4.2, p.225: the master
// re-initializes the session keys when the outstation restarts; clause
// 7.5.3.3, p.224: aggressive mode resumes only after a challenge answered
// with the new keys. With aggressive mode the client recovers in a few
// round trips, without a storm of refused requests and key changes (Table
// 7-6 #4 and #17 bound the rekeys).
func TestSpec7_5_4_2_RestartRecovery(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: updateKey}})},
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey}), client.WithAggressiveMode(),
		client.WithKeyChangeInterval(time.Hour))
	for range 2 {
		if _, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	p.srv.Restart()
	ok := false
	for range 6 {
		if _, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0)); err == nil {
			ok = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatal("no control succeeded within 6 attempts after the restart")
	}
	time.Sleep(500 * time.Millisecond)
	s := p.c.SecurityStatistics()
	if s[secauth.StatSessionKeyChanges] > 4 || s[secauth.StatRekeysDueToAuthFailure] > 3 || s[secauth.StatRekeysDueToRestarts] > 3 {
		t.Fatalf("key changes after one restart: %d (auth failures %d, restarts %d)",
			s[secauth.StatSessionKeyChanges], s[secauth.StatRekeysDueToAuthFailure], s[secauth.StatRekeysDueToRestarts])
	}
	if s[secauth.StatCriticalMessagesSent] > 20 {
		t.Fatalf("%d critical messages sent: a request storm", s[secauth.StatCriticalMessagesSent])
	}
}

// TestSpec7_6_1_4_5_KeyExpiryRecovery: clause 7.6.1.4.5, p.243: the
// outstation invalidates session keys not changed within the expected
// message count; clause 7.5.3.4 c), p.224: after the authentication error
// the master changes the keys, and the next critical request succeeds.
func TestSpec7_6_1_4_5_KeyExpiryRecovery(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: updateKey}, ExpectedKeyChangeCount: 4})},
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey}), client.WithKeyChangeInterval(time.Hour),
		client.WithAutoClearRestart(false))
	operate := func() error {
		_, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0))
		return err
	}
	for range 2 { // 4 messages: a challenge and a reply each
		if err := operate(); err != nil {
			t.Fatal(err)
		}
	}
	var ae *dnp3.AuthError
	if err := operate(); !errors.As(err, &ae) || ae.Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("past the expected key change count: %v", err)
	}
	waitUntil(t, "key change after the authentication error", func() bool {
		return p.c.SecurityStatistics()[secauth.StatSessionKeyChanges] == 2
	})
	if err := operate(); err != nil {
		t.Fatalf("after the new key change: %v", err)
	}
}

// TestSpec7_5_2_4_ErrorSuppressionE2E: clause 7.5.2.4, p.223: the
// outstation stops sending error messages past Max Error Messages Sent
// (threshold 2, Table 7-6 #10): a master with a wrong key sees three
// authentication errors, then timeouts.
func TestSpec7_5_2_4_ErrorSuppressionE2E(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(&relay{}),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: authKey}})},
		client.WithSecureAuthentication(secauth.User{Number: 1, Key: []byte("another session key, 32 octets!")}),
		client.WithResponseTimeout(300*time.Millisecond), client.WithAutoClearRestart(false))
	for i := range 4 {
		_, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0))
		var ae *dnp3.AuthError
		if i < 3 && !errors.As(err, &ae) {
			t.Fatalf("control %d: %v, want an authentication error", i, err)
		}
		if i == 3 && !errors.Is(err, dnp3.ErrTimeout) {
			t.Fatalf("control %d: %v, want a timeout once errors stop", i, err)
		}
	}
}

// TestSpec7_6_1_1_MACAlgorithmsE2E: clause 7.6.1.1, p.241-242: challenges
// and aggressive mode requests with each MAC algorithm the outstation may
// name; the 8-octet truncations are for serial links and need
// WithChallengeMACs over TCP.
func TestSpec7_6_1_1_MACAlgorithmsE2E(t *testing.T) {
	for _, alg := range []app.MACAlgorithm{app.MACHMACSHA256Trunc16, app.MACHMACSHA1Trunc10, app.MACHMACSHA256Trunc8, app.MACHMACSHA1Trunc8} {
		t.Run(alg.String(), func(t *testing.T) {
			r := &relay{}
			p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r),
				server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: authKey, MAC: alg}})},
				client.WithSecureAuthentication(secauth.User{Number: 1, Key: authKey}), client.WithAggressiveMode(),
				client.WithChallengeMACs(alg))
			for range 2 { // challenged, then in aggressive mode
				if _, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0)); err != nil {
					t.Fatal(err)
				}
			}
			if _, op, _ := r.snapshot(); len(op) != 2 {
				t.Fatalf("%d controls executed", len(op))
			}
		})
	}
}

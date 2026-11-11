// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/secauth"
)

// Unit tests of the master's secure authentication paths that an exchange
// with an outstation reaches only rarely: stray and failed challenges,
// the ends of the wait for a challenge of a no-ack request, and the limits
// of the session key changes. They call the client's methods directly.

// authClient is a client with secure authentication for user u that never
// connects.
func authClient(t *testing.T, u secauth.User, opts ...Option) *Client {
	t.Helper()
	c, err := New("127.0.0.1:1", append(quiet(WithSecureAuthentication(u)), opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedSession is a session of a channel that has closed: every Send on
// it fails.
func closedSession(t *testing.T) *channel.Session {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	ch := channel.New(a, channel.Config{})
	sess := ch.AddSession(channel.SessionConfig{Local: 1, Remote: 10, Master: true})
	ch.Start()
	ch.Close(nil)
	<-ch.Done()
	return sess
}

func authResponse(seq uint8, hs ...app.Header) *app.Fragment {
	return &app.Fragment{Control: app.SingleControl(seq), Function: app.FuncAuthResponse, Headers: hs}
}

func challengeHeader(csq uint32, mac app.MACAlgorithm) app.Header {
	return app.FreeFormat(app.G120V1, app.AuthChallenge{CSQ: csq, User: 1, MAC: mac, Reason: app.ReasonCritical, Data: bytes.Repeat([]byte{7}, 4)})
}

func authErrorHeader(code app.AuthErrorCode) app.Header {
	return app.FreeFormat(app.G120V7, app.AuthError{User: 1, Code: code})
}

// TestChallengedFragment: an AUTHENTICATE_RESP refers, before the response
// has begun, to the request when it carries the request's sequence number
// (IEEE 1815-2012 clause 7.5.1.3), and once it has begun, to the last
// CONFIRM sent when it carries that one's (clause 7.5.2.3.2 j).
func TestChallengedFragment(t *testing.T) {
	c := authClient(t, secauth.User{Number: 1, Key: specKey})
	request := []byte{0xC3, byte(app.FuncDirectOperate)}
	confirm := []byte{0xC5, byte(app.FuncConfirm)}
	for _, tc := range []struct {
		name        string
		lastConfirm []byte
		seq         uint8
		begun       bool
		want        []byte
		ofRequest   bool
	}{
		{"request", nil, 3, false, request, true},
		{"other sequence before the response", nil, 4, false, nil, false},
		{"last confirm", confirm, 5, true, confirm, false},
		{"other sequence than the confirm", confirm, 6, true, nil, false},
		{"no confirm sent", nil, 3, true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.mu.Lock()
			c.auth.lastConfirm = tc.lastConfirm
			c.mu.Unlock()
			got, ofRequest := c.challenged(tc.seq, 3, request, tc.begun)
			if !bytes.Equal(got, tc.want) || ofRequest != tc.ofRequest {
				t.Fatalf("challenged(%d) = %x %v, want %x %v", tc.seq, got, ofRequest, tc.want, tc.ofRequest)
			}
		})
	}
}

// TestStrayAuthResponses: an AUTHENTICATE_RESP no request waits for is
// counted as Table 7-6 asks: an error message as received (#9), a
// challenge of no CONFIRM sent, or anything else, as unexpected (#13) and
// discarded (#16). A challenge of the last CONFIRM is answered (clause
// 7.5.2.3.2 j); without session keys it cannot be, and is counted as Table
// 7-13 says.
func TestStrayAuthResponses(t *testing.T) {
	stat := func(c *Client, s secauth.Statistic) uint32 { return c.SecurityStatistics()[s] }
	t.Run("not an authentication response", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey})
		c.onStrayAuth(nil, &app.Fragment{Control: app.SingleControl(2), Function: app.FuncResponse}, nil)
		for s, n := range c.SecurityStatistics() {
			if n != 0 {
				t.Fatalf("statistic %s counted", secauth.Statistic(s))
			}
		}
	})
	t.Run("error message", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey})
		c.onStrayAuth(nil, authResponse(2, authErrorHeader(app.AuthErrAuthenticationFailed)), nil)
		if stat(c, secauth.StatErrorMessagesReceived) != 1 || stat(c, secauth.StatDiscardedMessages) != 0 {
			t.Fatalf("statistics %v", c.SecurityStatistics())
		}
	})
	for _, tc := range []struct {
		name    string
		confirm []byte
		f       *app.Fragment
	}{
		{"challenge, no confirm sent", nil, authResponse(2, challengeHeader(1, app.MACHMACSHA256Trunc16))},
		{"challenge of another confirm", []byte{0xC5, 0x00}, authResponse(2, challengeHeader(1, app.MACHMACSHA256Trunc16))},
		{"no objects", []byte{0xC2, 0x00}, authResponse(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := authClient(t, secauth.User{Number: 1, Key: specKey})
			c.mu.Lock()
			c.auth.lastConfirm = tc.confirm
			c.mu.Unlock()
			c.onStrayAuth(nil, tc.f, nil)
			if stat(c, secauth.StatUnexpectedMessages) != 1 || stat(c, secauth.StatDiscardedMessages) != 1 || stat(c, secauth.StatCriticalMessagesSent) != 0 {
				t.Fatalf("statistics %v", c.SecurityStatistics())
			}
		})
	}
	t.Run("challenge of the confirm without session keys", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, UpdateKey: testUpdateKey})
		c.mu.Lock()
		c.auth.lastConfirm = []byte{0xC2, 0x00}
		c.mu.Unlock()
		c.onStrayAuth(closedSession(t), authResponse(2, challengeHeader(1, app.MACHMACSHA256Trunc16)), nil)
		if stat(c, secauth.StatAuthenticationFailures) != 1 || stat(c, secauth.StatCriticalMessagesSent) != 0 {
			t.Fatalf("statistics %v", c.SecurityStatistics())
		}
	})
}

// TestNoAckChallengeEnds: the wait for a challenge of a no-ack request
// (IEEE 1815-2012 clause 7.5.2.3.2 i) passes stray fragments on, goes on
// past an authentication response that is no challenge, and ends with an
// error message of the request, at the loss of the connection, at the end
// of the context and at Close.
func TestNoAckChallengeEnds(t *testing.T) {
	const seq = 4
	request := []byte{0xC4, byte(app.FuncDirectOperateNoAck)}
	wait := func(c *Client, ctx context.Context, tr *transaction) error {
		return c.noAckChallenge(ctx, nil, tr, app.FuncDirectOperateNoAck, seq, request)
	}
	t.Run("error message after stray fragments", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, UpdateKey: testUpdateKey}, WithResponseTimeout(time.Hour))
		tr := newTransaction()
		for _, f := range []*app.Fragment{
			{Control: app.SingleControl(seq + 1), Function: app.FuncResponse}, // not authentication: ignored
			authResponse(seq + 1), // of no request: discarded
			authResponse(seq),     // no challenge: the wait goes on
			authResponse(seq, authErrorHeader(app.AuthErrAuthenticationFailed)),
		} {
			tr.frags <- received{f: f}
		}
		err := wait(c, testCtx(t), tr)
		if ae, ok := errors.AsType[*dnp3.AuthError](err); !ok || ae.Code != app.AuthErrAuthenticationFailed {
			t.Fatalf("error message of the request: %v", err)
		}
		s := c.SecurityStatistics()
		// The error message asks for a session key change (clause 7.5.3.4).
		if s[secauth.StatUnexpectedMessages] != 1 || s[secauth.StatErrorMessagesReceived] != 1 || s[secauth.StatRekeysDueToAuthFailure] != 1 {
			t.Fatalf("statistics %v", s)
		}
		c.mu.Lock()
		authRekey := c.auth.authRekey
		c.mu.Unlock()
		if !authRekey {
			t.Fatal("no session key change asked for")
		}
	})
	t.Run("connection lost", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithResponseTimeout(time.Hour))
		tr := newTransaction()
		tr.errc <- io.EOF
		if err := wait(c, testCtx(t), tr); !errors.Is(err, dnp3.ErrConnectionLost) || !errors.Is(err, io.EOF) {
			t.Fatalf("connection lost: %v", err)
		}
	})
	t.Run("context ended", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithResponseTimeout(time.Hour))
		ctx, cancel := context.WithCancel(testCtx(t))
		cancel()
		if err := wait(c, ctx, newTransaction()); err != nil {
			t.Fatalf("context ended: %v", err)
		}
	})
	t.Run("closed", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithResponseTimeout(time.Hour))
		_ = c.Close()
		if err := wait(c, testCtx(t), newTransaction()); !errors.Is(err, dnp3.ErrClosed) {
			t.Fatalf("closed: %v", err)
		}
	})
}

// TestAnswerChallengeFails: a reply the master cannot compute or send
// fails the challenged request and is not counted as a critical message
// sent (Table 7-6 #2).
func TestAnswerChallengeFails(t *testing.T) {
	raw := []byte{0xC3, byte(app.FuncAuthResponse)}
	critical := []byte{0xC3, byte(app.FuncDirectOperate)}
	t.Run("MAC not computable", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey})
		// WithChallengeMACs refuses an algorithm package secauth does not
		// compute; the reply guards against one all the same.
		c.opts.challengeMACs = []app.MACAlgorithm{app.MACAESGMAC}
		ch := app.AuthChallenge{CSQ: 1, User: 1, MAC: app.MACAESGMAC, Reason: app.ReasonCritical, Data: []byte{1, 2, 3, 4}}
		if _, err := c.answerChallenge(testCtx(t), closedSession(t), 3, ch, raw, critical); !errors.Is(err, dnp3.ErrAuthentication) {
			t.Fatalf("challenge for AES-GMAC: %v", err)
		}
		if s := c.SecurityStatistics(); s[secauth.StatCriticalMessagesSent] != 0 {
			t.Fatalf("statistics %v", s)
		}
	})
	t.Run("send fails", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey})
		ch := app.AuthChallenge{CSQ: 1, User: 1, MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: []byte{1, 2, 3, 4}}
		if _, err := c.answerChallenge(testCtx(t), closedSession(t), 3, ch, raw, critical); !errors.Is(err, dnp3.ErrClosed) {
			t.Fatalf("reply on a closed connection: %v", err)
		}
		if s := c.SecurityStatistics(); s[secauth.StatTotalMessagesSent] != 0 {
			t.Fatalf("statistics %v", s)
		}
	})
}

// TestAggressiveFragmentMACNotComputable: an aggressive mode fragment
// (Table A-9) is not made with a MAC algorithm package secauth does not
// compute, even one with a known length.
func TestAggressiveFragmentMACNotComputable(t *testing.T) {
	if app.MACAESGMAC.Len() == 0 {
		t.Fatal("AES-GMAC has no MAC length")
	}
	f := &app.Fragment{Control: app.SingleControl(1), Function: app.FuncConfirm}
	if _, err := aggressiveFragment(f, app.MACAESGMAC, specKey, []byte{0xC1, 0x83}, 1, 1); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("aggressive mode with AES-GMAC: %v", err)
	}
	if len(f.Headers) != 0 {
		t.Fatal("the fragment was changed")
	}
}

// TestConfirmChallengeNotAnswerable: a response that ends with a challenge
// asks for an aggressive mode confirmation (IEEE 1815-2012 clause 7.5.2.3.2
// e). Without session keys, or for a MAC algorithm the master does not
// accept, a plain CONFIRM is sent, and kept as the last one.
func TestConfirmChallengeNotAnswerable(t *testing.T) {
	for _, tc := range []struct {
		name string
		u    secauth.User
		mac  app.MACAlgorithm
	}{
		{"no session keys", secauth.User{Number: 1, UpdateKey: testUpdateKey}, app.MACHMACSHA256Trunc16},
		{"MAC not accepted", secauth.User{Number: 1, Key: specKey}, app.MACHMACSHA1Trunc4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := authClient(t, tc.u)
			f := &app.Fragment{Control: app.Control{FIR: true, FIN: true, CON: true, Seq: 6}, Function: app.FuncResponse,
				Headers: []app.Header{challengeHeader(9, tc.mac)}}
			c.confirmResponse(closedSession(t), f, []byte{0xE6, byte(app.FuncResponse)}, false)
			c.mu.Lock()
			last := c.auth.lastConfirm
			c.mu.Unlock()
			if !bytes.Equal(last, []byte{0xC6, byte(app.FuncConfirm)}) {
				t.Fatalf("confirmation %x, want a plain CONFIRM", last)
			}
			if s := c.SecurityStatistics(); s[secauth.StatCriticalMessagesSent] != 0 {
				t.Fatalf("statistics %v", s)
			}
		})
	}
}

// TestAuthFailureBeforeKeyChange: a challenge that fails because the
// session keys were not changed yet asks for a session key change (Table
// 7-13); other failures, or one once the keys are there, do not.
func TestAuthFailureBeforeKeyChange(t *testing.T) {
	noKeys := fmt.Errorf("%w: challenged before the session keys were changed", dnp3.ErrAuthentication)
	for _, tc := range []struct {
		name  string
		key   []byte
		err   error
		rekey bool
	}{
		{"no session keys", nil, noKeys, true},
		{"session keys", []byte("control key"), noKeys, false},
		{"another error", nil, dnp3.ErrTimeout, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := authClient(t, secauth.User{Number: 1, UpdateKey: testUpdateKey})
			// Close stops the key change loop: the request for a key
			// change stays queued for the test to see.
			_ = c.Close()
			c.mu.Lock()
			c.auth.sessionKey = tc.key
			c.mu.Unlock()
			c.onAuthFailure(app.FuncDirectOperate, false, tc.err)
			if got := len(c.rekey) == 1; got != tc.rekey {
				t.Fatalf("session key change asked for: %v, want %v", got, tc.rekey)
			}
		})
	}
}

// TestRestartRekeyLimit: an outstation restart changes the session keys
// only while Rekeys Due to Restarts is below Max Rekeys Due to Restarts
// (IEEE 1815-2012 clause 7.5.2.2, Table 7-6 #5, Table 7-8).
func TestRestartRekeyLimit(t *testing.T) {
	c := authClient(t, secauth.User{Number: 1, UpdateKey: testUpdateKey})
	restarted := app.IINDeviceRestart
	c.mu.Lock()
	c.auth.restart = false
	c.counters.stats[secauth.StatRekeysDueToRestarts] = c.counters.maxRestartRekeys
	c.mu.Unlock()
	if c.restartRekey(restarted) {
		t.Fatal("session keys changed past Max Rekeys Due to Restarts")
	}
	c.mu.Lock()
	c.auth.restart = false
	c.counters.stats[secauth.StatRekeysDueToRestarts] = c.counters.maxRestartRekeys - 1
	c.mu.Unlock()
	if !c.restartRekey(restarted) {
		t.Fatal("session keys not changed below Max Rekeys Due to Restarts")
	}
	if s := c.SecurityStatistics(); s[secauth.StatRekeysDueToRestarts] != c.counters.maxRestartRekeys {
		t.Fatalf("rekeys due to restarts %d", s[secauth.StatRekeysDueToRestarts])
	}
}

// addrOf is a net.Addr of a stream that is not IP, such as a serial port.
type addrOf string

func (a addrOf) Network() string { return "serial" }
func (a addrOf) String() string  { return string(a) }

// TestStreamOverIP: over a stream (WithStream) the client is over IP when
// the stream's remote address is a TCP or UDP address; only then are the
// MAC truncations to 8 octets refused by default (IEEE 1815-2012 clauses
// 7.6.1.1.1 and 7.6.1.1.2).
func TestStreamOverIP(t *testing.T) {
	open := func(context.Context) (io.ReadWriteCloser, net.Addr, error) { return nil, nil, errors.New("not opened") }
	for _, tc := range []struct {
		remote net.Addr
		overIP bool
	}{
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20000}, true},
		{&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20000}, true},
		{addrOf("/dev/ttyS0"), false},
	} {
		t.Run(tc.remote.Network(), func(t *testing.T) {
			c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithStream(open))
			c.mu.Lock()
			c.remote = tc.remote
			c.mu.Unlock()
			if c.overIP() != tc.overIP {
				t.Fatalf("over IP: %v, want %v", c.overIP(), tc.overIP)
			}
			if c.acceptsMAC(app.MACHMACSHA256Trunc8) == tc.overIP {
				t.Fatalf("HMAC-SHA-256-8 accepted: %v over IP %v", !tc.overIP, tc.overIP)
			}
		})
	}
}

// TestKeyStatusOKBeforeKeyChange: a key status with Status OK before the
// session keys were changed on the connection carries a MAC the master has
// no monitoring direction session key to check, and is accepted (IEEE
// 1815-2012 clause 7.5.4.2, Table 7-13). Once they were, a MAC that does
// not verify is refused.
func TestKeyStatusOKBeforeKeyChange(t *testing.T) {
	u := secauth.User{Number: 1, UpdateKey: testUpdateKey}
	c := authClient(t, u)
	st := app.AuthSessionKeyStatus{KSQ: 2, User: 1, KeyWrap: u.KeyWrapAlgorithm(), Status: app.KeyStatusOK,
		MAC: app.MACHMACSHA256Trunc16, Challenge: bytes.Repeat([]byte{1}, 4), MACValue: bytes.Repeat([]byte{9}, 16)}
	if err := c.checkKeyStatus(st); err != nil {
		t.Fatalf("OK key status before a key change: %v", err)
	}
	c.keysChanged([]byte("control key"), []byte("monitoring key"), []byte{0xC1, byte(app.FuncAuthRequest)})
	if err := c.checkKeyStatus(st); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("OK key status with a wrong MAC after a key change: %v", err)
	}
}

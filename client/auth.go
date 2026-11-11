// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/secauth"
)

// DefaultKeyChangeCount is the default session key change count: the
// number of authentication messages, sent or received, after which the
// session keys are changed (IEEE 1815-2012 clause 7.6.1.4.4).
const DefaultKeyChangeCount = 1000

// authState is the master's secure authentication state on the current
// channel: the responder of IEEE 1815-2012 clause 7.5.3 and the session
// key state of Table 7-13. It is guarded by Client.mu and starts over on
// every connection.
type authState struct {
	// sessionKey is the control direction session key, nil before the
	// first session key change of the channel.
	sessionKey []byte
	// monitoring and keyChange are the monitoring direction session key
	// and the session key change fragment the outstation last confirmed:
	// the MAC of a key status with Status OK must verify with them
	// (clause 7.5.4.2, A.45.5).
	monitoring, keyChange []byte
	// lastChallenge is the last challenge fragment received and lastMAC
	// its MAC algorithm; csq is the CSQ of the last reply or aggressive
	// mode request sent since, which the next aggressive mode request
	// increments (clause 7.5.2.3.3 c-d).
	lastChallenge []byte
	lastMAC       app.MACAlgorithm
	csq           uint32
	// replied is set once the response to a challenged request came: a
	// challenge was answered successfully since the last session key
	// change, as aggressive mode needs (clause 7.5.3.3).
	replied bool
	// noAggressive is set when the outstation answered an aggressive mode
	// request with error 4, aggressive mode not supported (A.45.7).
	noAggressive bool
	// count is the number of authentication messages since the last
	// session key change: challenges and errors received, replies and
	// aggressive mode requests sent (clause 7.6.1.4.4).
	count uint32
	// restart is IIN1.7 of the last response: a restart is detected when
	// it becomes set (clause 7.5.4.2). It starts set, so that the restart
	// indication of a new connection does not change the keys again.
	restart bool
	// authRekey is set while a session key change asked for by an
	// authentication failure is pending.
	authRekey bool
	// lastConfirm is the last CONFIRM sent: an outstation may challenge it
	// (clause 7.5.2.3.2 e, j).
	lastConfirm []byte
}

// reset starts the state over, for a new connection.
func (s *authState) reset() {
	clear(s.sessionKey)
	clear(s.monitoring)
	*s = authState{restart: true}
}

// authCounters are the master's security statistics (Table 7-6, clause
// 7.5.2.2) and the maxima of Table 7-15 it acts on. They are guarded by
// Client.mu and kept across connections.
type authCounters struct {
	stats [secauth.NumStatistics]uint32
	// maxAuthRekeys and maxRestartRekeys are Max Authentication Rekeys and
	// Max Rekeys Due to Restarts (clause 7.5.2.2): the statistic plus its
	// threshold, reset at startup.
	maxAuthRekeys, maxRestartRekeys uint32
}

func newAuthCounters() authCounters {
	return authCounters{
		maxAuthRekeys:    uint32(secauth.StatRekeysDueToAuthFailure.DefaultThreshold()),
		maxRestartRekeys: uint32(secauth.StatRekeysDueToRestarts.DefaultThreshold()),
	}
}

// countLocked increments statistic s. The caller holds c.mu.
func (c *Client) countLocked(s secauth.Statistic) {
	if c.opts.auth != nil {
		c.counters.stats[s]++
	}
}

// count increments statistic s.
func (c *Client) count(s secauth.Statistic) {
	c.mu.Lock()
	c.countLocked(s)
	c.mu.Unlock()
}

// SecurityStatistics returns the master's security statistics (IEEE
// 1815-2012 Table 7-6, clause 7.5.2.2), indexed by secauth.Statistic: for
// example the session key changes, the challenges answered (critical
// messages sent) and the authentication errors received. They count from
// New and are all zero without WithSecureAuthentication. The outstation's
// statistics are read from it as group 121.
func (c *Client) SecurityStatistics() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.counters.stats[:])
}

// authMessageLocked counts one authentication message of the current
// session keys and asks for a session key change when they reached the key
// change count (clause 7.6.1.4.4). The caller holds c.mu.
func (c *Client) authMessageLocked() {
	c.auth.count++
	if c.auth.count == c.opts.keyChangeCount && len(c.opts.auth.UpdateKey) > 0 {
		c.log.Debug("key change count reached", "messages", c.auth.count)
		c.keyChangeTimeoutLocked()
		c.rekeySoon()
	}
}

// keyChangeTimeoutLocked is a Key Change Timeout of Table 7-8: the key
// change interval or count was reached. It resets Max Rekeys Due to
// Restarts. The caller holds c.mu.
func (c *Client) keyChangeTimeoutLocked() {
	c.counters.maxRestartRekeys = c.counters.stats[secauth.StatRekeysDueToRestarts] +
		uint32(secauth.StatRekeysDueToRestarts.DefaultThreshold())
}

// keyChangeTimeout is keyChangeTimeoutLocked for the key change loop.
func (c *Client) keyChangeTimeout() {
	c.mu.Lock()
	c.keyChangeTimeoutLocked()
	c.mu.Unlock()
}

// onAuthResponse handles an AUTHENTICATE_RESP received while a request
// waits. For a challenge it sends the reply and returns the sequence
// number the response to the critical request will carry: the reply keeps
// the sequence number of the challenge, which is that of the critical
// request (IEEE 1815-2012 clause 7.5.1.3). An authentication error fails
// the request. For other authentication objects it returns -1: the
// fragment is the response itself.
func (c *Client) onAuthResponse(ctx context.Context, sess *channel.Session, f *app.Fragment, raw, critical []byte) (int, error) {
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			switch v := o.Value.(type) {
			case app.AuthError:
				c.mu.Lock()
				if c.opts.auth != nil {
					c.countLocked(secauth.StatErrorMessagesReceived)
					c.authMessageLocked()
				}
				c.mu.Unlock()
				c.log.WarnContext(ctx, "authentication error received", "code", v.Code.String(), "user", v.User, "csq", v.CSQ)
				return 0, &dnp3.AuthError{Code: v.Code, User: v.User, Text: string(v.Text)}
			case app.AuthChallenge:
				return c.answerChallenge(ctx, sess, f.Control.Seq, v, raw, critical)
			}
		}
	}
	return -1, nil
}

// answerChallenge replies to a challenge of the fragment critical (Table
// A-3): a MAC with the control direction session key over the challenge
// fragment raw and critical, with the algorithm the challenge names.
func (c *Client) answerChallenge(ctx context.Context, sess *channel.Session, seq uint8, v app.AuthChallenge, raw, critical []byte) (int, error) {
	u := c.opts.auth
	if u == nil {
		return 0, fmt.Errorf("%w: challenged without secure authentication configured", dnp3.ErrAuthentication)
	}
	// The challenge (g120v1, A.45.1) names the MAC algorithm of the reply:
	// the outstation's choice, within the algorithms this client accepts.
	if !c.acceptsMAC(v.MAC) {
		c.count(secauth.StatDiscardedMessages)
		return 0, fmt.Errorf("%w: challenge asks for %s, not among the accepted MAC algorithms", dnp3.ErrAuthentication, v.MAC)
	}
	key := c.controlKey()
	if key == nil {
		// Table 7-13, Rx Challenge message without valid session keys:
		// count and discard it.
		c.mu.Lock()
		c.countLocked(secauth.StatUnexpectedMessages)
		c.countLocked(secauth.StatAuthenticationFailures)
		c.countLocked(secauth.StatDiscardedMessages)
		c.mu.Unlock()
		return 0, fmt.Errorf("%w: challenged before the session keys were changed", dnp3.ErrAuthentication)
	}
	mac, err := secauth.MAC(v.MAC, key, secauth.AuthData(raw, critical))
	if err != nil {
		return 0, fmt.Errorf("%w: %w", dnp3.ErrAuthentication, err)
	}
	reply := &app.Fragment{Control: app.SingleControl(seq), Function: app.FuncAuthRequest,
		Headers: []app.Header{app.FreeFormat(app.G120V2, app.AuthReply{CSQ: v.CSQ, User: u.Number, MAC: mac})}}
	data, err := reply.Encode()
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	// The reply takes the challenge's CSQ (clause 7.5.2.3.3 c). Aggressive
	// mode waits until the response shows the reply was accepted.
	c.auth.lastChallenge, c.auth.lastMAC, c.auth.csq, c.auth.replied = append([]byte(nil), raw...), v.MAC, v.CSQ, false
	c.countLocked(secauth.StatCriticalMessagesSent) // clause 7.5.3.2
	c.authMessageLocked()                           // the challenge
	c.authMessageLocked()                           // the reply
	c.mu.Unlock()
	if err := sess.Send(ctx, data); err != nil {
		return 0, sendError(err)
	}
	c.sent(reply, len(data))
	c.log.DebugContext(ctx, "challenge answered", "csq", v.CSQ, "user", u.Number)
	return int(seq), nil
}

// sent reports a fragment sent: to the metrics, and as a message sent to
// the security statistics.
func (c *Client) sent(f *app.Fragment, n int) {
	c.count(secauth.StatTotalMessagesSent)
	if m := c.opts.metrics; m != nil {
		m.OnFragmentSent(c.remoteAddr(), f, n)
	}
}

// challengeAccepted records that the response to a challenged request
// came: the reply was valid, and aggressive mode may follow (clause
// 7.5.3.3).
func (c *Client) challengeAccepted() {
	c.mu.Lock()
	c.auth.replied = c.auth.lastChallenge != nil
	c.mu.Unlock()
}

// challenged returns the fragment an AUTHENTICATE_RESP with sequence
// number seq refers to, during the exchange of request (sequence number
// reqSeq): once the response has begun, the last CONFIRM if it carried
// seq (clause 7.5.2.3.2 j); before, the request if seq is its sequence
// number (clause 7.5.1.3). ofRequest reports which; nil means neither.
func (c *Client) challenged(seq, reqSeq uint8, request []byte, begun bool) (critical []byte, ofRequest bool) {
	if begun {
		c.mu.Lock()
		cf := c.auth.lastConfirm
		c.mu.Unlock()
		if len(cf) > 0 && cf[0]&0x0F == seq {
			return cf, false
		}
		return nil, false
	}
	if seq != reqSeq {
		return nil, false
	}
	return request, true
}

// keysFor refuses a request of function fc that the outstation will
// challenge while the session keys are not valid yet (IEEE 1815-2012 Table
// 7-13: the master is changing them): a function Table 7-7 marks MANDATORY
// (clause 7.5.2.3.2 a), or one WithAggressiveMode names. Sent, it could
// only fail: the master discards a challenge it has no valid keys for
// (Table 7-13 row 7), and the outstation, waiting for the reply up to its
// reply timeout, discards the key status request that would change them
// (Table 7-8 row 16). Requests sent again at once then keep the keys from
// ever being changed. The request fails at once, unsent, and a session key
// change is asked for; non-critical requests go on (clause 7.3.6).
func (c *Client) keysFor(fc app.FunctionCode) error {
	u := c.opts.auth
	if u == nil || len(u.UpdateKey) == 0 ||
		!slices.Contains(secauth.MandatoryCritical, fc) && !slices.Contains(c.opts.aggressive, fc) {
		return nil
	}
	if c.controlKey() != nil {
		return nil
	}
	c.rekeySoon()
	return fmt.Errorf("%w: %s not sent: no valid session keys yet, a session key change is pending", dnp3.ErrAuthentication, fc)
}

// aggressive turns req into an aggressive mode request when its function
// is configured for it, a challenge was answered successfully since the
// last session key change (IEEE 1815-2012 clause 7.5.3.3) and the
// outstation did not refuse aggressive mode: a g120v3 object first and a
// g120v9 MAC last, over the last challenge and every octet of the request
// up to the MAC value (Table A-9). It reports whether it did.
func (c *Client) aggressive(req *app.Fragment) (bool, error) {
	u := c.opts.auth
	if u == nil || !slices.Contains(c.opts.aggressive, req.Function) {
		return false, nil
	}
	key := c.controlKey()
	c.mu.Lock()
	last, alg, csq, ok := c.auth.lastChallenge, c.auth.lastMAC, c.auth.csq, c.auth.replied && !c.auth.noAggressive
	c.mu.Unlock()
	if !ok || last == nil || key == nil {
		return false, nil
	}
	// The CSQ is the last challenge's plus the replies and aggressive mode
	// requests sent since (clause 7.5.2.3.3 d).
	if _, err := aggressiveFragment(req, alg, key, last, csq+1, u.Number); err != nil {
		return false, err
	}
	c.mu.Lock()
	c.auth.csq = csq + 1
	c.countLocked(secauth.StatCriticalMessagesSent) // clause 7.5.3.3
	c.authMessageLocked()
	c.mu.Unlock()
	return true, nil
}

// aggressiveFragment makes f an aggressive mode fragment of user user with
// CSQ csq: a g120v3 object first and a g120v9 object last, its MAC
// computed with alg and key over the challenge fragment last and every
// octet of f before the MAC value, the g120v9 object header and size
// prefix included (IEEE 1815-2012 Table A-9). It returns the encoding.
func aggressiveFragment(f *app.Fragment, alg app.MACAlgorithm, key, last []byte, csq uint32, user uint16) ([]byte, error) {
	n := alg.Len()
	if n == 0 {
		return nil, fmt.Errorf("%w: MAC algorithm %s", dnp3.ErrAuthentication, alg)
	}
	hs := make([]app.Header, 0, len(f.Headers)+2)
	hs = append(hs, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq, User: user}))
	hs = append(hs, f.Headers...)
	// Encode with a MAC value of the right length, then compute the MAC
	// over the octets before it.
	hs = append(hs, app.FreeFormat(app.G120V9, app.AuthMAC{MAC: make([]byte, n)}))
	g := *f
	g.Headers = hs
	b, err := g.Encode()
	if err != nil {
		return nil, err
	}
	mac, err := secauth.MAC(alg, key, secauth.AuthData(last, b[:len(b)-n]))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", dnp3.ErrAuthentication, err)
	}
	copy(b[len(b)-n:], mac)
	hs[len(hs)-1] = app.FreeFormat(app.G120V9, app.AuthMAC{MAC: mac})
	f.Headers = hs
	return b, nil
}

// onAuthFailure handles an error message, or a failed challenge, in answer
// to a request of function fc, sent in aggressive mode or not (IEEE
// 1815-2012 clause 7.5.3.4): the next critical request is sent normally,
// aggressive mode is not used again on the connection after error 4
// (aggressive mode not supported, A.45.7), and error 1 (authentication
// failed) changes the session keys, unless Rekeys Due to Authentication
// Failure reached Max Authentication Rekeys without a key change for
// another reason since (Table 7-6 #4).
func (c *Client) onAuthFailure(fc app.FunctionCode, aggressive bool, err error) {
	if fc == app.FuncAuthRequest || c.opts.auth == nil {
		return
	}
	ae, isAuthError := errors.AsType[*dnp3.AuthError](err)
	c.mu.Lock()
	defer c.mu.Unlock()
	if aggressive {
		c.auth.lastChallenge, c.auth.replied = nil, false
	}
	if isAuthError && ae.Code == app.AuthErrAggressiveModeNotSupported {
		if !c.auth.noAggressive {
			c.log.Warn("the outstation does not support aggressive mode: not used again on this connection")
		}
		c.auth.noAggressive = true
		return
	}
	if len(c.opts.auth.UpdateKey) == 0 {
		return
	}
	if !isAuthError {
		if c.auth.sessionKey == nil && errors.Is(err, dnp3.ErrAuthentication) {
			c.rekeySoon() // challenged before the session keys were changed
		}
		return
	}
	if ae.Code != app.AuthErrAuthenticationFailed {
		return
	}
	if c.counters.stats[secauth.StatRekeysDueToAuthFailure] >= c.counters.maxAuthRekeys {
		c.log.Warn("authentication failed: max authentication rekeys reached, session keys not changed")
		// Over TCP the connection is closed as well (Table 7-8 row 11): the
		// key change of the next connection, one for another reason, lifts
		// the limit.
		if _, tcp := c.remote.(*net.TCPAddr); tcp && c.ch != nil {
			c.auth.authRekey = false
			go c.ch.Close(fmt.Errorf("%w: max authentication rekeys exceeded", dnp3.ErrAuthentication))
		}
		return
	}
	c.countLocked(secauth.StatRekeysDueToAuthFailure)
	c.auth.authRekey = true
	c.rekeySoon()
}

// keysChanged records a successful session key change (Table 7-13): the
// new keys and the key change fragment the next key status is
// authenticated with. Aggressive mode waits for a new challenge (clause
// 7.5.3.3), and Max Authentication Rekeys is reset unless an
// authentication failure asked for the change (Table 7-6 #4).
func (c *Client) keysChanged(control, monitoring, keyChange []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.auth.sessionKey)
	clear(c.auth.monitoring)
	c.auth.sessionKey, c.auth.monitoring, c.auth.keyChange = control, monitoring, slices.Clone(keyChange)
	c.auth.lastChallenge, c.auth.replied, c.auth.count = nil, false, 0
	c.countLocked(secauth.StatSessionKeyChanges)
	if !c.auth.authRekey {
		c.counters.maxAuthRekeys = c.counters.stats[secauth.StatRekeysDueToAuthFailure] +
			uint32(secauth.StatRekeysDueToAuthFailure.DefaultThreshold())
	}
	c.auth.authRekey = false
}

// checkKeyStatus checks the key status st the outstation sent in answer to
// a key status request: for this user, with the key wrap algorithm of the
// update key (A.45.5), and, when the Status is OK and the keys were
// changed before on this connection, authentic: a MAC with the last
// monitoring direction session key over the last key change (clause
// 7.5.4.2). An OK status that is not authentic is counted as an
// authentication failure and fails the key change (Table 7-13).
func (c *Client) checkKeyStatus(st app.AuthSessionKeyStatus) error {
	u := c.opts.auth
	if st.User != u.Number {
		return fmt.Errorf("%w: key status for user %d, requested for user %d", dnp3.ErrAuthentication, st.User, u.Number)
	}
	if st.KeyWrap != u.KeyWrapAlgorithm() {
		return fmt.Errorf("%w: the outstation's key wrap algorithm is %d, the update key needs %d", dnp3.ErrAuthentication, st.KeyWrap, u.KeyWrapAlgorithm())
	}
	if st.Status != app.KeyStatusOK {
		return nil
	}
	c.mu.Lock()
	monitoring, change := c.auth.monitoring, c.auth.keyChange
	c.mu.Unlock()
	if monitoring == nil || change == nil {
		return nil // nothing to authenticate it with (Table 7-13)
	}
	want, err := secauth.MAC(st.MAC, monitoring, change)
	if err == nil && secauth.Equal(want, st.MACValue) {
		return nil
	}
	c.mu.Lock()
	c.countLocked(secauth.StatAuthenticationFailures)
	c.countLocked(secauth.StatDiscardedMessages)
	c.mu.Unlock()
	c.log.Warn("key status not authentic: possible attack", "user", st.User, "ksq", st.KSQ, "mac", st.MAC.String())
	return fmt.Errorf("%w: the key status is not authentic", dnp3.ErrAuthentication)
}

// restartRekey reports whether the internal indications iin show an
// outstation restart that calls for a session key change (IEEE 1815-2012
// clause 7.5.4.2, Table 7-8 Outstation Restarted): IIN1.7 newly set, with
// an update key, while Rekeys Due to Restarts has not reached Max Rekeys
// Due to Restarts.
func (c *Client) restartRekey(iin app.IIN) bool {
	if c.opts.auth == nil || len(c.opts.auth.UpdateKey) == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	was := c.auth.restart
	c.auth.restart = iin.Has(app.IINDeviceRestart)
	if !c.auth.restart || was {
		return false
	}
	if c.counters.stats[secauth.StatRekeysDueToRestarts] >= c.counters.maxRestartRekeys {
		c.log.Warn("outstation restarted: max rekeys due to restarts reached, session keys not changed")
		return false
	}
	c.countLocked(secauth.StatRekeysDueToRestarts)
	c.log.Info("outstation restarted: changing the session keys")
	return true
}

// noAckChallenge waits, after a no-ack request (0x06, 0x08, 0x0A, 0x0C) was
// sent normally under secure authentication, for the outstation to
// challenge it, and answers the challenge (IEEE 1815-2012 clause 7.5.2.3.2
// i): up to the response timeout, or until ctx ends. Without a challenge
// it returns nil; an authentication error fails the request.
func (c *Client) noAckChallenge(ctx context.Context, sess *channel.Session, t *transaction, fc app.FunctionCode, seq uint8, request []byte) error {
	if c.opts.auth == nil || fc == app.FuncAuthRequestNoAck || fc == app.FuncConfirm {
		return nil
	}
	timer := time.NewTimer(c.opts.responseTimeout)
	defer timer.Stop()
	for {
		select {
		case rf := <-t.frags:
			f := rf.f
			if f.Function != app.FuncAuthResponse || f.Control.Seq != seq {
				c.onStrayAuth(sess, f, rf.raw)
				continue
			}
			next, err := c.onAuthResponse(ctx, sess, f, rf.raw, request)
			if err != nil {
				c.onAuthFailure(fc, false, err)
				return err
			}
			if next >= 0 {
				return nil // answered: the outstation executes it and does not respond
			}
		case err := <-t.errc:
			return fmt.Errorf("%w: %w", dnp3.ErrConnectionLost, err)
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return nil
		case <-c.closeCh:
			return dnp3.ErrClosed
		}
	}
}

// errNoConfirmKey is why an authenticated confirmation cannot be sent.
var errNoConfirmKey = errors.New("no session key or MAC algorithm for it")

// confirmResponse confirms the response fragment f (raw as received). An
// outstation that ends it with a challenge (g120v1) asks for the
// confirmation in aggressive mode, which the master sends whether
// aggressive mode is enabled or not (IEEE 1815-2012 clauses 7.5.2.3.2 e-f,
// 7.5.3.2, 7.6.1.4.7): a g120v3 object with the challenge's CSQ and a MAC
// over the challenge fragment and the confirmation (Table A-9).
func (c *Client) confirmResponse(sess *channel.Session, f *app.Fragment, raw []byte, uns bool) {
	cf := &app.Fragment{Control: app.Control{FIR: true, FIN: true, UNS: uns, Seq: f.Control.Seq}, Function: app.FuncConfirm}
	if ch, ok := trailingChallenge(f); ok && c.opts.auth != nil {
		err := errNoConfirmKey
		if key := c.controlKey(); key != nil && c.acceptsMAC(ch.MAC) {
			_, err = aggressiveFragment(cf, ch.MAC, key, raw, ch.CSQ, c.opts.auth.Number)
		}
		if err != nil {
			c.log.Warn("authenticated confirmation not possible: plain confirmation sent", "seq", f.Control.Seq, "error", err)
		} else {
			c.mu.Lock()
			c.auth.lastChallenge, c.auth.lastMAC, c.auth.csq = append([]byte(nil), raw...), ch.MAC, ch.CSQ
			c.countLocked(secauth.StatCriticalMessagesSent)
			c.authMessageLocked() // the challenge
			c.authMessageLocked() // the aggressive mode confirmation
			c.mu.Unlock()
		}
	}
	c.sendConfirm(sess, cf)
}

// trailingChallenge returns the challenge that ends a response, if any.
func trailingChallenge(f *app.Fragment) (app.AuthChallenge, bool) {
	if len(f.Headers) == 0 {
		return app.AuthChallenge{}, false
	}
	h := f.Headers[len(f.Headers)-1]
	if h.GV != app.G120V1 || len(h.Objects) != 1 {
		return app.AuthChallenge{}, false
	}
	ch, ok := h.Objects[0].Value.(app.AuthChallenge)
	return ch, ok
}

// onStrayAuth handles a response no request waits for. A challenge of the
// last CONFIRM sent is answered (clause 7.5.2.3.2 j, Figure 7-25); an
// authentication error is counted and logged; anything else is discarded.
func (c *Client) onStrayAuth(sess *channel.Session, f *app.Fragment, raw []byte) {
	if f.Function != app.FuncAuthResponse || c.opts.auth == nil {
		c.log.Debug("response nobody waits for ignored", "seq", f.Control.Seq)
		return
	}
	c.mu.Lock()
	confirm := c.auth.lastConfirm
	c.mu.Unlock()
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			switch v := o.Value.(type) {
			case app.AuthError:
				c.count(secauth.StatErrorMessagesReceived)
				c.log.Warn("authentication error received for no pending request", "code", v.Code.String(), "user", v.User, "seq", f.Control.Seq)
				return
			case app.AuthChallenge:
				if len(confirm) > 0 && confirm[0]&0x0F == f.Control.Seq {
					ctx, cancel := context.WithTimeout(context.Background(), c.opts.responseTimeout)
					defer cancel()
					if _, err := c.answerChallenge(ctx, sess, f.Control.Seq, v, raw, confirm); err != nil {
						c.log.Warn("challenge of a confirmation not answered", "error", err)
					}
					return
				}
			}
		}
	}
	c.log.Debug("authentication response nobody waits for discarded", "seq", f.Control.Seq)
	c.mu.Lock()
	c.countLocked(secauth.StatUnexpectedMessages)
	c.countLocked(secauth.StatDiscardedMessages)
	c.mu.Unlock()
}

// acceptsMAC reports whether a challenge may ask for the MAC algorithm alg:
// one of WithChallengeMACs, or by default any algorithm secauth computes
// except the obsolete HMAC-SHA-1 truncated to 4 octets and, over IP, the
// truncations to 8 octets, which IEEE 1815-2012 clauses 7.6.1.1.1 and
// 7.6.1.1.2 allow on serial links only.
func (c *Client) acceptsMAC(alg app.MACAlgorithm) bool {
	if c.opts.challengeMACs != nil {
		return slices.Contains(c.opts.challengeMACs, alg)
	}
	switch alg {
	case app.MACHMACSHA1Trunc4:
		return false
	case app.MACHMACSHA1Trunc8, app.MACHMACSHA256Trunc8:
		if c.overIP() {
			return false
		}
	default:
	}
	_, err := secauth.MAC(alg, []byte{0}, nil)
	return err == nil
}

// overIP reports whether the client runs over TCP/IP or UDP/IP: over the
// built-in dialer, or over a stream (WithStream) whose remote address is a
// TCP or UDP address.
func (c *Client) overIP() bool {
	if c.opts.opener == nil {
		return true
	}
	switch c.remoteAddr().(type) {
	case *net.TCPAddr, *net.UDPAddr:
		return true
	default:
		return false
	}
}

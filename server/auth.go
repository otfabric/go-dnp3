// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// SecureAuth configures DNP3 Secure Authentication version 5 (see package
// secauth): with an update key, the master negotiates the session keys
// with the session key change; without, a pre-shared session key is used.
//
// The outstation is the challenger of IEEE 1815-2012 Table 7-8, for one
// user per master (association).
type SecureAuth struct {
	// User is the user and its key.
	User secauth.User
	// Critical are the function codes the outstation challenges. Nil
	// selects DefaultCritical. The codes Table 7-7 marks MANDATORY
	// (secauth.MandatoryCritical) are challenged whatever the list says
	// (clause 7.5.2.3.2 a): a list without them is completed with them.
	Critical []app.FunctionCode
	// ReplyTimeout is how long a challenge waits for the master's reply
	// (clause 7.6.1.4.1). When it expires, the challenged request is
	// discarded and counted as a reply timeout; past Max Reply Timeouts
	// the session keys become invalid (COMM_FAIL, Table 7-8). Zero selects
	// DefaultReplyTimeout.
	ReplyTimeout time.Duration
	// StatisticsClass is the event class of security statistic events
	// (g122); zero selects class 1. StatisticsThreshold, when set (at most
	// 65 535), is the event threshold of every statistic Thresholds does
	// not name: the number of increments between two of its events.
	StatisticsClass     Class
	StatisticsThreshold uint32
	// Thresholds sets the event threshold (1..65 535) of single statistics
	// (clause 7.6.1.4.2). A statistic neither names nor StatisticsThreshold
	// covers has the default of IEEE 1815-2012 Table 7-6
	// (secauth.Statistic.DefaultThreshold). The thresholds of
	// authentication failures, reply timeouts, rekeys due to authentication
	// failure and error messages sent are also the steps of the maxima the
	// state machine acts on (Table 7-15): for example, error messages stop
	// once Error Messages Sent exceeds Max Error Messages Sent, until the
	// next valid session key change.
	Thresholds map[secauth.Statistic]uint16
	// NoAggressiveMode refuses aggressive mode requests (clause 7.6.1.4.7):
	// they are discarded and, within Max Error Messages Sent, answered with
	// error 4, aggressive mode not supported.
	NoAggressiveMode bool
	// ExpectedKeyChangeInterval is how long session keys stay valid
	// without a session key change (clause 7.6.1.4.5): once it has passed,
	// the key status is NOT_INIT until the master changes them. Zero
	// selects DefaultExpectedKeyChangeInterval; a negative value disables
	// the interval, leaving ExpectedKeyChangeCount. It does not apply to a
	// pre-shared session key.
	ExpectedKeyChangeInterval time.Duration
	// ExpectedKeyChangeCount is how many authentication messages
	// (challenges, replies and aggressive mode requests) the session keys
	// serve before they become invalid without a session key change
	// (clause 7.6.1.4.5). Zero selects DefaultExpectedKeyChangeCount.
	ExpectedKeyChangeCount uint32
	// MaxKeyStatusRequests is how many session key status requests the
	// outstation takes within the expected key change interval before it
	// reports, as an error in its log, that the limit was exceeded
	// (clause 7.6.1.4.6). The requests are still answered. 2..255; zero
	// selects DefaultMaxKeyStatusRequests.
	MaxKeyStatusRequests int
}

// DefaultCritical are the function codes challenged by default: the ones
// that change the outstation's state.
var DefaultCritical = secauth.DefaultCritical

// DefaultReplyTimeout is how long a challenge waits for its reply when
// SecureAuth.ReplyTimeout is zero: 2 seconds (IEEE 1815-2012 clause
// 7.6.1.4.1).
const DefaultReplyTimeout = 2 * time.Second

// The defaults of the expected session key change (IEEE 1815-2012 clause
// 7.6.1.4.5, which recommends twice the master's 15 minutes and 1000
// messages) and of the maximum session key status count (7.6.1.4.6).
const (
	DefaultExpectedKeyChangeInterval = 30 * time.Minute
	DefaultExpectedKeyChangeCount    = 2000
	DefaultMaxKeyStatusRequests      = 5
)

// WithSecureAuthentication enables Secure Authentication: critical
// requests are executed only after the master answered a challenge with
// the right MAC, or when they carry it themselves in aggressive mode. The
// outstation takes part in the session key change and keeps the security
// statistics (g121, g122) per master. A user number of 0, which IEEE
// 1815-2012 reserves for an unknown user, is taken as 1, the default user.
// The keys are copied: the caller may clear its own slices afterwards.
func WithSecureAuthentication(cfg SecureAuth) Option {
	return func(o *options) error {
		// A copy per server, of the keys too: an Option may be used for
		// several, and the caller keeps its slices.
		sa := cfg
		sa.User.UpdateKey = bytes.Clone(sa.User.UpdateKey)
		sa.User.Key = bytes.Clone(sa.User.Key)
		if err := sa.User.Validate(); err != nil {
			return invalidOption("%v", err)
		}
		if sa.User.Number == 0 {
			sa.User.Number = 1 // 0 is reserved for an unknown user
		}
		if sa.Critical == nil {
			sa.Critical = DefaultCritical
		}
		sa.Critical = withMandatory(sa.Critical)
		if sa.ReplyTimeout <= 0 {
			sa.ReplyTimeout = DefaultReplyTimeout
		}
		if sa.StatisticsClass == 0 {
			sa.StatisticsClass = 1
		}
		if sa.StatisticsClass > 3 {
			return invalidOption("statistics class %d", sa.StatisticsClass)
		}
		if sa.StatisticsThreshold > 0xFFFF {
			return invalidOption("statistics threshold %d: at most 65535", sa.StatisticsThreshold)
		}
		th := make(map[secauth.Statistic]uint16, len(sa.Thresholds))
		for s, v := range sa.Thresholds {
			if s >= secauth.NumStatistics || v == 0 {
				return invalidOption("threshold %d of statistic %d", v, uint16(s))
			}
			th[s] = v
		}
		sa.Thresholds = th
		if sa.ExpectedKeyChangeInterval == 0 {
			sa.ExpectedKeyChangeInterval = DefaultExpectedKeyChangeInterval
		}
		if sa.ExpectedKeyChangeCount == 0 {
			sa.ExpectedKeyChangeCount = DefaultExpectedKeyChangeCount
		}
		if sa.MaxKeyStatusRequests == 0 {
			sa.MaxKeyStatusRequests = DefaultMaxKeyStatusRequests
		}
		if sa.MaxKeyStatusRequests < 2 || sa.MaxKeyStatusRequests > 255 {
			return invalidOption("max key status requests %d: need 2..255", sa.MaxKeyStatusRequests)
		}
		o.auth = &sa
		return nil
	}
}

// withMandatory returns the critical function codes fcs completed with the
// MANDATORY ones of Table 7-7.
func withMandatory(fcs []app.FunctionCode) []app.FunctionCode {
	out := slices.Clone(fcs)
	for _, fc := range secauth.MandatoryCritical {
		if !slices.Contains(out, fc) {
			out = append(out, fc)
		}
	}
	return out
}

// threshold returns the event threshold of statistic s.
func (sa *SecureAuth) threshold(s secauth.Statistic) uint32 {
	if v, ok := sa.Thresholds[s]; ok {
		return uint32(v)
	}
	if sa.StatisticsThreshold > 0 {
		return sa.StatisticsThreshold
	}
	return uint32(s.DefaultThreshold())
}

// challenge is a critical request waiting for the master's reply: the
// Wait for Reply state of Table 7-8.
type challenge struct {
	csq      uint32
	sent     []byte // the encoded challenge fragment
	critical []byte // the encoded critical request
	req      *app.Fragment
	in       inbound
	deadline time.Time // when the reply timer expires
}

// authMax are the moving maxima of IEEE 1815-2012 Table 7-15, by
// statistic: the value of a statistic past which the state machine acts.
// Each is reset to the statistic plus its threshold. The state machine
// uses those of Authentication Failures, Reply Timeouts, Authentication
// Rekeys and Error Messages Sent.
type authMax [secauth.NumStatistics]uint32

func (a *association) critical(fc app.FunctionCode) bool {
	sa := a.srv.opts.auth
	return sa != nil && slices.Contains(sa.Critical, fc)
}

// resetMax sets the maximum of statistic s to its value plus its
// threshold.
func (a *association) resetMax(s secauth.Statistic) {
	sa := a.srv.opts.auth
	if sa == nil {
		return
	}
	a.max[s] = a.stats[s] + sa.threshold(s)
}

// resetAuth is the start-up of secure authentication: Key Status
// NOT_INIT, CSQ and KSQ zero, every maximum reset (IEEE 1815-2012
// 7.5.2.3.3 a, 7.5.5.2, A.45.5, 7.5.2.2).
func (a *association) resetAuth() {
	a.keys.reset()
	a.keys = sessionKeys{}
	a.pendingAuth, a.lastChallenge, a.validReply = nil, nil, false
	a.csq = 0
	a.statusRequests, a.statusWindow = 0, time.Time{}
	for _, s := range []secauth.Statistic{secauth.StatAuthenticationFailures, secauth.StatReplyTimeouts,
		secauth.StatRekeysDueToAuthFailure, secauth.StatErrorMessagesSent} {
		a.resetMax(s)
	}
}

// commFail is the communications failure of Table 7-8 (row 9): the
// connection ended. The challenged request is discarded and the session
// keys become invalid, COMM_FAIL; the last monitoring key is kept for the
// key status MAC (A.45.5).
func (a *association) commFail() {
	if a.srv.opts.auth == nil {
		return
	}
	if a.pendingAuth != nil {
		a.pendingAuth = nil
		a.count(secauth.StatDiscardedMessages)
	}
	a.lastChallenge, a.validReply = nil, false
	if a.keys.state == app.KeyStatusOK || a.keys.state == app.KeyStatusAuthFail {
		a.invalidateKeys(app.KeyStatusCommFail)
	}
	a.resetMax(secauth.StatReplyTimeouts)
}

// sendChallenge holds a critical request and challenges the master (Table
// 7-8, Rx Critical ASDU in Security Idle).
func (a *association) sendChallenge(req *app.Fragment, in inbound) {
	sa := a.srv.opts.auth
	// 32 octets: the standard asks for at least 4, and DSC go-dnp3's
	// master answers only challenges of 32.
	data := make([]byte, 32)
	_, _ = rand.Read(data) // never fails (crypto/rand, Go 1.24)
	a.csq++
	// The user is 0, unknown: the master names it in the reply (Table
	// 7-11, A.45.1).
	ch := app.AuthChallenge{CSQ: a.csq, User: 0, MAC: sa.User.Algorithm(), Reason: app.ReasonCritical, Data: data}
	f := &app.Fragment{
		Control:  app.SingleControl(req.Control.Seq),
		Function: app.FuncAuthResponse,
		IIN:      a.iin(),
		Headers:  []app.Header{app.FreeFormat(app.G120V1, ch)},
	}
	a.count(secauth.StatCriticalMessagesReceived)
	a.keys.count++
	sent := a.send(f)
	a.lastChallenge = sent
	a.pendingAuth = &challenge{csq: a.csq, sent: sent, critical: in.frag, req: req, in: in,
		deadline: time.Now().Add(sa.ReplyTimeout)}
}

// waitDiscards applies Table 7-8 rows 2 and 3 in Wait for Reply: a
// request that is not part of the authentication is discarded while a
// challenge waits for its reply. It reports whether req was discarded.
func (a *association) waitDiscards(req *app.Fragment, err error) bool {
	if a.srv.opts.auth == nil || a.pendingAuth == nil {
		return false
	}
	if err == nil && (req.Function == app.FuncAuthRequest || req.Function == app.FuncAuthRequestNoAck ||
		len(req.Headers) > 0 && req.Headers[0].GV == app.G120V3) {
		return false // authRequest and aggressive handle Wait for Reply
	}
	if err == nil && a.critical(req.Function) {
		a.count(secauth.StatCriticalMessagesReceived)
	}
	a.log.Warn("request discarded: a challenge waits for its reply", "function", req.Function.String(), "seq", req.Control.Seq)
	a.count(secauth.StatUnexpectedMessages)
	a.count(secauth.StatDiscardedMessages)
	return true
}

// onReplyTimer is the Reply Timeout of Table 7-8 (row 7): the challenged
// request is discarded, and past Max Reply Timeouts the session keys
// become invalid (row 9).
func (a *association) onReplyTimer(now time.Time) {
	p := a.pendingAuth
	if p == nil || now.Before(p.deadline) {
		return
	}
	a.pendingAuth = nil
	a.log.Warn("challenge not answered within the reply timeout", "csq", p.csq)
	a.count(secauth.StatReplyTimeouts)
	a.count(secauth.StatDiscardedMessages)
	if a.stats[secauth.StatReplyTimeouts] > a.max[secauth.StatReplyTimeouts] {
		a.log.Warn("max reply timeouts exceeded: session keys invalid", "reply_timeouts", a.stats[secauth.StatReplyTimeouts])
		a.invalidateKeys(app.KeyStatusCommFail)
		a.resetMax(secauth.StatReplyTimeouts)
	}
}

// sessionKeys is the outstation's state of the session key change
// procedure for its user (IEEE 1815-2012 clauses 7.5.5.2..7.5.5.4). It
// belongs to the association goroutine.
type sessionKeys struct {
	ksq uint32
	// state is the Key Status; zero stands for NOT_INIT, the status at
	// start-up.
	state   app.KeyStatus
	control []byte // control direction session key; nil while not valid
	// monitoring is the monitoring direction session key of the last valid
	// key change, kept when the keys become invalid: the key status MAC
	// uses it (A.45.5).
	monitoring []byte
	// status and statusMAC are the last key status object sent, without
	// and with its MAC value: what the key change must carry.
	status, statusMAC []byte
	// change is the last accepted session key change fragment, over which
	// the key status MAC is computed.
	change []byte
	// at and count are when the keys were changed and the authentication
	// messages since: the expected key change of 7.6.1.4.5.
	at    time.Time
	count uint32
}

// reset forgets every key, as at start-up.
func (k *sessionKeys) reset() {
	clear(k.control)
	clear(k.monitoring)
	*k = sessionKeys{ksq: k.ksq}
}

// keyStatus returns the current Key Status.
func (a *association) keyStatus() app.KeyStatus {
	if len(a.srv.opts.auth.User.UpdateKey) == 0 {
		return app.KeyStatusOK // a pre-shared session key is always valid
	}
	if a.keys.state == 0 {
		return app.KeyStatusNotInit
	}
	return a.keys.state
}

// invalidateKeys sets the Key Status to st, which is not OK: the session
// keys are no longer valid (clause 7.5.2.3.5). A pre-shared session key
// cannot be changed and stays valid.
func (a *association) invalidateKeys(st app.KeyStatus) {
	if len(a.srv.opts.auth.User.UpdateKey) == 0 {
		return
	}
	k := &a.keys
	clear(k.control)
	k.control, k.state = nil, st
	a.validReply = false
}

// expireKeys invalidates session keys that were not changed within the
// expected interval or message count (clause 7.6.1.4.5, Table 7-8 row 15).
func (a *association) expireKeys() {
	sa := a.srv.opts.auth
	k := &a.keys
	if len(sa.User.UpdateKey) == 0 || k.state != app.KeyStatusOK {
		return
	}
	late := sa.ExpectedKeyChangeInterval > 0 && time.Since(k.at) > sa.ExpectedKeyChangeInterval
	if late || k.count > sa.ExpectedKeyChangeCount {
		a.log.Info("session keys expired: not changed within the expected interval or count", "messages", k.count)
		a.invalidateKeys(app.KeyStatusNotInit)
	}
}

// controlKey returns the key that verifies challenge replies and
// aggressive mode requests: the pre-shared one without an update key, the
// negotiated one while valid, or nil.
func (a *association) controlKey() []byte {
	u := a.srv.opts.auth.User
	if len(u.UpdateKey) == 0 {
		return u.Key
	}
	a.expireKeys()
	return a.keys.control
}

// authRequest handles AUTHENTICATE_REQ and AUTHENTICATE_REQ_NO_ACK: a reply
// to a challenge, a session key status request, a session key change or an
// error message.
func (a *association) authRequest(req *app.Fragment, in inbound) {
	sa := a.srv.opts.auth
	noAck := req.Function == app.FuncAuthRequestNoAck
	if sa == nil {
		if !noAck {
			a.sendSolicited(req.Control.Seq, &response{iin: app.IINNoFuncCodeSupport})
		}
		return
	}
	for _, h := range req.Headers {
		for _, o := range h.Objects {
			switch v := o.Value.(type) {
			case app.AuthError:
				a.receivedError(v)
				return
			case app.AuthSessionKeyStatusRequest:
				if !noAck {
					a.keyStatusRequest(req, v)
					return
				}
			case app.AuthSessionKeyChange:
				if !noAck {
					a.changeKeys(req, in, v)
					return
				}
			case app.AuthReply:
				if !noAck {
					a.verifyReply(req, v)
					return
				}
			}
		}
	}
	if noAck {
		// AUTHENTICATE_REQ_NO_ACK carries error messages only (Table 7-3).
		a.count(secauth.StatUnexpectedMessages)
		a.count(secauth.StatDiscardedMessages)
		return
	}
	a.sendSolicited(req.Control.Seq, &response{iin: app.IINParameterError})
}

// receivedError handles an error message from the master (Table 7-8 row
// 13): logged and counted; in Wait for Reply the challenged request is
// discarded.
func (a *association) receivedError(v app.AuthError) {
	a.count(secauth.StatErrorMessagesReceived)
	a.log.Warn("authentication error received", "user", v.User, "csq", v.CSQ, "code", v.Code.String())
	if a.pendingAuth != nil {
		a.pendingAuth = nil
		a.count(secauth.StatDiscardedMessages)
		a.resetMax(secauth.StatReplyTimeouts)
	}
}

// keyStatusRequest answers a session key status request (Table 7-8 row
// 16).
func (a *association) keyStatusRequest(req *app.Fragment, v app.AuthSessionKeyStatusRequest) {
	sa := a.srv.opts.auth
	if a.pendingAuth != nil {
		a.log.Warn("session key status request discarded: a challenge waits for its reply", "user", v.User)
		a.count(secauth.StatUnexpectedMessages)
		a.count(secauth.StatDiscardedMessages)
		return
	}
	// The KSQ counts every key status request and key change received
	// (A.45.5).
	a.keys.ksq++
	a.countKeyStatusRequest(v.User)
	if v.User != sa.User.Number {
		// A.45.5: the answer to an invalid user number is the key status
		// AUTH_FAIL (Table 7-8 row 16 discards it instead; the object
		// definition is followed, so that the master learns why).
		a.log.Warn("session key status request for an unknown user", "user", v.User)
		a.count(secauth.StatUnexpectedMessages)
		challenge := make([]byte, 32)
		_, _ = rand.Read(challenge) // never fails (crypto/rand, Go 1.24)
		st := app.AuthSessionKeyStatus{KSQ: a.keys.ksq, User: v.User, KeyWrap: sa.User.KeyWrapAlgorithm(),
			Status: app.KeyStatusAuthFail, Challenge: challenge}
		a.sendAuth(req.Control.Seq, app.FreeFormat(app.G120V5, st))
		return
	}
	a.sendKeyStatus(req.Control.Seq)
}

// countKeyStatusRequest counts session key status requests within the
// expected key change interval and reports, once per interval, that they
// exceeded the maximum (clause 7.6.1.4.6: the outstation shall alert a
// human).
func (a *association) countKeyStatusRequest(user uint16) {
	sa := a.srv.opts.auth
	window := sa.ExpectedKeyChangeInterval
	if window <= 0 {
		window = DefaultExpectedKeyChangeInterval
	}
	now := time.Now()
	if a.statusWindow.IsZero() || now.Sub(a.statusWindow) > window {
		a.statusWindow, a.statusRequests = now, 0
	}
	a.statusRequests++
	if a.statusRequests == sa.MaxKeyStatusRequests+1 {
		a.log.Error("max session key status requests exceeded within the expected key change interval: possible attack",
			"user", user, "requests", a.statusRequests, "max", sa.MaxKeyStatusRequests, "interval", window.String())
	}
}

// sendKeyStatus sends a session key status object for the user with
// fresh challenge data, the current KSQ and Key Status, and remembers it
// for the key change that follows. Its MAC is over the last valid key
// change, with the monitoring key of that change, whether the keys are
// still valid or not (A.45.5); without one there is no MAC.
func (a *association) sendKeyStatus(seq uint8) {
	u := a.srv.opts.auth.User
	challenge := make([]byte, 32)
	_, _ = rand.Read(challenge) // never fails (crypto/rand, Go 1.24)
	a.expireKeys()
	k := &a.keys
	st := app.AuthSessionKeyStatus{KSQ: k.ksq, User: u.Number, KeyWrap: u.KeyWrapAlgorithm(), Status: a.keyStatus(), Challenge: challenge}
	if k.monitoring != nil && k.change != nil {
		mac, err := secauth.MAC(u.Algorithm(), k.monitoring, k.change)
		if err != nil {
			a.log.Error("key status MAC", "error", err)
			return
		}
		st.MAC, st.MACValue = u.Algorithm(), mac
	}
	withMAC, _ := app.AppendObjectValue(nil, app.G120V5, st)
	noMAC := st
	noMAC.MACValue = nil
	k.status, _ = app.AppendObjectValue(nil, app.G120V5, noMAC)
	k.statusMAC = withMAC
	a.sendAuth(seq, app.FreeFormat(app.G120V5, st))
}

// changeKeys handles a session key change: the master's new session keys,
// wrapped with the update key together with the key status message (Table
// 7-8 rows 24 and 25, clause 7.5.5.3).
func (a *association) changeKeys(req *app.Fragment, in inbound, v app.AuthSessionKeyChange) {
	u := a.srv.opts.auth.User
	k := &a.keys
	status, statusMAC, ksq := k.status, k.statusMAC, k.ksq
	k.status, k.statusMAC = nil, nil // a key status is answered by one key change at most
	k.ksq++                          // A.45.5: every key change received counts
	var control, monitoring []byte
	err := errKeyChange
	if len(u.UpdateKey) != 0 && v.User == u.Number && status != nil && v.KSQ == ksq {
		var plain []byte
		if plain, err = secauth.KeyUnwrap(u.UpdateKey, v.WrappedKeys); err == nil {
			// Implementations differ in whether the key status message
			// carries its MAC value: both forms are accepted.
			control, monitoring, err = secauth.ParseKeyChangeData(plain, statusMAC, status)
			clear(plain)
		}
	}
	if err != nil {
		a.log.Warn("session key change refused", "user", v.User, "ksq", v.KSQ, "error", err)
		a.count(secauth.StatFailedSessionKeyChanges)
		if a.pendingAuth != nil {
			// Row 25 in Wait for Reply: discarded.
			a.count(secauth.StatUnexpectedMessages)
			a.count(secauth.StatDiscardedMessages)
			return
		}
		// Row 25 in Security Idle: AUTH_FAIL. The answer is the error
		// message of Table 7-4 (row 25 names a key status instead).
		a.invalidateKeys(app.KeyStatusAuthFail)
		a.authError(req.Control.Seq, v.KSQ, v.User, app.AuthErrAuthenticationFailed)
		return
	}
	if a.pendingAuth != nil {
		// Row 24 in Wait for Reply: the challenged request is discarded.
		a.pendingAuth = nil
		a.count(secauth.StatDiscardedMessages)
		a.resetMax(secauth.StatReplyTimeouts)
	}
	clear(k.control)
	clear(k.monitoring)
	k.control, k.monitoring, k.state = control, monitoring, app.KeyStatusOK
	k.change = append([]byte(nil), in.frag...)
	k.at, k.count = time.Now(), 0
	// A reply must be valid again before aggressive mode (7.5.3.3).
	a.lastChallenge, a.validReply = nil, false
	a.resetMax(secauth.StatErrorMessagesSent)
	a.resetMax(secauth.StatRekeysDueToAuthFailure)
	a.count(secauth.StatSessionKeyChanges)
	// Table 7-6: Authentication Failures is reported at each key change.
	a.report(secauth.StatAuthenticationFailures)
	a.log.Info("session keys changed", "user", v.User)
	a.sendKeyStatus(req.Control.Seq)
}

// errKeyChange stands for a key change that is not even unwrapped: the
// wrong user, mode or KSQ, or no key status sent before it.
var errKeyChange = errors.New("no matching key status")

// authError sends an error message, while Error Messages Sent has not
// exceeded Max Error Messages Sent (clause 7.5.2.4); past it the error is
// only logged until the next valid session key change.
func (a *association) authError(seq uint8, csq uint32, user uint16, code app.AuthErrorCode) {
	if a.stats[secauth.StatErrorMessagesSent] > a.max[secauth.StatErrorMessagesSent] {
		a.log.Debug("authentication error not sent: max error messages sent exceeded", "code", code.String())
		return
	}
	a.count(secauth.StatErrorMessagesSent)
	a.sendAuth(seq, app.FreeFormat(app.G120V7, app.AuthError{CSQ: csq, User: user, Code: code, Time: a.srv.clock.now()}))
}

// verifyReply handles a reply to a challenge (Table 7-8 rows 5 and 6).
func (a *association) verifyReply(req *app.Fragment, r app.AuthReply) {
	sa := a.srv.opts.auth
	a.onReplyTimer(time.Now()) // a reply that came after the timer expired
	p := a.pendingAuth
	if p == nil {
		// Security Idle: a reply nobody asked for is discarded.
		a.log.Warn("unexpected challenge reply discarded", "user", r.User, "csq", r.CSQ)
		a.count(secauth.StatUnexpectedMessages)
		a.count(secauth.StatDiscardedMessages)
		return
	}
	a.pendingAuth = nil
	a.keys.count++
	key := a.controlKey()
	ok := r.CSQ == p.csq && r.User == sa.User.Number && key != nil
	if ok {
		want, err := secauth.MAC(sa.User.Algorithm(), key, secauth.AuthData(p.sent, p.critical))
		ok = err == nil && secauth.Equal(want, r.MAC)
	}
	a.resetMax(secauth.StatReplyTimeouts)
	if !ok {
		a.log.Warn("authentication failed", "user", r.User, "csq", r.CSQ)
		a.count(secauth.StatAuthenticationFailures)
		a.count(secauth.StatDiscardedMessages)
		a.authError(req.Control.Seq, r.CSQ, r.User, app.AuthErrAuthenticationFailed)
		a.checkAuthFailures()
		return
	}
	a.count(secauth.StatSuccessfulAuthentications)
	a.validReply = true
	// Authenticated: execute the critical request. Its response carries
	// the sequence number of the reply, so a SELECT's selection is
	// recorded under that number: the OPERATE that follows carries the next
	// one.
	resp := a.dispatch(p.req, p.in, false)
	if a.selection != nil && p.req.Function == app.FuncSelect {
		a.selection.seq = req.Control.Seq
	}
	if resp.none || p.req.Function.NoAck() {
		return
	}
	a.sendSolicited(req.Control.Seq, resp)
}

// checkAuthFailures is the Max Authentication Failures Exceeded event of
// Table 7-8 (rows 10..12): past Max Authentication Failures the session
// keys become invalid, AUTH_FAIL, so that the master changes them; once
// that happened more often than Max Authentication Rekeys allows without
// a valid key change since, a TCP connection is closed instead.
func (a *association) checkAuthFailures() {
	if a.stats[secauth.StatAuthenticationFailures] <= a.max[secauth.StatAuthenticationFailures] {
		return
	}
	a.resetMax(secauth.StatAuthenticationFailures)
	if a.stats[secauth.StatRekeysDueToAuthFailure] <= a.max[secauth.StatRekeysDueToAuthFailure] {
		a.log.Warn("max authentication failures exceeded: session keys invalid", "failures", a.stats[secauth.StatAuthenticationFailures])
		a.invalidateKeys(app.KeyStatusAuthFail)
		a.count(secauth.StatRekeysDueToAuthFailure)
		return
	}
	a.log.Error("max authentication failures exceeded again after max authentication rekeys: possible attack",
		"failures", a.stats[secauth.StatAuthenticationFailures], "rekeys", a.stats[secauth.StatRekeysDueToAuthFailure])
	if a.sess != nil {
		if _, tcp := a.sess.Channel().Remote().(*net.TCPAddr); tcp {
			a.log.Warn("closing the TCP connection")
			a.sess.Channel().Close(nil)
		}
	}
}

func (a *association) sendAuth(seq uint8, h app.Header) {
	a.send(&app.Fragment{Control: app.SingleControl(seq), Function: app.FuncAuthResponse, IIN: a.iin(), Headers: []app.Header{h}})
}

// aggressive handles a request in aggressive mode (IEEE 1815-2012 clause
// 7.5.3.3, A.45.3 and A.45.9; Table 7-8 rows 17..22): a g120v3 object
// first and a g120v9 MAC last, computed over the outstation's last
// challenge and every octet of the request up to the MAC value (Table
// A-9). It returns the request without those objects, or nil when it was
// refused.
func (a *association) aggressive(req *app.Fragment, in inbound) *app.Fragment {
	sa := a.srv.opts.auth
	hs := req.Headers
	broadcast := in.dest.Broadcast()
	a.count(secauth.StatCriticalMessagesReceived)
	waiting := a.pendingAuth != nil
	if sa.NoAggressiveMode {
		// Rows 20 and 21.
		a.log.Warn("aggressive mode request discarded: aggressive mode is disabled", "seq", req.Control.Seq)
		a.count(secauth.StatUnexpectedMessages)
		a.count(secauth.StatDiscardedMessages)
		if broadcast || a.stats[secauth.StatErrorMessagesSent] > a.max[secauth.StatErrorMessagesSent] {
			return nil
		}
		if waiting {
			a.pendingAuth = nil
			a.count(secauth.StatDiscardedMessages)
			a.resetMax(secauth.StatReplyTimeouts)
		}
		var am app.AuthAggressiveMode
		if len(hs[0].Objects) == 1 {
			am, _ = hs[0].Objects[0].Value.(app.AuthAggressiveMode)
		}
		a.authError(req.Control.Seq, am.CSQ, am.User, app.AuthErrAggressiveModeNotSupported)
		return nil
	}
	var am app.AuthAggressiveMode
	var mac app.AuthMAC
	last := len(hs) - 1
	ok := len(hs) >= 2 && len(hs[0].Objects) == 1 && hs[last].GV == app.G120V9 &&
		hs[last].Qualifier == app.Qual2ByteSizeFreeFormat && len(hs[last].Objects) == 1
	if ok {
		am, ok = hs[0].Objects[0].Value.(app.AuthAggressiveMode)
	}
	if ok {
		mac, ok = hs[last].Objects[0].Value.(app.AuthMAC)
	}
	a.keys.count++
	key := a.controlKey()
	// The request must follow a valid reply since the last key change
	// (7.5.2.3.4, 7.5.3.3), take the next CSQ (7.5.2.3.3 d) and end with
	// the MAC value.
	n := len(mac.MAC)
	ok = ok && am.User == sa.User.Number && am.CSQ == a.csq+1 && a.lastChallenge != nil && a.validReply && key != nil &&
		n > 0 && len(in.frag) > n && bytes.Equal(in.frag[len(in.frag)-n:], mac.MAC)
	if ok {
		want, err := secauth.MAC(sa.User.Algorithm(), key, secauth.AuthData(a.lastChallenge, in.frag[:len(in.frag)-n]))
		ok = err == nil && secauth.Equal(want, mac.MAC)
	}
	if !ok {
		a.log.Warn("aggressive mode request refused", "user", am.User, "csq", am.CSQ)
		a.count(secauth.StatAuthenticationFailures)
		if waiting {
			// Row 22 in Wait for Reply: discarded without an error.
			a.count(secauth.StatUnexpectedMessages)
			a.count(secauth.StatDiscardedMessages)
		} else if !broadcast {
			// Nobody answers a broadcast, not even with an error.
			a.authError(req.Control.Seq, am.CSQ, am.User, app.AuthErrAuthenticationFailed)
		}
		a.checkAuthFailures()
		return nil
	}
	if waiting {
		// Row 17 in Wait for Reply: the challenged request is discarded.
		a.pendingAuth = nil
		a.count(secauth.StatUnexpectedMessages)
		a.count(secauth.StatDiscardedMessages)
		a.resetMax(secauth.StatReplyTimeouts)
	}
	a.csq = am.CSQ // the next challenge takes the following CSQ (7.5.2.3.3 e)
	a.count(secauth.StatSuccessfulAuthentications)
	out := *req
	out.Headers = hs[1:last]
	return &out
}

// count increments a security statistic and reports it as an event once
// it has grown by its threshold since it was last reported (clause
// 7.6.1.4.2).
func (a *association) count(s secauth.Statistic) {
	sa := a.srv.opts.auth
	if sa == nil {
		return
	}
	a.stats[s]++
	if a.stats[s]-a.reported[s] >= sa.threshold(s) {
		a.report(s)
	}
}

// report adds an event (g122) with the value of statistic s. Statistics
// are reported on the association they measure: Association ID 0 (clause
// 7.5.2.2).
func (a *association) report(s secauth.Statistic) {
	sa := a.srv.opts.auth
	a.reported[s] = a.stats[s]
	v := app.SecurityStatistic{Flags: app.FlagOnline, Association: 0, Value: a.stats[s], Time: a.srv.clock.now()}
	a.events.add([]event{{typ: SecurityStatistic, index: uint32(s), class: sa.StatisticsClass, value: v}})
	a.wake()
}

// statisticItems returns the security statistics a READ of g121 names.
func (a *association) statisticItems(sel selector, variation uint8, p *readPlan) []item {
	if a.srv.opts.auth == nil || (variation != 0 && variation != 1) {
		p.iin |= app.IINObjectUnknown
		return nil
	}
	h := app.Header{GV: app.G121V1, Qualifier: app.Qual1ByteStartStop}
	if sel.indexes != nil {
		h.Qualifier = app.Qual2ByteIndexCount
	}
	for i := range uint32(secauth.NumStatistics) {
		if !sel.has(i) {
			continue
		}
		h.Objects = append(h.Objects, app.Object{Index: i, Value: app.SecurityStatistic{
			Flags: app.FlagOnline, Association: 0, Value: a.stats[i]}})
	}
	if !sel.all && (sel.indexes == nil && sel.stop >= uint32(secauth.NumStatistics) || len(h.Objects) == 0) {
		p.iin |= app.IINParameterError
	}
	if len(h.Objects) == 0 {
		return nil
	}
	return []item{{h: h}}
}

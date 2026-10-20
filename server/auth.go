// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/rand"
	"slices"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// SecureAuth configures DNP3 Secure Authentication version 5 (see package
// secauth): with an update key, the master negotiates the session keys
// with the session key change; without, a pre-shared session key is used.
type SecureAuth struct {
	// User is the user and its key.
	User secauth.User
	// Critical are the function codes the outstation challenges. Nil
	// selects DefaultCritical.
	Critical []app.FunctionCode
	// ReplyTimeout is how long a challenge waits for the master's reply;
	// a later reply counts as a reply timeout and is refused. Zero
	// selects DefaultReplyTimeout.
	ReplyTimeout time.Duration
	// StatisticsClass is the event class of security statistic events
	// (g122); zero selects class 1. StatisticsThreshold is the number of
	// increments of a statistic between two of its events; zero selects
	// 10.
	StatisticsClass     Class
	StatisticsThreshold uint32
}

// DefaultCritical are the function codes challenged by default: the ones
// that change the outstation's state.
var DefaultCritical = secauth.DefaultCritical

// DefaultReplyTimeout is how long a challenge waits for its reply when
// SecureAuth.ReplyTimeout is zero.
const DefaultReplyTimeout = 10 * time.Second

// WithSecureAuthentication enables Secure Authentication: critical
// requests are executed only after the master answered a challenge with
// the right MAC, or when they carry it themselves in aggressive mode. The
// outstation takes part in the session key change and keeps the security
// statistics (g121, g122) per master.
func WithSecureAuthentication(sa SecureAuth) Option {
	return func(o *options) error {
		if err := sa.User.Validate(); err != nil {
			return invalidOption("%v", err)
		}
		if sa.Critical == nil {
			sa.Critical = DefaultCritical
		}
		if sa.ReplyTimeout <= 0 {
			sa.ReplyTimeout = DefaultReplyTimeout
		}
		if sa.StatisticsClass == 0 {
			sa.StatisticsClass = 1
		}
		if sa.StatisticsClass > 3 {
			return invalidOption("statistics class %d", sa.StatisticsClass)
		}
		if sa.StatisticsThreshold == 0 {
			sa.StatisticsThreshold = 10
		}
		o.auth = &sa
		return nil
	}
}

// challenge is a critical request waiting for the master's reply.
type challenge struct {
	csq      uint32
	sent     []byte // the encoded challenge fragment
	critical []byte // the encoded critical request
	req      *app.Fragment
	in       inbound
	at       time.Time
}

func (a *association) critical(fc app.FunctionCode) bool {
	sa := a.srv.opts.auth
	return sa != nil && slices.Contains(sa.Critical, fc)
}

// sendChallenge holds a critical request and challenges the master.
func (a *association) sendChallenge(req *app.Fragment, in inbound) {
	sa := a.srv.opts.auth
	// 32 octets: the standard asks for at least 4, and DSC go-dnp3
	// go-dnp3's master answers only challenges of 32.
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		a.log.Error("no random challenge data", "error", err)
		return
	}
	a.csq++
	ch := app.AuthChallenge{CSQ: a.csq, User: sa.User.Number, MAC: sa.User.Algorithm(), Reason: app.ReasonCritical, Data: data}
	f := &app.Fragment{
		Control:  app.SingleControl(req.Control.Seq),
		Function: app.FuncAuthResponse,
		IIN:      a.iin(),
		Headers:  []app.Header{app.FreeFormat(app.G120V1, ch)},
	}
	if a.pendingAuth != nil {
		// A request that is not the reply abandons the challenge.
		a.count(secauth.StatDiscardedMessages)
	}
	a.count(secauth.StatCriticalMessagesReceived)
	sent := a.send(f)
	a.lastChallenge = sent
	a.pendingAuth = &challenge{csq: a.csq, sent: sent, critical: in.frag, req: req, in: in, at: time.Now()}
}

// sessionKeys is the outstation's state of the session key change
// procedure for its user (IEEE 1815-2012 clause 7.5.2.3). It belongs to
// the association goroutine.
type sessionKeys struct {
	ksq        uint32
	control    []byte // control direction session key; nil until a key change
	monitoring []byte
	// status and statusMAC are the last key status object sent, without
	// and with its MAC value: what the key change must carry.
	status, statusMAC []byte
	// change is the last accepted session key change fragment, over which
	// the next key status MAC is computed.
	change []byte
}

// reset invalidates the session keys, when the connection ends.
func (k *sessionKeys) reset() {
	clear(k.control)
	clear(k.monitoring)
	*k = sessionKeys{ksq: k.ksq}
}

// controlKey returns the key that verifies challenge replies: the
// negotiated session key, or the pre-shared one without an update key.
func (a *association) controlKey() []byte {
	u := a.srv.opts.auth.User
	if len(u.UpdateKey) == 0 {
		return u.Key
	}
	return a.keys.control
}

// authRequest handles AUTHENTICATE_REQ: a reply to a challenge, a session
// key status request or a session key change.
func (a *association) authRequest(req *app.Fragment, in inbound) {
	sa := a.srv.opts.auth
	if sa == nil {
		a.sendSolicited(req.Control.Seq, &response{iin: app.IINNoFuncCodeSupport})
		return
	}
	for _, h := range req.Headers {
		for _, o := range h.Objects {
			switch v := o.Value.(type) {
			case app.AuthSessionKeyStatusRequest:
				if v.User != sa.User.Number {
					a.authError(req.Control.Seq, 0, v.User, app.AuthErrUnknownUser)
					return
				}
				a.sendKeyStatus(req.Control.Seq)
				return
			case app.AuthSessionKeyChange:
				a.changeKeys(req, in, v)
				return
			case app.AuthReply:
				a.verifyReply(req, v)
				return
			case app.AuthError:
				a.count(secauth.StatErrorMessagesReceived)
				a.log.Warn("authentication error received", "user", v.User, "code", v.Code.String())
				return
			}
		}
	}
	a.sendSolicited(req.Control.Seq, &response{iin: app.IINParameterError})
}

// sendKeyStatus sends a session key status object with fresh challenge
// data and remembers it for the key change that follows.
func (a *association) sendKeyStatus(seq uint8) {
	u := a.srv.opts.auth.User
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		a.log.Error("no random challenge data", "error", err)
		return
	}
	k := &a.keys
	k.ksq++
	st := app.AuthSessionKeyStatus{KSQ: k.ksq, User: u.Number, KeyWrap: u.KeyWrapAlgorithm(), Status: app.KeyStatusNotInit, Challenge: challenge}
	if len(u.UpdateKey) == 0 {
		// Pre-shared session keys are always initialized.
		st.Status, st.MAC = app.KeyStatusOK, u.Algorithm()
	} else if k.control != nil {
		st.Status, st.MAC = app.KeyStatusOK, u.Algorithm()
		mac, err := secauth.MAC(u.Algorithm(), k.monitoring, k.change)
		if err != nil {
			a.log.Error("key status MAC", "error", err)
			return
		}
		st.MACValue = mac
	}
	withMAC, _ := app.AppendObjectValue(nil, app.G120V5, st)
	noMAC := st
	noMAC.MACValue = nil
	k.status, _ = app.AppendObjectValue(nil, app.G120V5, noMAC)
	k.statusMAC = withMAC
	a.sendAuth(seq, app.FreeFormat(app.G120V5, st))
}

// changeKeys handles a session key change: the master's new session keys,
// wrapped with the update key together with the key status message.
func (a *association) changeKeys(req *app.Fragment, in inbound, v app.AuthSessionKeyChange) {
	u := a.srv.opts.auth.User
	k := &a.keys
	status, statusMAC := k.status, k.statusMAC
	k.status, k.statusMAC = nil, nil // a key status is answered by one key change at most
	if len(u.UpdateKey) == 0 || v.User != u.Number || status == nil || v.KSQ != k.ksq {
		a.log.Warn("session key change refused", "user", v.User, "ksq", v.KSQ)
		a.count(secauth.StatFailedSessionKeyChanges)
		a.authError(req.Control.Seq, v.KSQ, v.User, app.AuthErrAuthenticationFailed)
		return
	}
	plain, err := secauth.KeyUnwrap(u.UpdateKey, v.WrappedKeys)
	var control, monitoring []byte
	if err == nil {
		// Implementations differ in whether the key status message carries
		// its MAC value: both forms are accepted.
		control, monitoring, err = secauth.ParseKeyChangeData(plain, statusMAC, status)
		clear(plain)
	}
	if err != nil {
		a.log.Warn("session key change failed", "user", v.User, "error", err)
		a.count(secauth.StatFailedSessionKeyChanges)
		a.authError(req.Control.Seq, v.KSQ, v.User, app.AuthErrAuthenticationFailed)
		return
	}
	k.reset()
	k.ksq = v.KSQ
	k.control, k.monitoring = control, monitoring
	k.change = append([]byte(nil), in.frag...)
	a.count(secauth.StatSessionKeyChanges)
	a.log.Info("session keys changed", "user", v.User)
	a.sendKeyStatus(req.Control.Seq)
}

func (a *association) authError(seq uint8, csq uint32, user uint16, code app.AuthErrorCode) {
	a.count(secauth.StatErrorMessagesSent)
	a.sendAuth(seq, app.FreeFormat(app.G120V7, app.AuthError{CSQ: csq, User: user, Code: code, Time: a.srv.clock.now()}))
}

func (a *association) verifyReply(req *app.Fragment, r app.AuthReply) {
	sa := a.srv.opts.auth
	p := a.pendingAuth
	a.pendingAuth = nil
	if p == nil {
		a.count(secauth.StatUnexpectedMessages)
		a.authError(req.Control.Seq, r.CSQ, r.User, app.AuthErrAuthenticationFailed)
		return
	}
	if time.Since(p.at) > sa.ReplyTimeout {
		a.log.Warn("challenge reply too late", "user", r.User, "csq", r.CSQ)
		a.count(secauth.StatReplyTimeouts)
		a.authError(req.Control.Seq, r.CSQ, r.User, app.AuthErrAuthenticationFailed)
		return
	}
	key := a.controlKey()
	ok := r.CSQ == p.csq && r.User == sa.User.Number && key != nil
	if ok {
		want, err := secauth.MAC(sa.User.Algorithm(), key, secauth.AuthData(p.sent, p.critical))
		ok = err == nil && secauth.Equal(want, r.MAC)
	}
	if !ok {
		a.log.Warn("authentication failed", "user", r.User, "csq", r.CSQ)
		a.count(secauth.StatAuthenticationFailures)
		a.authError(req.Control.Seq, r.CSQ, r.User, app.AuthErrAuthenticationFailed)
		return
	}
	a.count(secauth.StatSuccessfulAuthentications)
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

func (a *association) sendAuth(seq uint8, h app.Header) {
	a.send(&app.Fragment{Control: app.SingleControl(seq), Function: app.FuncAuthResponse, IIN: a.iin(), Headers: []app.Header{h}})
}

// aggressive handles a request in aggressive mode (IEEE 1815-2012 clause
// 7.5.2.2.4): a g120v3 object first and a g120v9 MAC last, computed over
// the outstation's last challenge and the request up to the MAC. It
// returns the request without those objects, or nil when it was refused.
func (a *association) aggressive(req *app.Fragment, in inbound) *app.Fragment {
	sa := a.srv.opts.auth
	hs := req.Headers
	a.count(secauth.StatCriticalMessagesReceived)
	var am app.AuthAggressiveMode
	var mac app.AuthMAC
	ok := len(hs) >= 2 && len(hs[0].Objects) == 1 && hs[len(hs)-1].GV == app.G120V9 && len(hs[len(hs)-1].Objects) == 1
	if ok {
		am, ok = hs[0].Objects[0].Value.(app.AuthAggressiveMode)
	}
	if ok {
		mac, ok = hs[len(hs)-1].Objects[0].Value.(app.AuthMAC)
	}
	if !ok {
		a.count(secauth.StatUnexpectedMessages)
		if !in.dest.Broadcast() {
			a.authError(req.Control.Seq, 0, sa.User.Number, app.AuthErrAuthenticationFailed)
		}
		return nil
	}
	// The octets the MAC covers end where the g120v9 object begins: its
	// encoding is the same in every request.
	tail, _ := (&app.Fragment{Headers: hs[len(hs)-1:]}).Encode()
	empty, _ := (&app.Fragment{}).Encode()
	n := len(tail) - len(empty)
	key := a.controlKey()
	ok = am.User == sa.User.Number && am.CSQ == a.csq+1 && a.lastChallenge != nil && key != nil &&
		n > 0 && len(in.frag) > n && bytes.Equal(in.frag[len(in.frag)-n:], tail[len(empty):])
	if ok {
		want, err := secauth.MAC(sa.User.Algorithm(), key, secauth.AuthData(a.lastChallenge, in.frag[:len(in.frag)-n]))
		ok = err == nil && secauth.Equal(want, mac.MAC)
	}
	if !ok {
		a.log.Warn("aggressive mode request refused", "user", am.User, "csq", am.CSQ)
		a.count(secauth.StatAuthenticationFailures)
		if !in.dest.Broadcast() {
			// Nobody answers a broadcast, not even with an error.
			a.authError(req.Control.Seq, am.CSQ, am.User, app.AuthErrAuthenticationFailed)
		}
		return nil
	}
	a.csq = am.CSQ
	a.count(secauth.StatSuccessfulAuthentications)
	out := *req
	out.Headers = hs[1 : len(hs)-1]
	return &out
}

// count increments a security statistic and, every StatisticsThreshold
// increments, reports it as an event.
func (a *association) count(s secauth.Statistic) {
	sa := a.srv.opts.auth
	if sa == nil {
		return
	}
	a.stats[s]++
	if a.stats[s]%sa.StatisticsThreshold != 0 {
		return
	}
	v := app.SecurityStatistic{Flags: app.FlagOnline, Association: uint16(a.master), Value: a.stats[s], Time: a.srv.clock.now()}
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
			Flags: app.FlagOnline, Association: uint16(a.master), Value: a.stats[i]}})
	}
	if !sel.all && (sel.indexes == nil && sel.stop >= uint32(secauth.NumStatistics) || len(h.Objects) == 0) {
		p.iin |= app.IINParameterError
	}
	if len(h.Objects) == 0 {
		return nil
	}
	return []item{{h: h}}
}

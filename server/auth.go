// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"slices"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// SecureAuth configures DNP3 Secure Authentication version 5 with a
// pre-shared session key (see package secauth).
type SecureAuth struct {
	// User is the user and its key.
	User secauth.User
	// Critical are the function codes the outstation challenges. Nil
	// selects DefaultCritical.
	Critical []app.FunctionCode
}

// DefaultCritical are the function codes challenged by default: the ones
// that change the outstation's state.
var DefaultCritical = []app.FunctionCode{
	app.FuncWrite, app.FuncSelect, app.FuncOperate, app.FuncDirectOperate, app.FuncDirectOperateNoAck,
	app.FuncImmediateFreeze, app.FuncImmediateFreezeNoAck, app.FuncFreezeClear, app.FuncFreezeClearNoAck,
	app.FuncFreezeAtTime, app.FuncFreezeAtTimeNoAck, app.FuncColdRestart, app.FuncWarmRestart,
	app.FuncInitializeData, app.FuncInitializeApplication, app.FuncStartApplication, app.FuncStopApplication,
	app.FuncSaveConfiguration, app.FuncAssignClass, app.FuncOpenFile, app.FuncDeleteFile,
	app.FuncActivateConfig, app.FuncAuthenticateFile,
}

// WithSecureAuthentication enables Secure Authentication: critical
// requests are executed only after the master answered a challenge with
// the right MAC.
func WithSecureAuthentication(sa SecureAuth) Option {
	return func(o *options) error {
		if err := sa.User.Validate(); err != nil {
			return invalidOption("%v", err)
		}
		if sa.Critical == nil {
			sa.Critical = DefaultCritical
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
}

func (a *association) critical(fc app.FunctionCode) bool {
	sa := a.srv.opts.auth
	return sa != nil && slices.Contains(sa.Critical, fc)
}

// sendChallenge holds a critical request and challenges the master.
func (a *association) sendChallenge(req *app.Fragment, in inbound) {
	sa := a.srv.opts.auth
	data := make([]byte, 16)
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
	sent := a.send(f)
	a.pendingAuth = &challenge{csq: a.csq, sent: sent, critical: in.frag, req: req, in: in}
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
		a.authFailures++
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
		a.authFailures++
		a.authError(req.Control.Seq, v.KSQ, v.User, app.AuthErrAuthenticationFailed)
		return
	}
	k.reset()
	k.ksq = v.KSQ
	k.control, k.monitoring = control, monitoring
	k.change = append([]byte(nil), in.frag...)
	a.log.Info("session keys changed", "user", v.User)
	a.sendKeyStatus(req.Control.Seq)
}

func (a *association) authError(seq uint8, csq uint32, user uint16, code app.AuthErrorCode) {
	a.sendAuth(seq, app.FreeFormat(app.G120V7, app.AuthError{CSQ: csq, User: user, Code: code, Time: a.srv.clock.now()}))
}

func (a *association) verifyReply(req *app.Fragment, r app.AuthReply) {
	sa := a.srv.opts.auth
	p := a.pendingAuth
	a.pendingAuth = nil
	key := a.controlKey()
	ok := p != nil && r.CSQ == p.csq && r.User == sa.User.Number && key != nil
	if ok {
		want, err := secauth.MAC(sa.User.Algorithm(), key, secauth.AuthData(p.sent, p.critical))
		ok = err == nil && secauth.Equal(want, r.MAC)
	}
	if !ok {
		a.log.Warn("authentication failed", "user", r.User, "csq", r.CSQ)
		a.authFailures++
		a.authError(req.Control.Seq, r.CSQ, r.User, app.AuthErrAuthenticationFailed)
		return
	}
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

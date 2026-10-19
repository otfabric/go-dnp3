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

// authRequest handles AUTHENTICATE_REQ: a reply to a challenge, or a
// session key status request.
func (a *association) authRequest(req *app.Fragment) {
	sa := a.srv.opts.auth
	if sa == nil {
		a.sendSolicited(req.Control.Seq, &response{iin: app.IINNoFuncCodeSupport})
		return
	}
	for _, h := range req.Headers {
		for _, o := range h.Objects {
			switch v := o.Value.(type) {
			case app.AuthSessionKeyStatusRequest:
				a.sendAuth(req.Control.Seq, app.FreeFormat(app.G120V5, app.AuthSessionKeyStatus{
					KSQ: a.csq, User: v.User, KeyWrap: app.KeyWrapAES256, Status: app.KeyStatusOK, MAC: sa.User.Algorithm(),
				}))
				return
			case app.AuthReply:
				a.verifyReply(req, v)
				return
			}
		}
	}
	a.sendSolicited(req.Control.Seq, &response{iin: app.IINParameterError})
}

func (a *association) verifyReply(req *app.Fragment, r app.AuthReply) {
	sa := a.srv.opts.auth
	p := a.pendingAuth
	a.pendingAuth = nil
	ok := p != nil && r.CSQ == p.csq && r.User == sa.User.Number
	if ok {
		want, err := secauth.MAC(sa.User.Algorithm(), sa.User.Key, secauth.AuthData(p.sent, p.critical))
		ok = err == nil && secauth.Equal(want, r.MAC)
	}
	if !ok {
		a.log.Warn("authentication failed", "user", r.User, "csq", r.CSQ)
		a.authFailures++
		a.sendAuth(req.Control.Seq, app.FreeFormat(app.G120V7, app.AuthError{
			CSQ: r.CSQ, User: r.User, Code: app.AuthErrAuthenticationFailed, Time: a.srv.clock.now(),
		}))
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

// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// association is the outstation's side of one master: its event buffer,
// internal indications, select-before-operate state and unsolicited
// state. Everything but the event buffer is owned by the goroutine run;
// other goroutines reach it through post and receive.
type association struct {
	srv    *Server
	master link.Address
	events *eventBuffer
	log    *logx.Logger

	fn     chan func()
	wakeCh chan struct{}
	done   chan struct{}
	once   sync.Once

	// Owned by run.
	sess       *channel.Session
	restartIIN bool
	broadcast  bool
	lastSync   time.Time
	lastReq    *lastRequest
	selection  *selection
	recorded   time.Time
	sol        *pendingResponse
	unsol      *pendingUnsol
	unsolMask  uint8 // enabled classes, 1<<class
	nullDone   bool  // the null unsolicited response was confirmed
	unsolSeq   uint8
	holdStart  time.Time
	unsolPause time.Time
	timer      *time.Timer

	pendingAuth   *challenge
	lastChallenge []byte // the last g120v1 fragment sent
	keys          sessionKeys
	csq           uint32
	stats         [secauth.NumStatistics]uint32

	// broadcastTo is the address of the last broadcast: whether the
	// response reporting it asks for confirmation.
	broadcastTo link.Address

	files             map[uint32]*openFile
	nextHandle        uint32
	pendingFileStatus []app.FileTransportStatus
}

type inbound struct {
	sess *channel.Session
	frag []byte
	dest link.Address
	at   time.Time
}

// lastRequest is kept to answer a repeated request with the same
// response instead of executing it twice.
type lastRequest struct {
	seq  uint8
	data []byte
	resp []byte // nil when the request had no response
}

// pendingResponse is a solicited response waiting for its confirmation.
type pendingResponse struct {
	seq      uint8
	plans    []fragPlan
	next     int // index of the fragment waiting for its confirmation
	iin      app.IIN
	deadline time.Time
	// broadcast: the first fragment reported IIN1.0, which its
	// confirmation clears.
	broadcast bool
}

// pendingUnsol is an unsolicited response waiting for its confirmation.
type pendingUnsol struct {
	null     bool
	seq      uint8
	data     []byte
	events   []*bufEvent
	attempts int
	deadline time.Time
}

func newAssociation(s *Server, master link.Address) *association {
	a := &association{
		srv:        s,
		master:     master,
		events:     newEventBuffer(s.opts.eventLimits),
		log:        s.log.With("master", master),
		fn:         make(chan func(), 32),
		wakeCh:     make(chan struct{}, 1),
		done:       make(chan struct{}),
		restartIIN: true,
		timer:      time.NewTimer(time.Hour),
		files:      make(map[uint32]*openFile),
	}
	a.timer.Stop()
	a.unsolMask = a.startupMask()
	return a
}

func (a *association) startupMask() uint8 {
	var m uint8
	for _, c := range a.srv.opts.unsolicited.Classes {
		m |= 1 << c
	}
	return m
}

// post runs f on the association's goroutine.
func (a *association) post(f func()) {
	select {
	case a.fn <- f:
	case <-a.done:
	}
}

func (a *association) wake() {
	select {
	case a.wakeCh <- struct{}{}:
	default:
	}
}

func (a *association) close() {
	a.once.Do(func() { close(a.done) })
}

// attach makes sess the session the association answers on.
func (a *association) attach(sess *channel.Session) {
	a.post(func() {
		if a.sess == sess {
			return
		}
		if old := a.sess; old != nil && old.Channel() != sess.Channel() {
			// A master connected again while its old connection still
			// stood: the old one is closed.
			a.log.Info("master reconnected, closing its previous connection")
			old.Channel().Close(nil)
		}
		a.detach()
		a.sess = sess
		// Every connection starts with a null unsolicited response; the
		// classes the master enabled belong to the outstation and survive
		// connections.
		a.nullDone = false
		go func() {
			<-sess.Channel().Done()
			a.post(func() {
				if a.sess == sess {
					a.detach()
					a.sess = nil
				}
			})
		}()
	})
}

// detach abandons what was in progress on the current session: its
// unconfirmed events are reported again later.
func (a *association) detach() {
	a.abandonSolicited()
	if a.unsol != nil {
		a.events.release(a.unsol.events)
		a.unsol = nil
	}
	a.selection = nil
	a.lastReq = nil
	a.closeFiles()
	// Session keys do not survive the connection (clause 7.5.2.3).
	a.keys.reset()
	a.pendingAuth, a.lastChallenge = nil, nil
}

// receive queues a fragment from sess. It goes through the same queue
// as attach, so a session's fragments are never handled before it is
// attached.
func (a *association) receive(sess *channel.Session, frag []byte, dest link.Address) {
	in := inbound{sess: sess, frag: frag, dest: dest, at: time.Now()}
	a.post(func() {
		if in.sess == a.sess {
			a.handle(in)
		}
	})
}

// restart is Server.Restart for one association.
func (a *association) restart() {
	a.detach()
	a.restartIIN = true
	a.nullDone = false
	a.unsolMask = a.startupMask()
	a.events.mu.Lock()
	a.events.events = nil
	a.events.count = [numPointTypes]int{}
	a.events.overflow = false
	a.events.mu.Unlock()
}

func (a *association) run() {
	defer a.srv.wg.Done()
	defer a.timer.Stop()
	for {
		a.maybeUnsolicited()
		a.arm()
		select {
		case <-a.done:
			a.detach()
			return
		case f := <-a.fn:
			f()
		case <-a.wakeCh:
		case <-a.timer.C:
			a.onTimer()
		}
	}
}

// arm sets the timer to the earliest deadline.
func (a *association) arm() {
	var next time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	if a.sol != nil {
		consider(a.sol.deadline)
	}
	if a.unsol != nil {
		consider(a.unsol.deadline)
	}
	consider(a.unsolPause)
	if u := a.srv.opts.unsolicited; !a.holdStart.IsZero() && u.HoldTime > 0 {
		consider(a.holdStart.Add(u.HoldTime))
	}
	a.timer.Stop()
	select {
	case <-a.timer.C:
	default:
	}
	if !next.IsZero() {
		a.timer.Reset(max(time.Until(next), 0))
	}
}

func (a *association) onTimer() {
	now := time.Now()
	if a.sol != nil && !now.Before(a.sol.deadline) {
		a.log.Debug("response not confirmed", "seq", a.sol.seq)
		a.abandonSolicited()
	}
	if u := a.unsol; u != nil && !now.Before(u.deadline) {
		if u.attempts < a.srv.opts.unsolicited.Retries {
			u.attempts++
			u.deadline = now.Add(a.srv.opts.confirmTimeout)
			a.log.Debug("unsolicited response repeated", "seq", u.seq, "attempt", u.attempts)
			a.sendRaw(u.data)
		} else {
			err := fmt.Errorf("%w: unsolicited response not confirmed", dnp3.ErrTimeout)
			a.log.Info("unsolicited response given up", "seq", u.seq, "events", len(u.events))
			a.events.release(u.events)
			if a.srv.sm != nil {
				a.srv.sm.OnUnsolicited(a.remote(), len(u.events), err)
			}
			a.unsol = nil
			a.unsolSeq = app.NextSeq(a.unsolSeq)
			a.unsolPause = now.Add(a.srv.opts.unsolicited.RetryDelay)
		}
	}
	if !a.unsolPause.IsZero() && !now.Before(a.unsolPause) {
		a.unsolPause = time.Time{}
	}
}

func (a *association) remote() net.Addr {
	if a.sess == nil {
		return nil
	}
	return a.sess.Channel().Remote()
}

// iin returns the internal indications of the next response.
func (a *association) iin() app.IIN {
	i := a.events.iin() | a.srv.indications()
	if a.restartIIN {
		i |= app.IINDeviceRestart
	}
	if a.broadcast {
		i |= app.IINBroadcast
	}
	if n := a.srv.opts.needTime; n > 0 && (a.lastSync.IsZero() || time.Since(a.lastSync) > n) {
		i |= app.IINNeedTime
	}
	return i
}

func (a *association) handle(in inbound) {
	req, err := app.Decode(in.frag)
	if req == nil {
		a.log.Debug("undecodable fragment dropped", "error", err)
		if m := a.srv.opts.metrics; m != nil {
			m.OnDecodeError(a.remote(), err)
		}
		return
	}
	if m := a.srv.opts.metrics; m != nil {
		m.OnFragmentReceived(a.remote(), req, len(in.frag))
	}
	if a.log.DebugEnabled() {
		a.log.Debug("request received", "fragment", req.String())
	}
	if req.Function.IsResponse() {
		a.log.Debug("response function sent to an outstation ignored", "function", req.Function.String())
		return
	}
	if req.Function == app.FuncConfirm {
		a.onConfirm(req)
		return
	}
	if !req.Control.FIR || !req.Control.FIN {
		a.log.Warn("multi-fragment request ignored", "control", req.Control.String())
		return
	}
	broadcast := in.dest.Broadcast()
	if !broadcast {
		if r := a.lastReq; r != nil && r.seq == req.Control.Seq && bytes.Equal(r.data, in.frag) && req.Function != app.FuncRead {
			a.log.Debug("repeated request answered with the previous response", "seq", r.seq)
			if r.resp != nil {
				a.sendRaw(r.resp)
			}
			return
		}
	}
	a.abandonSolicited()
	a.count(secauth.StatTotalMessagesReceived)
	if err == nil && (req.Function == app.FuncAuthRequest || req.Function == app.FuncAuthRequestNoAck) {
		a.authRequest(req, in)
		return
	}
	if err == nil && a.srv.opts.auth != nil && len(req.Headers) > 0 && req.Headers[0].GV == app.G120V3 {
		if req = a.aggressive(req, in); req == nil {
			return
		}
	} else if err == nil && a.critical(req.Function) {
		if broadcast {
			// A broadcast cannot be challenged: with secure authentication
			// a critical one is carried out only in aggressive mode.
			a.log.Warn("unauthenticated critical broadcast discarded", "function", req.Function.String())
			a.count(secauth.StatDiscardedMessages)
			return
		}
		a.sendChallenge(req, in)
		return
	}
	start := time.Now()

	var resp *response
	if err != nil {
		resp = &response{iin: errorIIN(err)}
		a.log.Debug("request rejected", "error", err)
	} else {
		resp = a.dispatch(req, in, broadcast)
	}
	if a.srv.sm != nil {
		a.srv.sm.OnHandled(a.remote(), req.Function, time.Since(start))
	}
	if broadcast {
		a.broadcast, a.broadcastTo = true, in.dest
		return
	}
	if resp.none || req.Function.NoAck() {
		a.lastReq = &lastRequest{seq: req.Control.Seq, data: in.frag}
		return
	}
	first := a.sendSolicited(req.Control.Seq, resp)
	if len(resp.plans) <= 1 && !resp.hasEvents() {
		a.lastReq = &lastRequest{seq: req.Control.Seq, data: in.frag, resp: first}
	} else {
		a.lastReq = nil
	}
}

func errorIIN(err error) app.IIN {
	switch {
	case isErr(err, app.ErrUnknownFunction):
		return app.IINNoFuncCodeSupport
	case isErr(err, app.ErrUnknownObject):
		return app.IINObjectUnknown
	default:
		return app.IINParameterError
	}
}

// response is the answer to a request before it is sent.
type response struct {
	plans []fragPlan
	iin   app.IIN
	// none is set for requests that are not answered.
	none bool
}

func (r *response) hasEvents() bool {
	for _, p := range r.plans {
		if len(p.events) > 0 {
			return true
		}
	}
	return false
}

// headers returns a single-fragment response with these headers.
func headers(hs ...app.Header) *response {
	return &response{plans: []fragPlan{{headers: hs}}}
}

// sendSolicited sends the first fragment of a response and returns its
// encoding. Every event of every fragment is selected at once; those of a
// fragment are removed when it is confirmed.
func (a *association) sendSolicited(seq uint8, r *response) []byte {
	if len(r.plans) == 0 {
		r.plans = []fragPlan{{}}
	}
	for _, p := range r.plans {
		a.events.mark(p.events)
	}
	p := &pendingResponse{seq: seq, plans: r.plans, iin: r.iin}
	data, con := a.sendFragment(p)
	if con {
		p.deadline = time.Now().Add(a.srv.opts.confirmTimeout)
		a.sol = p
	}
	return data
}

// sendFragment sends fragment p.next of a solicited response and reports
// whether it requested a confirmation.
func (a *association) sendFragment(p *pendingResponse) ([]byte, bool) {
	plan := p.plans[p.next]
	fin := p.next == len(p.plans)-1
	iin := a.iin() | p.iin
	// The response that reports a broadcast (IIN1.0) asks for
	// confirmation when the broadcast was to 0xFFFE (confirmation required)
	// or 0xFFFF (optional), and IIN1.0 is cleared when it comes; after one
	// to 0xFFFD (no confirmation) once it is sent (IEEE 1815-2012 Table 9-2,
	// the DNP3 IED certification procedure 3.1r1 Section 2 Note 7).
	if p.next == 0 && a.broadcast {
		if a.broadcastTo == link.BroadcastNoConfirm {
			a.broadcast = false
		} else {
			p.broadcast = true
		}
	}
	con := !fin || len(plan.events) > 0 || (p.next == 0 && p.broadcast)
	f := &app.Fragment{
		Control:  app.Control{FIR: p.next == 0, FIN: fin, CON: con, Seq: p.seq},
		Function: app.FuncResponse,
		IIN:      iin,
		Headers:  plan.headers,
	}
	return a.send(f), con
}

func (a *association) abandonSolicited() {
	if a.sol == nil {
		return
	}
	for _, p := range a.sol.plans[a.sol.next:] {
		a.events.release(p.events)
	}
	a.sol = nil
}

func (a *association) onConfirm(req *app.Fragment) {
	seq := req.Control.Seq
	if req.Control.UNS {
		u := a.unsol
		if u == nil || u.seq != seq {
			a.log.Debug("unexpected unsolicited confirmation ignored", "seq", seq)
			return
		}
		a.events.confirm(u.events)
		if u.null {
			a.nullDone = true
		}
		if a.srv.sm != nil {
			a.srv.sm.OnUnsolicited(a.remote(), len(u.events), nil)
		}
		a.unsol = nil
		a.unsolSeq = app.NextSeq(a.unsolSeq)
		a.holdStart = time.Time{}
		return
	}
	p := a.sol
	if p == nil || p.seq != seq {
		a.log.Debug("unexpected confirmation ignored", "seq", seq)
		return
	}
	a.events.confirm(p.plans[p.next].events)
	if p.next == 0 && p.broadcast {
		a.broadcast = false
	}
	p.next++
	if p.next == len(p.plans) {
		a.sol = nil
		return
	}
	p.seq = app.NextSeq(p.seq)
	if _, con := a.sendFragment(p); con {
		p.deadline = time.Now().Add(a.srv.opts.confirmTimeout)
	} else {
		a.sol = nil
	}
}

// maybeUnsolicited sends an unsolicited response when one is due.
func (a *association) maybeUnsolicited() {
	u := a.srv.opts.unsolicited
	if !u.Enabled || a.sess == nil || a.sol != nil || a.unsol != nil || !a.unsolPause.IsZero() {
		return
	}
	if !a.nullDone {
		f := &app.Fragment{
			Control:  app.Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: a.unsolSeq},
			Function: app.FuncUnsolicitedResponse,
			IIN:      a.iin(),
		}
		data := a.send(f)
		a.unsol = &pendingUnsol{null: true, seq: a.unsolSeq, data: data, deadline: time.Now().Add(a.srv.opts.confirmTimeout)}
		return
	}
	if a.unsolMask == 0 {
		return
	}
	n := a.events.pending(a.unsolMask)
	if n == 0 {
		a.holdStart = time.Time{}
		return
	}
	if u.HoldTime > 0 && (u.HoldCount == 0 || n < u.HoldCount) {
		if a.holdStart.IsZero() {
			a.holdStart = time.Now()
		}
		if time.Since(a.holdStart) < u.HoldTime {
			return
		}
	}
	var sels []*eventSelector
	for c := uint8(1); c <= 3; c++ {
		if a.unsolMask&(1<<c) != 0 {
			sels = append(sels, &eventSelector{classes: 1 << c})
		}
	}
	plans, _ := pack(a.eventItems(sels), a.srv.opts.maxTxFragment)
	plan := plans[0] // an unsolicited response is a single fragment
	if len(plan.events) == 0 {
		return
	}
	a.events.mark(plan.events)
	f := &app.Fragment{
		Control:  app.Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: a.unsolSeq},
		Function: app.FuncUnsolicitedResponse,
		IIN:      a.iin(),
		Headers:  plan.headers,
	}
	data := a.send(f)
	a.unsol = &pendingUnsol{seq: a.unsolSeq, data: data, events: plan.events, deadline: time.Now().Add(a.srv.opts.confirmTimeout)}
}

// send encodes and sends f on the current session and returns the
// encoding.
func (a *association) send(f *app.Fragment) []byte {
	data, err := f.Encode()
	if err != nil {
		// A bug: everything the outstation sends is built to encode.
		a.log.Error("response does not encode", "fragment", f.String(), "error", err)
		return nil
	}
	if a.log.DebugEnabled() {
		a.log.Debug("response sent", "fragment", f.String())
	}
	if m := a.srv.opts.metrics; m != nil {
		m.OnFragmentSent(a.remote(), f, len(data))
	}
	a.count(secauth.StatTotalMessagesSent)
	a.sendRaw(data)
	return data
}

func (a *association) sendRaw(data []byte) {
	if a.sess == nil || data == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.sess.Send(ctx, data); err != nil {
		a.log.Debug("fragment not sent", "error", err)
	}
}

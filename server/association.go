// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime/debug"
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
	// deferred is a READ that came while an unsolicited response waited
	// for its confirmation, answered once it is confirmed or times out.
	deferred *inbound
	sentOK   bool // the last fragment sent went out

	pendingAuth   *challenge
	lastChallenge []byte // the last g120v1 fragment sent
	keys          sessionKeys
	csq           uint32
	stats         [secauth.NumStatistics]uint32

	// broadcastTo is the address of the last broadcast: whether the
	// response reporting it asks for confirmation.
	broadcastTo link.Address

	files             map[uint32]*openFile
	pendingFileStatus []app.FileTransportStatus
}

type inbound struct {
	sess *channel.Session
	frag []byte
	dest link.Address
	at   time.Time
	// resumed: a deferred READ, now answered.
	resumed bool
}

// lastRequest is the last valid request accepted (IEEE 1815-2012 6.1): a
// repeat of it, the same sequence number and octets, is answered with the
// same response instead of being executed twice (Table 6-1 row 8).
type lastRequest struct {
	seq  uint8
	data []byte
	resp []byte // nil when the request had no response
	// replay: resp is the whole response, which a repeat gets again. A
	// READ is executed again instead (see handle).
	replay bool
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
	// req and reqSeq are the request the response answers, and last the
	// octets of the fragment sent last: a repeat of the request while the
	// confirmation is awaited gets that fragment again (Table 6-1 row 17).
	req    []byte
	reqSeq uint8
	last   []byte
}

// pendingUnsol is an unsolicited response waiting for its confirmation.
type pendingUnsol struct {
	null     bool
	seq      uint8
	frag     *app.Fragment
	sent     time.Time // when it last went out; zero if it never did
	peer     string    // where it went
	events   []*bufEvent
	attempts int
	deadline time.Time
	// broadcast: the response reported IIN1.0 of a broadcast that needs a
	// confirmation, which its confirmation clears (Table 4-13; 4.6.6
	// Rule 17).
	broadcast bool
	// disabled: DISABLE_UNSOLICITED came while the response waited for
	// its confirmation; at the confirm timeout the series ends instead of
	// being retried (4.6.6 Rule 15).
	disabled bool
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

// startupMask returns the classes enabled for unsolicited reporting at a
// start or restart: none by default, as IEEE 1815-2012 4.4.13 and 5.1.1.1.1
// Rule 3 require; Unsolicited.Classes otherwise (a non-standard option).
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
	a.deferred = nil
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
	// The clock is unsynchronized again: NEED_TIME, and g51v2 CTOs.
	a.srv.timeSync.reset()
	a.nullDone = false
	a.unsolMask = a.startupMask()
	a.events.mu.Lock()
	a.events.events = nil
	a.events.count = [numPointTypes]int{}
	a.events.overflow = [numPointTypes]bool{}
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
			a.safely(f)
		case <-a.wakeCh:
		case <-a.timer.C:
			a.safely(a.onTimer)
		}
	}
}

// safely runs f, recovering from a panic in it (a bug reached by a request,
// or in the application's Handler): the request in hand goes unanswered, as
// one lost on the line would, instead of the panic stopping every
// association of the process.
func (a *association) safely(f func()) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("panic while serving a request", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	f()
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
	if a.unsol != nil && a.sol == nil {
		consider(a.unsol.deadline)
	}
	consider(a.unsolPause)
	if u := a.srv.opts.unsolicited; !a.holdStart.IsZero() && u.HoldTime > 0 {
		consider(a.holdStart.Add(u.HoldTime))
	}
	consider(a.fileDeadline())
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
	if u := a.unsol; u != nil && a.sol == nil && !now.Before(u.deadline) {
		a.unsolicitedTimeout(u, now)
	}
	if !a.unsolPause.IsZero() && !now.Before(a.unsolPause) {
		a.unsolPause = time.Time{}
	}
	a.expireFiles(now)
}

// unsolicitedTimeout handles an unsolicited response whose confirm timeout
// has expired, once no solicited response is in progress: a repeat is never
// sent between the fragments of a response, or before its confirmation.
func (a *association) unsolicitedTimeout(u *pendingUnsol, now time.Time) {
	if a.deferred != nil {
		// A READ deferred while the response waited is answered now
		// (TB2015-002a). The events of a response with data go back to
		// the buffer, so that the READ reports them, and the response is
		// not repeated; a null response is repeated once the READ's
		// response is done.
		if !u.null {
			a.log.Debug("unsolicited response superseded by a deferred READ", "seq", u.seq, "events", len(u.events))
			a.events.release(u.events)
			a.unsol = nil
			a.unsolSeq = app.NextSeq(a.unsolSeq)
		}
		a.answerDeferred()
		if a.unsol == nil || a.sol != nil {
			return
		}
	}
	if u.disabled && !u.null {
		// DISABLE_UNSOLICITED came while the response waited: the series
		// ends without a retry and its events are reported later (IEEE
		// 1815-2012 4.6.6 Rule 15). Footnote 18 exempts the null response,
		// which is retried until confirmed (5.1.1.1.1 Rule 2).
		a.log.Debug("unsolicited response series ended by DISABLE_UNSOLICITED", "seq", u.seq, "events", len(u.events))
		a.endUnsolicited(u, 0)
		return
	}
	// The null response is retried until it is confirmed, whatever the
	// configured number of retries (5.1.1.1.1 Rule 2).
	if r := a.srv.opts.unsolicited.Retries; u.null || r < 0 || u.attempts < r {
		u.attempts++
		u.deadline = now.Add(a.srv.opts.confirmTimeout)
		if iin := a.iin(); iin != u.frag.IIN {
			// The indications changed meanwhile, e.g. IIN1.7 cleared by the
			// master: a regenerated retry, with the next sequence number,
			// since an identical retry must match the previous response
			// octet for octet (4.6.6 Rules 5 and 12).
			a.unsolSeq = app.NextSeq(a.unsolSeq)
			u.seq = a.unsolSeq
			f := *u.frag
			f.Control.Seq, f.IIN = u.seq, iin
			u.frag = &f
			u.broadcast = a.reportsBroadcast(iin)
			a.log.Debug("unsolicited response regenerated", "seq", u.seq, "attempt", u.attempts)
		} else {
			a.log.Debug("unsolicited response repeated", "seq", u.seq, "attempt", u.attempts)
		}
		a.sendUnsolicited(u)
		return
	}
	a.log.Info("unsolicited response given up", "seq", u.seq, "events", len(u.events))
	a.endUnsolicited(u, a.srv.opts.unsolicited.RetryDelay)
}

// endUnsolicited ends the unsolicited response series of u without its
// confirmation: its events are reported later, and a new series may start
// after pause (4.6.6 Rules 13 and 14).
func (a *association) endUnsolicited(u *pendingUnsol, pause time.Duration) {
	a.events.release(u.events)
	if a.srv.sm != nil {
		err := fmt.Errorf("%w: unsolicited response not confirmed", dnp3.ErrTimeout)
		a.srv.sm.OnUnsolicited(a.remote(), len(u.events), err)
	}
	a.unsol = nil
	a.unsolSeq = app.NextSeq(a.unsolSeq)
	if pause > 0 {
		a.unsolPause = time.Now().Add(pause)
	}
}

// reportsBroadcast is called for each response whose IIN is iin, before it
// is sent. It reports whether the response must ask for a confirmation
// because it reports a broadcast to 0xFFFE or 0xFFFF, whose IIN1.0 that
// confirmation clears; IIN1.0 of one to 0xFFFD is cleared once a response
// reported it (IEEE 1815-2012 Table 4-13, 4.6.6 Rule 17).
func (a *association) reportsBroadcast(iin app.IIN) bool {
	if !a.broadcast || iin&app.IINBroadcast == 0 {
		return false
	}
	if a.broadcastTo == link.BroadcastNoConfirm {
		a.broadcast = false
		return false
	}
	return true
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
	if a.needsTime() {
		i |= app.IINNeedTime
	}
	return i
}

// needsTime reports whether the outstation asks for time synchronization
// (IIN1.4): its clock has not been synchronized since the start, or not
// within the interval of WithTimeSync. The clock is the outstation's, so a
// synchronization by one master serves every association.
func (a *association) needsTime() bool {
	return a.srv.timeSync.needsTime(a.srv.opts.needTime)
}

// unsynchronizedAt reports whether the outstation's time counted as
// unsynchronized at t, as the CTO of relative-time events says (g51v2).
func (a *association) unsynchronizedAt(t time.Time) bool {
	return a.srv.timeSync.unsynchronizedAt(t, a.srv.opts.needTime)
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
	if m := a.srv.opts.metrics; m != nil && !in.resumed {
		m.OnFragmentReceived(a.remote(), req, len(in.frag))
	}
	if a.log.DebugEnabled() {
		a.log.Debug("request received", "fragment", req.String())
	}
	if req.Function.IsResponse() {
		a.log.Debug("response function sent to an outstation ignored", "function", req.Function.String())
		return
	}
	broadcast := in.dest.Broadcast()
	if req.Function == app.FuncConfirm {
		if broadcast {
			// A confirmation answers one response of this outstation; one
			// sent to a broadcast address is not a request to process
			// (IEEE 1815-2012 4.7, Table 4-16; Table 6-1 keys).
			a.log.Debug("broadcast confirmation ignored", "seq", req.Control.Seq)
			return
		}
		a.onConfirm(req)
		return
	}
	if !req.Control.FIR || !req.Control.FIN || req.Control.UNS {
		// A valid request has FIR and FIN set and UNS clear; any other is
		// discarded (6.1).
		a.log.Warn("invalid request fragment ignored", "control", req.Control.String())
		return
	}
	if req.Control.CON && !broadcast && !in.resumed && err == nil {
		// A request asking for confirmation, which masters no longer send
		// (4.3 Rule 11), is confirmed at once (4.3 Rule 12), with its
		// sequence number (4.3 Rule 18).
		a.send(&app.Fragment{Control: app.Control{FIR: true, FIN: true, Seq: req.Control.Seq}, Function: app.FuncConfirm})
	}
	if req.Function == app.FuncRead && !broadcast && !in.resumed && a.defers(in.at) {
		// A READ sent while an unsolicited response waits for its
		// confirmation is not answered until it is confirmed or its
		// confirm timeout expires (IEEE 1815-2012 4.6.6 rule 16,
		// TB2015-002a). One that came before it, e.g. the datagram that
		// started a UDP session, is answered. A newer READ replaces an
		// older one.
		a.log.Debug("READ deferred until the unsolicited response is confirmed", "seq", req.Control.Seq)
		in.resumed = true
		a.deferred = &in
		return
	}
	// A newer request supersedes a deferred READ, which is not answered.
	if !in.resumed && a.deferred != nil {
		a.log.Debug("deferred READ superseded", "seq", req.Control.Seq)
		a.deferred = nil
	}
	// The sequence number of a broadcast is ignored (4.3 Rule 19): it is
	// never a repeat, and it does not become the last request.
	if !broadcast && a.repeated(req, in) {
		return
	}
	if req.Function == app.FuncSelect && !broadcast && a.selection != nil && req.Control.Seq == a.selection.seq {
		// A SELECT with the sequence number of the selection in effect but
		// other octets than its own is discarded (4.4.4.3 Rule 4, Table
		// 4-9); the selection stays.
		a.log.Debug("SELECT with the sequence number of the selection discarded", "seq", req.Control.Seq)
		return
	}
	switch req.Function {
	case app.FuncSelect, app.FuncOperate:
		// control() handles the selection.
	case app.FuncAuthRequest, app.FuncAuthRequestNoAck:
		// The challenge of a critical SELECT or OPERATE comes between them;
		// a selection survives it.
	default:
		// A request that is neither SELECT nor OPERATE ends the selection
		// (Table 4-9, last row).
		a.selection = nil
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
		a.lastReq = &lastRequest{seq: req.Control.Seq, data: in.frag, replay: true}
		return
	}
	first := a.sendSolicited(req.Control.Seq, resp)
	if a.sol != nil {
		a.sol.req, a.sol.reqSeq = in.frag, req.Control.Seq
	}
	a.lastReq = &lastRequest{seq: req.Control.Seq, data: in.frag, resp: first,
		replay: len(resp.plans) <= 1 && !resp.hasEvents()}
}

// repeated answers a repeat of the last request, the same sequence number
// and octets, and reports whether req was one (IEEE 1815-2012 Table 6-1):
//   - while the response to it waits for its confirmation, the fragment
//     sent last is sent again and the confirm timer restarts (row 17);
//   - otherwise the response is sent again, not executing the request
//     again (row 8), except for a READ, which is executed again: its
//     response reports the data as they are now, and its events, if any,
//     were released or confirmed since.
func (a *association) repeated(req *app.Fragment, in inbound) bool {
	seq := req.Control.Seq
	if p := a.sol; p != nil && p.req != nil && p.reqSeq == seq && bytes.Equal(p.req, in.frag) {
		a.log.Debug("repeated request answered with the response awaiting confirmation", "seq", seq)
		p.deadline = time.Now().Add(a.srv.opts.confirmTimeout)
		a.sendRaw(p.last)
		return true
	}
	r := a.lastReq
	if r == nil || r.seq != seq || !bytes.Equal(r.data, in.frag) || req.Function == app.FuncRead || !r.replay {
		return false
	}
	a.log.Debug("repeated request answered with the previous response", "seq", r.seq)
	if r.resp != nil {
		a.sendRaw(r.resp)
	}
	return true
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
	// to 0xFFFD (no confirmation) once it is sent (IEEE 1815-2012 Table
	// 4-13, the DNP3 IED certification procedure 3.1r1 Section 2 Note 7).
	if p.next == 0 && a.reportsBroadcast(iin) {
		p.broadcast = true
	}
	con := !fin || len(plan.events) > 0 || (p.next == 0 && p.broadcast)
	f := &app.Fragment{
		Control:  app.Control{FIR: p.next == 0, FIN: fin, CON: con, Seq: p.seq},
		Function: app.FuncResponse,
		IIN:      iin,
		Headers:  plan.headers,
	}
	p.last = a.send(f)
	return p.last, con
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
		if u.broadcast {
			a.broadcast = false
		}
		if a.srv.sm != nil {
			a.srv.sm.OnUnsolicited(a.remote(), len(u.events), nil)
		}
		a.unsol = nil
		a.unsolSeq = app.NextSeq(a.unsolSeq)
		a.holdStart = time.Time{}
		a.answerDeferred()
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
		a.unsol = &pendingUnsol{null: true, seq: a.unsolSeq, frag: f, deadline: time.Now().Add(a.srv.opts.confirmTimeout),
			broadcast: a.reportsBroadcast(f.IIN)}
		a.sendUnsolicited(a.unsol)
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
			sels = append(sels, &eventSelector{classes: 1 << c, limit: noLimit})
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
	a.unsol = &pendingUnsol{seq: a.unsolSeq, frag: f, events: plan.events, deadline: time.Now().Add(a.srv.opts.confirmTimeout),
		broadcast: a.reportsBroadcast(f.IIN)}
	a.sendUnsolicited(a.unsol)
}

// answerDeferred answers the READ deferred while an unsolicited response
// waited for its confirmation.
func (a *association) answerDeferred() {
	if d := a.deferred; d != nil {
		a.deferred = nil
		a.handle(*d)
	}
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

// sendUnsolicited sends an unsolicited response and records when it went
// out and to which peer; the time stays zero when it had nowhere to go,
// e.g. over UDP before a master's first datagram.
func (a *association) sendUnsolicited(u *pendingUnsol) {
	peer := a.peer()
	// Before sending: the master may answer before the send returns, and
	// what it sends then did not come first.
	at := time.Now()
	if data := a.send(u.frag); data == nil || !a.sentOK || peer == nil {
		return
	}
	u.sent, u.peer = at, peer.String()
}

// peer is where the current session's fragments go.
func (a *association) peer() net.Addr {
	if a.sess == nil {
		return nil
	}
	return a.sess.Channel().Peer()
}

// defers reports whether a READ received at is held back by the
// unsolicited response waiting for its confirmation: it was sent before the
// READ came, to the master the READ came from. A READ from another master
// (over UDP, one that took over the socket), or that came first, as the
// datagram that started a UDP session, is answered.
func (a *association) defers(at time.Time) bool {
	u := a.unsol
	if u == nil || u.sent.IsZero() || !at.After(u.sent) {
		return false
	}
	p := a.peer()
	return p != nil && p.String() == u.peer
}

// sendRaw sends data on the current session; sentOK says whether it went
// out.
func (a *association) sendRaw(data []byte) {
	a.sentOK = false
	if a.sess == nil || data == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.sess.Send(ctx, data); err != nil {
		a.log.Debug("fragment not sent", "error", err)
		return
	}
	a.sentOK = true
}

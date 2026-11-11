// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

func isErr(err, target error) bool { return errors.Is(err, target) }

// dispatch executes a decoded request and returns its response.
func (a *association) dispatch(req *app.Fragment, in inbound, broadcast bool) *response {
	switch req.Function {
	case app.FuncRead:
		return a.read(req)
	case app.FuncWrite:
		return a.write(req)
	case app.FuncSelect, app.FuncOperate, app.FuncDirectOperate, app.FuncDirectOperateNoAck:
		return a.control(req, broadcast)
	case app.FuncImmediateFreeze, app.FuncImmediateFreezeNoAck, app.FuncFreezeClear, app.FuncFreezeClearNoAck,
		app.FuncFreezeAtTime, app.FuncFreezeAtTimeNoAck:
		return a.freeze(req)
	case app.FuncColdRestart, app.FuncWarmRestart:
		return a.restartRequest(req)
	case app.FuncDelayMeasure:
		// g52v2 holds at most 65535 ms (A.25.2, p. 659); a longer
		// processing time is reported as that, not left unanswered.
		d := min(time.Since(in.at), 65535*time.Millisecond)
		return headers(app.Counted(app.G52V2, app.TimeDelay{Delay: d.Truncate(time.Millisecond)}))
	case app.FuncRecordCurrentTime:
		a.recorded = in.at
		return &response{}
	case app.FuncEnableUnsolicited, app.FuncDisableUnsolicited:
		return a.unsolicitedControl(req)
	case app.FuncAssignClass:
		return a.assignClass(req)
	case app.FuncInitializeData, app.FuncInitializeApplication, app.FuncStartApplication,
		app.FuncStopApplication, app.FuncSaveConfiguration, app.FuncActivateConfig:
		if h, ok := a.srv.opts.handler.(ActivateConfigHandler); ok && req.Function == app.FuncActivateConfig {
			return a.activateConfig(h, req)
		}
		h, ok := a.srv.opts.handler.(ApplicationHandler)
		if !ok {
			return &response{iin: app.IINNoFuncCodeSupport}
		}
		ctx, cancel := a.srv.handlerContext()
		defer cancel()
		// IIN2.4 (ALREADY_EXECUTING, 4.5.13) is the handler's to report,
		// as are the request errors.
		r := &response{iin: h.Application(ctx, req.Function, req.Headers) & (app.IINRequestErrors | app.IINAlreadyExecuting)}
		if r.iin&app.IINRequestErrors == 0 {
			switch req.Function {
			case app.FuncSaveConfiguration:
				// The answer is a time delay (4.4.12, p. 60): the handler
				// has stored the configuration when it returns.
				r.plans = []fragPlan{{headers: []app.Header{app.Counted(app.G52V2, app.TimeDelay{})}}}
			case app.FuncActivateConfig:
				// The answer is a status of requested operation (4.4.20,
				// p. 78): success for every object of the request.
				r = a.activated(req, r.iin)
			default:
			}
		}
		return r
	case app.FuncOpenFile, app.FuncCloseFile, app.FuncDeleteFile, app.FuncGetFileInfo,
		app.FuncAuthenticateFile, app.FuncAbortFile:
		return a.file(req)
	default:
		return &response{iin: app.IINNoFuncCodeSupport}
	}
}

// activateConfig answers ACTIVATE_CONFIG with the handler's status of
// requested operation (g91v1).
func (a *association) activateConfig(h ActivateConfigHandler, req *app.Fragment) *response {
	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	st, iin := h.ActivateConfig(ctx, req.Headers)
	if iin &= app.IINRequestErrors; iin != 0 {
		return &response{iin: iin}
	}
	return a.activationStatus(st)
}

// activated answers an ACTIVATE_CONFIG that a plain ApplicationHandler
// accepted: a status of success for each object of the request, at most
// 255, and no delay.
func (a *association) activated(req *app.Fragment, iin app.IIN) *response {
	var st app.ActivateConfigStatus
	for _, h := range req.Headers {
		for range h.Objects {
			if len(st.Results) < 255 {
				st.Results = append(st.Results, app.ActivateConfigResult{})
			}
		}
	}
	r := a.activationStatus(st)
	r.iin |= iin
	return r
}

// activationStatus answers ACTIVATE_CONFIG with st as its g91v1.
func (a *association) activationStatus(st app.ActivateConfigStatus) *response {
	raw, err := st.Raw()
	if err != nil {
		a.log.Warn("activation status does not encode", "error", err)
		return &response{iin: app.IINParameterError}
	}
	// Response header (4), object header with a one-octet count (4).
	if n := 8 + len(raw.Data); n > a.srv.opts.maxTxFragment {
		a.log.Warn("activation status too large for a fragment", "size", n)
		return &response{iin: app.IINParameterError}
	}
	return headers(app.Counted(app.G91V1, raw))
}

func (a *association) read(req *app.Fragment) *response {
	db := a.srv.db
	p := func() readPlan {
		db.mu.RLock()
		defer db.mu.RUnlock()
		return a.planRead(req)
	}()
	plans, dropped := pack(p.items, a.srv.opts.maxTxFragment)
	if dropped > 0 {
		a.log.Warn("objects too large for a fragment left out", "count", dropped)
	}
	return &response{plans: plans, iin: p.iin}
}

func (a *association) write(req *app.Fragment) *response {
	r := &response{}
	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	wh, _ := a.srv.opts.handler.(WriteHandler)
	for _, h := range req.Headers {
		if h.Qualifier == app.QualAll || len(h.Objects) == 0 {
			// A header that carries no values writes nothing: a
			// qualifier the outstation does not support for WRITE
			// (4.5.11, p. 85), unless the object is unknown.
			if h.GV.Known() {
				r.iin |= app.IINParameterError
			} else {
				r.iin |= app.IINObjectUnknown
			}
			continue
		}
		switch h.GV {
		case app.G50V1:
			at, ok := oneObject[app.AbsoluteTime](h)
			if !ok {
				r.iin |= app.IINParameterError
				continue
			}
			t := at.Time.Time()
			a.srv.clock.set(t, time.Now())
			a.synchronized(ctx, t)
		case app.G50V3:
			// LAN procedure: the master's time at the moment the outstation
			// recorded with RECORD_CURRENT_TIME.
			at, ok := oneObject[app.AbsoluteTime](h)
			if !ok || a.recorded.IsZero() {
				r.iin |= app.IINParameterError
				continue
			}
			t := at.Time.Time()
			a.srv.clock.set(t, a.recorded)
			a.recorded = time.Time{}
			a.synchronized(ctx, a.srv.clock.time())
		case app.G80V1:
			// A master clears IIN1.7 (5.1.1.1.1 Rule 1) and, when the
			// outstation asks for time, IIN1.4 (4.5.5, p. 83) by writing
			// 0; no other bit is written.
			for _, o := range h.Objects {
				b, ok := o.Value.(app.Binary)
				switch {
				case !ok || b.Value:
					r.iin |= app.IINParameterError
				case o.Index == app.IINBit(app.IINDeviceRestart):
					a.restartIIN = false
				case o.Index == app.IINBit(app.IINNeedTime) && a.srv.opts.needTime > 0:
					a.srv.timeSync.clearNeedTime(time.Now())
				default:
					r.iin |= app.IINParameterError
				}
			}
		case app.G34V1, app.G34V2, app.G34V3:
			db := a.srv.db
			db.mu.Lock()
			for _, o := range h.Objects {
				p, ok := db.points[AnalogInput][o.Index]
				if !ok {
					r.iin |= app.IINParameterError
					continue
				}
				d, isDeadband := o.Value.(app.AnalogDeadband)
				if !isDeadband || !validDeadband(d.Value) {
					r.iin |= app.IINParameterError
					continue
				}
				p.cfg.Deadband = d.Value
			}
			db.mu.Unlock()
		default:
			switch h.GV.Group() {
			case 0:
				r.iin |= a.writeAttributes(ctx, h)
			case 110:
				for _, o := range h.Objects {
					s, ok := o.Value.(app.OctetString)
					if !ok {
						r.iin |= app.IINParameterError
						continue
					}
					if err := a.srv.db.Update(OctetString, o.Index, s, EventOnChange); err != nil {
						r.iin |= app.IINParameterError
						continue
					}
					if wh != nil {
						if err := wh.WriteOctetString(ctx, o.Index, s.Data); err != nil {
							r.iin |= app.IINParameterError
						}
					}
				}
			case 70:
				r.iin |= a.writeFile(h)
			default:
				r.iin |= app.IINObjectUnknown
			}
		}
	}
	if st := a.pendingFileStatus; len(st) > 0 {
		a.pendingFileStatus = nil
		vals := make([]app.Value, len(st))
		for i, s := range st {
			vals[i] = s
		}
		r.plans = []fragPlan{{headers: []app.Header{app.FreeFormat(app.G70V6, vals...)}}}
	}
	return r
}

func (a *association) synchronized(ctx context.Context, t time.Time) {
	a.srv.timeSync.synchronized(time.Now())
	if th, ok := a.srv.opts.handler.(TimeHandler); ok {
		th.SetTime(ctx, t)
	}
	a.log.Info("time synchronized", "time", t.UTC().Format(time.RFC3339Nano))
}

// freeze copies counters into frozen counters, and analog inputs into
// frozen analog inputs, for the points the headers name: at once, or on
// the schedules of FREEZE_AT_TIME (freezeAtTime).
func (a *association) freeze(req *app.Fragment) *response {
	if req.Function == app.FuncFreezeAtTime || req.Function == app.FuncFreezeAtTimeNoAck {
		return &response{iin: a.srv.freezeAtTime(req.Headers)}
	}
	clearAfter := req.Function == app.FuncFreezeClear || req.Function == app.FuncFreezeClearNoAck
	if iin := freezeHeadersValid(req.Headers, clearAfter); iin != 0 {
		return &response{iin: iin}
	}
	a.srv.freezeNow(req.Headers, clearAfter)
	return &response{}
}

// freezeHeadersValid checks the headers of a freeze: counters (group 20)
// or analog inputs (group 30), with a qualifier that names points. A
// freeze-and-clear applies to counters: the guideline of IEEE 1815-2012
// lists function codes 9 and 10 for g20v0 (Table 12-10, p. 355), not for
// g30v0 (Table 12-14, p. 356), so an analog input header is an object the
// function is not supported for (IIN2.1, Table 4-14, p. 85).
func freezeHeadersValid(hs []app.Header, clear bool) app.IIN {
	var iin app.IIN
	for i := range hs {
		switch g := hs[i].GV.Group(); {
		case g == 20, g == 30 && !clear:
			if _, ok := selectorOf(&hs[i]); !ok {
				iin |= app.IINParameterError
			}
		default:
			iin |= app.IINObjectUnknown
		}
	}
	return iin
}

// freezeNow copies the counters or analog inputs the headers name into
// their frozen points, clearing the counters with clear. Every freeze of
// a frozen point with an event class produces an event, also when its
// value did not change (IEEE 1815-2012 11.9.1.2, p. 333; 11.9.5.2,
// p. 341). The caller has checked the headers (freezeHeadersValid).
func (s *Server) freezeNow(hs []app.Header, clear bool) {
	now := s.clock.now()
	db := s.db
	// The batch updates points of the kinds it reads: it cannot fail.
	_ = db.Batch(func(b *Batch) error {
		for i := range hs {
			h := &hs[i]
			src, dst := Counter, FrozenCounter
			if h.GV.Group() == 30 {
				src, dst = AnalogInput, FrozenAnalogInput
			}
			sel, _ := selectorOf(h)
			for _, idx := range db.indexes(src) {
				if !sel.has(idx) {
					continue
				}
				p := db.points[src][idx]
				if _, ok := db.points[dst][idx]; ok {
					_ = b.Update(dst, idx, withTime(p.value, now), EventForce)
				}
				if clear && src == Counter {
					c := p.value.(app.Counter)
					c.Value, c.Time = 0, now
					_ = b.Update(Counter, idx, c, EventOnChange)
				}
			}
		}
		return nil
	})
}

// MaxScheduledFreezes is how many FREEZE_AT_TIME schedules the outstation
// keeps at once; a request for more is refused. A schedule belongs to the
// Server: a periodic one keeps its place until a new FREEZE_AT_TIME for
// its points or Close, whatever happens to the master's connection.
const MaxScheduledFreezes = 16

// scheduledFreeze is a FREEZE_AT_TIME schedule waiting for its time.
type scheduledFreeze struct {
	timer *time.Timer
}

// freezeSchedule is one schedule of a FREEZE_AT_TIME request: a time and
// interval (g50v2) and the headers of the points it freezes.
type freezeSchedule struct {
	at     app.AbsoluteTime
	points []app.Header
}

// freezeAtTime handles FREEZE_AT_TIME (IEEE 1815-2012 4.4.8, pp. 56-57).
// The request holds one or more schedules, each a g50v2 time and interval
// followed by the headers of its points. Table 4-11 reads them as:
//   - time 0, interval 0: freeze once at once;
//   - a time, interval 0: freeze once at that time;
//   - time 0, an interval: every interval from the beginning of the
//     current hour;
//   - a time and an interval: every interval from that time;
//   - the time all ones: cancel (Table 4-11 NOTE).
//
// A periodic schedule continues until a new FREEZE_AT_TIME is received;
// go-dnp3 reads that per point set: a new schedule for the same point
// headers replaces the old one. Every schedule is checked before any is
// applied.
func (s *Server) freezeAtTime(hs []app.Header) app.IIN {
	var scheds []freezeSchedule
	for _, h := range hs {
		if h.GV == app.G50V2 {
			at, ok := oneObject[app.AbsoluteTime](h)
			if !ok {
				return app.IINParameterError
			}
			scheds = append(scheds, freezeSchedule{at: at})
			continue
		}
		if len(scheds) == 0 {
			return app.IINParameterError // the request does not start with a g50v2
		}
		scheds[len(scheds)-1].points = append(scheds[len(scheds)-1].points, h)
	}
	if len(scheds) == 0 {
		return app.IINParameterError
	}
	now := s.clock.time()
	added := map[string]bool{}
	for _, sc := range scheds {
		if len(sc.points) == 0 {
			return app.IINParameterError
		}
		if iin := freezeHeadersValid(sc.points, false); iin != 0 {
			return iin
		}
		switch {
		case sc.at.Time == app.MaxTimestamp, sc.at.Time == 0 && sc.at.Interval == 0:
		case sc.at.Interval == 0 && !sc.at.Time.Time().After(now):
			return app.IINParameterError // a time that has passed cannot be met
		default:
			added[freezeKey(sc.points)] = true
		}
	}
	s.mu.Lock()
	n := len(s.freezes)
	for key := range added {
		if s.freezes[key] == nil {
			n++
		}
	}
	s.mu.Unlock()
	if n > MaxScheduledFreezes {
		return app.IINParameterError
	}
	for _, sc := range scheds {
		key := freezeKey(sc.points)
		s.cancelFreeze(key)
		interval := time.Duration(sc.at.Interval) * time.Millisecond
		switch {
		case sc.at.Time == app.MaxTimestamp:
			// Cancelled.
		case sc.at.Time == 0 && interval == 0:
			s.freezeNow(sc.points, false)
		case sc.at.Time == 0:
			s.scheduleFreeze(key, now.Truncate(time.Hour), interval, sc.points)
		default:
			s.scheduleFreeze(key, sc.at.Time.Time(), interval, sc.points)
		}
	}
	return 0
}

// freezeKey identifies the points of a schedule by their headers.
func freezeKey(hs []app.Header) string {
	var b strings.Builder
	for _, h := range hs {
		fmt.Fprintf(&b, "%d/%d/%d-%d", uint16(h.GV), uint8(h.Qualifier), h.Start, h.Stop)
		for _, o := range h.Objects {
			fmt.Fprintf(&b, ",%d", o.Index)
		}
		b.WriteByte(';')
	}
	return b.String()
}

// cancelFreeze ends the schedule of key, if there is one.
func (s *Server) cancelFreeze(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.freezes[key]; f != nil {
		f.timer.Stop()
		delete(s.freezes, key)
	}
}

// scheduleFreeze freezes the points of hs at when and, with an interval,
// every interval after it, until a new schedule for key or Close.
func (s *Server) scheduleFreeze(key string, when time.Time, interval time.Duration, hs []app.Header) {
	hs = append([]app.Header(nil), hs...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	now := s.clock.time()
	if interval > 0 && !when.After(now) {
		// The next occurrence after now.
		when = when.Add((now.Sub(when)/interval + 1) * interval)
	}
	f := &scheduledFreeze{}
	current := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.freezes[key] == f
	}
	f.timer = time.AfterFunc(when.Sub(now), func() {
		if !current() {
			return // replaced, cancelled or closed
		}
		s.freezeNow(hs, false)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.freezes[key] != f {
			return
		}
		if interval > 0 {
			f.timer.Reset(interval)
			return
		}
		delete(s.freezes, key)
	})
	s.freezes[key] = f
}

func (a *association) restartRequest(req *app.Fragment) *response {
	h, ok := a.srv.opts.handler.(RestartHandler)
	if !ok {
		return &response{iin: app.IINNoFuncCodeSupport}
	}
	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	d, err := h.Restart(ctx, req.Function == app.FuncColdRestart)
	if err != nil {
		return &response{iin: app.IINNoFuncCodeSupport}
	}
	if d < 65536*time.Millisecond {
		return headers(app.Counted(app.G52V2, app.TimeDelay{Delay: d.Truncate(time.Millisecond)}))
	}
	return headers(app.Counted(app.G52V1, app.TimeDelay{Delay: min(d.Truncate(time.Second), 65535*time.Second)}))
}

func (a *association) unsolicitedControl(req *app.Fragment) *response {
	if !a.srv.opts.unsolicited.Enabled {
		return &response{iin: app.IINNoFuncCodeSupport}
	}
	var mask uint8
	for _, h := range req.Headers {
		g, v := h.GV.Group(), h.GV.Variation()
		if g != 60 || v < 2 || v > 4 {
			return &response{iin: app.IINParameterError}
		}
		mask |= 1 << (v - 1)
	}
	if req.Function == app.FuncEnableUnsolicited {
		a.unsolMask |= mask
	} else {
		a.unsolMask &^= mask
		if a.unsol != nil && !a.unsol.null {
			// Whatever its headers, the series in progress ends at its
			// confirm timeout, without a retry (4.6.6 Rule 15, pp. 92-93).
			a.unsol.disabled = true
		}
	}
	return &response{}
}

// assignClass handles ASSIGN_CLASS: each class header (g60) is followed
// by the headers of the points that get that class.
func (a *association) assignClass(req *app.Fragment) *response {
	r := &response{}
	// Authentication objects (g120) and security statistics (g121) are
	// never assigned to class 0: such a request gets a null response with
	// IIN2.0 (Table 4-12 note a, p. 63).
	toClass0 := false
	for _, h := range req.Headers {
		switch g := h.GV.Group(); {
		case g == 60:
			toClass0 = h.GV == app.G60V1
		case (g == 120 || g == 121) && toClass0:
			return &response{iin: app.IINNoFuncCodeSupport}
		}
	}
	db := a.srv.db
	db.mu.Lock()
	defer db.mu.Unlock()
	class, have := Class(0), false
	for i := range req.Headers {
		h := &req.Headers[i]
		if h.GV.Group() == 60 {
			if h.GV.Variation() < 1 || h.GV.Variation() > 4 {
				r.iin |= app.IINParameterError
				return r
			}
			class, have = Class(h.GV.Variation()-1), true
			continue
		}
		t, isEvent, ok := pointTypeOfGroup(h.GV.Group())
		switch h.GV.Group() {
		case 12:
			t, isEvent, ok = BinaryOutputCommand, false, true
		case 41:
			t, isEvent, ok = AnalogOutputCommand, false, true
		default:
		}
		switch {
		case !ok:
			// An object the outstation does not know (Table 4-14, p. 85).
			r.iin |= app.IINObjectUnknown
			continue
		case isEvent || !have || t == TimeAndInterval || t == SecurityStatistic:
			// The class of security statistic events is the one of
			// SecureAuth.StatisticsClass.
			r.iin |= app.IINParameterError
			continue
		}
		switch q := h.Qualifier; {
		case q == app.QualAll:
			db.assignClass(t, true, 0, 0, class)
		case q.IsRange():
			if !db.assignClass(t, false, h.Start, h.Stop, class) {
				r.iin |= app.IINParameterError
			}
		case q.IsIndexed():
			for _, o := range h.Objects {
				if !db.assignClass(t, false, o.Index, o.Index, class) {
					r.iin |= app.IINParameterError
				}
			}
		default:
			r.iin |= app.IINParameterError
		}
	}
	return r
}

// readOther serves READ headers of objects that are not points: device
// attributes and, when configured, file transfer. It reports whether it
// handled the header.
func (s *Server) readOther(a *association, h *app.Header, p *readPlan) bool {
	switch {
	case h.GV.Group() == 0:
		p.items = append(p.items, s.attributeItems(h, p)...)
		return true
	case h.GV == app.G70V5 && s.opts.files != nil:
		a.readFile(h, p)
		return true
	}
	return false
}

// attributeSet is one set of device attributes. legacy marks set 0 of
// WithAttributes: writable when the handler is a WriteHandler.
type attributeSet struct {
	mu       sync.Mutex
	attrs    map[uint8]app.Attribute
	writable map[uint8]bool
	legacy   bool
}

func (as *attributeSet) isWritable(h Handler, v uint8) bool {
	if as.legacy {
		_, ok := h.(WriteHandler)
		return ok
	}
	return as.writable[v]
}

// attributeSets returns the sets a READ or WRITE of group 0 names: the
// range of the header, set 0 for any other qualifier. An index-prefixed
// header names its sets by its indexes instead (attributeIndexes).
func attributeSets(h *app.Header) (start, stop uint32) {
	if h.Qualifier.IsRange() {
		return h.Start, h.Stop
	}
	return 0, 0
}

func (s *Server) attributeItems(h *app.Header, p *readPlan) []item {
	if h.GV.Variation() == 0 || len(s.opts.attributes) == 0 {
		// Group 0 has no variation 0 (IEEE 1815-2012 Annex A, device
		// attributes are variations 1..255): an unknown object, whatever
		// sets the outstation has. The DNP3 IED certification procedure
		// (8.6.3.2) expects IIN2.1; recorded in
		// conformance-runner_opendnp3-3_8-6-3-2.pcap. An outstation
		// without device attributes supports no group 0 object at all
		// (Table 4-14, p. 85).
		p.iin |= app.IINObjectUnknown
		return nil
	}
	var sets []uint16
	if h.Qualifier.IsIndexed() {
		// The set is the index of each object (5.5.6, pp. 151-152).
		for _, o := range h.Objects {
			if o.Index > 0xFFFF || s.opts.attributes[uint16(o.Index)] == nil {
				p.iin |= app.IINParameterError
				continue
			}
			sets = append(sets, uint16(o.Index))
		}
	} else {
		start, stop := attributeSets(h)
		// The configured sets in the range, in order: a range is not
		// walked set by set, it may span four billion of them.
		for set := range s.opts.attributes {
			if uint32(set) >= start && uint32(set) <= stop {
				sets = append(sets, set)
			}
		}
		slices.Sort(sets)
		if uint64(stop)-uint64(start)+1 != uint64(len(sets)) {
			p.iin |= app.IINParameterError // the range names sets that do not exist
		}
	}
	var out []item
	for _, set := range sets {
		out = append(out, s.attributeSetItems(uint32(set), s.opts.attributes[set], h.GV.Variation(), p)...)
	}
	return out
}

func (s *Server) attributeSetItems(set uint32, as *attributeSet, v uint8, p *readPlan) []item {
	as.mu.Lock()
	defer as.mu.Unlock()
	one := func(v uint8, at app.Attribute) item {
		return item{h: app.Ranged(app.GV(0, v), set, at)}
	}
	switch v {
	case app.AttrAllAttributes:
		var out []item
		for _, v := range sortedVariations(as.attrs) {
			out = append(out, one(v, as.attrs[v]))
		}
		return out
	case app.AttrListOfVariations:
		var entries []app.AttributeListEntry
		for _, v := range sortedVariations(as.attrs) {
			entries = append(entries, app.AttributeListEntry{Variation: v, Writable: as.isWritable(s.opts.handler, v)})
		}
		// The list of variations has the set as the index of qualifier
		// 0x17 (5.5.6.2 b, p. 151; EX 5-11).
		return []item{{h: app.Indexed(app.GV(0, v), app.Object{Index: set, Value: app.ListAttribute(entries...)})}}
	default:
		at, ok := as.attrs[v]
		if !ok {
			p.iin |= app.IINObjectUnknown
			return nil
		}
		return []item{one(v, at)}
	}
}

// writeAttributes handles a WRITE of group 0 and returns its IIN bits.
func (a *association) writeAttributes(ctx context.Context, h app.Header) app.IIN {
	var iin app.IIN
	start, _ := attributeSets(&h)
	if h.Qualifier.IsIndexed() && len(h.Objects) > 0 {
		start = h.Objects[0].Index
	}
	if start > 0xFFFF {
		return app.IINParameterError
	}
	as := a.srv.opts.attributes[uint16(start)]
	if as == nil {
		return app.IINParameterError
	}
	v := h.GV.Variation()
	for _, o := range h.Objects {
		val, isAttribute := o.Value.(app.Attribute)
		if !isAttribute {
			iin |= app.IINParameterError
			continue
		}
		if as.legacy {
			wh, ok := a.srv.opts.handler.(WriteHandler)
			if !ok || wh.WriteAttribute(ctx, v, val) != nil {
				iin |= app.IINParameterError
				continue
			}
			// An accepted write changes the attribute (5.5.8, p. 153).
			as.mu.Lock()
			if _, exists := as.attrs[v]; exists {
				as.attrs[v] = val
			}
			as.mu.Unlock()
			continue
		}
		as.mu.Lock()
		cur, exists := as.attrs[v]
		ok := exists && as.writable[v] && cur.Type == val.Type
		as.mu.Unlock()
		if ok {
			if sw, has := a.srv.opts.handler.(AttributeSetWriteHandler); has {
				ok = sw.WriteAttributeSet(ctx, uint16(start), v, val) == nil
			}
		}
		if !ok {
			iin |= app.IINParameterError
			continue
		}
		as.mu.Lock()
		as.attrs[v] = val
		as.mu.Unlock()
	}
	return iin
}

func sortedVariations(m map[uint8]app.Attribute) []uint8 {
	out := make([]uint8, 0, len(m))
	for v := 255; v >= 0; v-- {
		if _, ok := m[uint8(v)]; ok {
			out = append(out, uint8(v))
		}
	}
	return out
}

// oneObject returns the value of the only object of h, when it has exactly
// one and the value is a T: an object of a qualifier that carries indices
// only has none.
func oneObject[T app.Value](h app.Header) (T, bool) {
	var zero T
	if len(h.Objects) != 1 {
		return zero, false
	}
	v, ok := h.Objects[0].Value.(T)
	return v, ok
}

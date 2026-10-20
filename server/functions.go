// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
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
		d := time.Since(in.at)
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
		h, ok := a.srv.opts.handler.(ApplicationHandler)
		if !ok {
			return &response{iin: app.IINNoFuncCodeSupport}
		}
		ctx, cancel := a.srv.handlerContext()
		defer cancel()
		return &response{iin: h.Application(ctx, req.Function, req.Headers) & app.IINRequestErrors}
	case app.FuncOpenFile, app.FuncCloseFile, app.FuncDeleteFile, app.FuncGetFileInfo,
		app.FuncAuthenticateFile, app.FuncAbortFile:
		return a.file(req)
	default:
		return &response{iin: app.IINNoFuncCodeSupport}
	}
}

func (a *association) read(req *app.Fragment) *response {
	db := a.srv.db
	db.mu.RLock()
	p := a.planRead(req)
	db.mu.RUnlock()
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
		switch h.GV {
		case app.G50V1:
			if len(h.Objects) != 1 {
				r.iin |= app.IINParameterError
				continue
			}
			t := h.Objects[0].Value.(app.AbsoluteTime).Time.Time()
			a.srv.clock.set(t, time.Now())
			a.synchronized(ctx, t)
		case app.G50V3:
			// LAN procedure: the master's time at the moment the outstation
			// recorded with RECORD_CURRENT_TIME.
			if len(h.Objects) != 1 || a.recorded.IsZero() {
				r.iin |= app.IINParameterError
				continue
			}
			t := h.Objects[0].Value.(app.AbsoluteTime).Time.Time()
			a.srv.clock.set(t, a.recorded)
			a.recorded = time.Time{}
			a.synchronized(ctx, a.srv.clock.time())
		case app.G80V1:
			for _, o := range h.Objects {
				if o.Index != app.IINBit(app.IINDeviceRestart) || o.Value.(app.Binary).Value {
					r.iin |= app.IINParameterError
					continue
				}
				a.restartIIN = false
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
				p.cfg.Deadband = o.Value.(app.AnalogDeadband).Value
			}
			db.mu.Unlock()
		default:
			switch h.GV.Group() {
			case 0:
				r.iin |= a.writeAttributes(ctx, h)
			case 110:
				for _, o := range h.Objects {
					s := o.Value.(app.OctetString)
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
	a.lastSync = time.Now()
	if th, ok := a.srv.opts.handler.(TimeHandler); ok {
		th.SetTime(ctx, t)
	}
	a.log.Info("time synchronized", "time", t.UTC().Format(time.RFC3339Nano))
}

// freeze copies counters into frozen counters, and analog inputs into
// frozen analog inputs, for the points the headers name. FREEZE_AT_TIME
// is executed at once when its time has passed and its interval is zero;
// a scheduled freeze is not supported.
func (a *association) freeze(req *app.Fragment) *response {
	clearAfter := req.Function == app.FuncFreezeClear || req.Function == app.FuncFreezeClearNoAck
	hs := req.Headers
	if req.Function == app.FuncFreezeAtTime || req.Function == app.FuncFreezeAtTimeNoAck {
		if len(hs) == 0 || hs[0].GV != app.G50V2 || len(hs[0].Objects) != 1 {
			return &response{iin: app.IINParameterError}
		}
		at := hs[0].Objects[0].Value.(app.AbsoluteTime)
		hs = hs[1:]
		if iin := freezeHeadersValid(hs); iin != 0 {
			return &response{iin: iin}
		}
		// IEEE 1815-2012 A.23.2: time 0 and interval 0 freeze at once;
		// otherwise at the time and every interval after it. A time that
		// has passed, without an interval, cannot be met.
		interval := time.Duration(at.Interval) * time.Millisecond
		if at.Time != 0 || interval != 0 {
			when := at.Time.Time()
			if at.Time == 0 {
				when = a.srv.clock.time()
			}
			if interval == 0 && !when.After(a.srv.clock.time()) {
				return &response{iin: app.IINParameterError}
			}
			if !a.srv.scheduleFreeze(when, interval, hs) {
				return &response{iin: app.IINParameterError}
			}
			return &response{}
		}
	}
	return &response{iin: a.srv.freezeNow(hs, clearAfter)}
}

// freezeHeadersValid checks the headers of a freeze: counters (group 20)
// or analog inputs (group 30), with a qualifier that names points.
func freezeHeadersValid(hs []app.Header) app.IIN {
	var iin app.IIN
	for i := range hs {
		switch hs[i].GV.Group() {
		case 20, 30:
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
// their frozen points, clearing the counters with clear.
func (s *Server) freezeNow(hs []app.Header, clear bool) app.IIN {
	iin := freezeHeadersValid(hs)
	now := s.clock.now()
	db := s.db
	err := db.Batch(func(b *Batch) error {
		for i := range hs {
			h := &hs[i]
			src, dst := Counter, FrozenCounter
			if h.GV.Group() == 30 {
				src, dst = AnalogInput, FrozenAnalogInput
			}
			sel, ok := selectorOf(h)
			if !ok || (h.GV.Group() != 20 && h.GV.Group() != 30) {
				continue
			}
			for _, idx := range db.indexes(src) {
				if !sel.has(idx) {
					continue
				}
				p := db.points[src][idx]
				if _, ok := db.points[dst][idx]; ok {
					// An unchanged frozen value produces no event.
					_ = b.Update(dst, idx, withTime(p.value, now), EventOnChange)
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
	if err != nil {
		iin |= app.IINParameterError
	}
	return iin
}

// MaxScheduledFreezes is how many FREEZE_AT_TIME requests the outstation
// keeps waiting at once; a further one is refused.
const MaxScheduledFreezes = 16

// scheduleFreeze freezes the points of hs at when and, with an interval,
// every interval after it, until Close. It reports false when there are
// MaxScheduledFreezes already.
func (s *Server) scheduleFreeze(when time.Time, interval time.Duration, hs []app.Header) bool {
	hs = append([]app.Header(nil), hs...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.freezes) >= MaxScheduledFreezes {
		return false
	}
	now := s.clock.time()
	if interval > 0 && !when.After(now) {
		// The next occurrence after now.
		when = when.Add((now.Sub(when)/interval + 1) * interval)
	}
	var t *time.Timer
	t = time.AfterFunc(when.Sub(now), func() {
		_ = s.freezeNow(hs, false)
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.freezes[t]; !ok {
			return // stopped by Close
		}
		if interval > 0 {
			t.Reset(interval)
			return
		}
		delete(s.freezes, t)
	})
	s.freezes[t] = struct{}{}
	return true
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
	}
	return &response{}
}

// assignClass handles ASSIGN_CLASS: each class header (g60) is followed
// by the headers of the points that get that class.
func (a *association) assignClass(req *app.Fragment) *response {
	r := &response{}
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
		if !ok || isEvent || !have || t == TimeAndInterval || t == SecurityStatistic {
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
// range of the header, set 0 for any other qualifier.
func attributeSets(h *app.Header) (start, stop uint32) {
	if h.Qualifier.IsRange() {
		return h.Start, h.Stop
	}
	return 0, 0
}

func (s *Server) attributeItems(h *app.Header, p *readPlan) []item {
	start, stop := attributeSets(h)
	var out []item
	for set := uint64(start); set <= uint64(stop); set++ {
		as := s.opts.attributes[uint16(set)]
		if set > 0xFFFF || as == nil {
			p.iin |= app.IINParameterError
			continue
		}
		out = append(out, s.attributeSetItems(uint32(set), as, h.GV.Variation(), p)...)
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
		return []item{one(v, app.ListAttribute(entries...))}
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
	as := a.srv.opts.attributes[uint16(start)]
	if start > 0xFFFF || as == nil {
		return app.IINParameterError
	}
	v := h.GV.Variation()
	for _, o := range h.Objects {
		val := o.Value.(app.Attribute)
		if as.legacy {
			wh, ok := a.srv.opts.handler.(WriteHandler)
			if !ok || wh.WriteAttribute(ctx, v, val) != nil {
				iin |= app.IINParameterError
			}
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

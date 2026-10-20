// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
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
			switch g := h.GV.Group(); {
			case g == 0 && wh != nil:
				for _, o := range h.Objects {
					if err := wh.WriteAttribute(ctx, h.GV.Variation(), o.Value.(app.Attribute)); err != nil {
						r.iin |= app.IINParameterError
					}
				}
			case g == 110:
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
			case g == 70:
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
	r := &response{}
	clearAfter := req.Function == app.FuncFreezeClear || req.Function == app.FuncFreezeClearNoAck
	hs := req.Headers
	if req.Function == app.FuncFreezeAtTime || req.Function == app.FuncFreezeAtTimeNoAck {
		if len(hs) == 0 || hs[0].GV != app.G50V2 || len(hs[0].Objects) != 1 {
			return &response{iin: app.IINParameterError}
		}
		at := hs[0].Objects[0].Value.(app.AbsoluteTime)
		if at.Interval != 0 || at.Time.Time().After(a.srv.clock.time()) {
			return &response{iin: app.IINParameterError}
		}
		hs = hs[1:]
	}
	now := a.srv.clock.now()
	db := a.srv.db
	err := db.Batch(func(b *Batch) error {
		for i := range hs {
			h := &hs[i]
			var src, dst PointType
			switch h.GV.Group() {
			case 20:
				src, dst = Counter, FrozenCounter
			case 30:
				src, dst = AnalogInput, FrozenAnalogInput
			default:
				r.iin |= app.IINObjectUnknown
				continue
			}
			sel, ok := selectorOf(h)
			if !ok {
				r.iin |= app.IINParameterError
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
				if clearAfter && src == Counter {
					c := p.value.(app.Counter)
					c.Value, c.Time = 0, now
					_ = b.Update(Counter, idx, c, EventOnChange)
				}
			}
		}
		return nil
	})
	if err != nil {
		r.iin |= app.IINParameterError
	}
	return r
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

func (s *Server) attributeItems(h *app.Header, p *readPlan) []item {
	attrs := s.opts.attributes
	one := func(v uint8, at app.Attribute) item {
		return item{h: app.Ranged(app.GV(0, v), 0, at)}
	}
	switch v := h.GV.Variation(); v {
	case app.AttrAllAttributes:
		var out []item
		for _, v := range sortedVariations(attrs) {
			out = append(out, one(v, attrs[v]))
		}
		return out
	case app.AttrListOfVariations:
		_, writable := s.opts.handler.(WriteHandler)
		var entries []app.AttributeListEntry
		for _, v := range sortedVariations(attrs) {
			entries = append(entries, app.AttributeListEntry{Variation: v, Writable: writable})
		}
		return []item{one(v, app.ListAttribute(entries...))}
	default:
		at, ok := attrs[v]
		if !ok {
			p.iin |= app.IINObjectUnknown
			return nil
		}
		return []item{one(v, at)}
	}
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

// SPDX-License-Identifier: MIT

package server

import (
	"math"

	"github.com/otfabric/go-dnp3/app"
)

// selector is the set of indexes a header of a READ names.
type selector struct {
	all         bool
	start, stop uint32
	indexes     map[uint32]bool
}

func selectorOf(h *app.Header) (selector, bool) {
	q := h.Qualifier
	switch {
	case q == app.QualAll:
		return selector{all: true}, true
	case q.IsRange():
		return selector{start: h.Start, stop: h.Stop}, true
	case q.IsIndexed():
		s := selector{indexes: make(map[uint32]bool, len(h.Objects))}
		for _, o := range h.Objects {
			s.indexes[o.Index] = true
		}
		return s, true
	default:
		return selector{}, false
	}
}

func (s selector) has(i uint32) bool {
	switch {
	case s.all:
		return true
	case s.indexes != nil:
		return s.indexes[i]
	default:
		return i >= s.start && i <= s.stop
	}
}

// eventSelector is one event header of a READ: a class or a point type,
// a variation (0 for each event's own) and a count limit (0 for none).
type eventSelector struct {
	classes   uint8 // bit mask, 1<<class; 0 when the selector is a type
	typ       PointType
	variation uint8
	limit     int
	taken     int
}

func (s *eventSelector) match(e *bufEvent) bool {
	if s.limit > 0 && s.taken >= s.limit {
		return false
	}
	if s.classes != 0 {
		return s.classes&(1<<e.class) != 0
	}
	return e.typ == s.typ
}

// readPlan is the content of a READ response before packing.
type readPlan struct {
	items []item
	iin   app.IIN
}

// planRead builds the response to a READ. The caller holds the database
// lock for reading.
func (a *association) planRead(req *app.Fragment) readPlan {
	var p readPlan
	var sels []*eventSelector
	var statics []item
	db := a.srv.db

	for i := range req.Headers {
		h := &req.Headers[i]
		g, v := h.GV.Group(), h.GV.Variation()
		limit := 0
		if h.Qualifier.IsCount() {
			limit = int(h.Count)
		}
		switch {
		case g == 60 && v == 1:
			for t := range numPointTypes {
				if t == TimeAndInterval {
					continue // read by group and variation only, as the references do
				}
				statics = append(statics, db.statics(t, selector{all: true}, 0, true)...)
			}
		case g == 60 && v >= 2 && v <= 4:
			sels = append(sels, &eventSelector{classes: 1 << (v - 1), limit: limit})
		case g == 34:
			sel, ok := selectorOf(h)
			if !ok {
				p.iin |= app.IINParameterError
				continue
			}
			statics = append(statics, db.deadbandItems(sel, v, &p)...)
		case g == 80 && v == 1:
			sel, ok := selectorOf(h)
			if !ok {
				p.iin |= app.IINParameterError
				continue
			}
			statics = append(statics, a.iinItem(sel))
		default:
			t, isEvent, ok := pointTypeOfGroup(g)
			if !ok {
				if a.srv.readOther(a, h, &p) {
					continue
				}
				p.iin |= app.IINObjectUnknown
				continue
			}
			if v != 0 && !validVariation(t, isEvent, h.GV) {
				p.iin |= app.IINObjectUnknown
				continue
			}
			if isEvent {
				sels = append(sels, &eventSelector{typ: t, variation: v, limit: limit})
				continue
			}
			sel, ok := selectorOf(h)
			if !ok {
				p.iin |= app.IINParameterError
				continue
			}
			if t == SecurityStatistic {
				statics = append(statics, a.statisticItems(sel, v, &p)...)
				continue
			}
			items := db.statics(t, sel, v, false)
			if !sel.all && !db.covers(t, sel) {
				p.iin |= app.IINParameterError
			}
			statics = append(statics, items...)
		}
	}
	if len(sels) > 0 {
		p.items = append(p.items, a.eventItems(sels)...)
	}
	p.items = append(p.items, statics...)
	return p
}

func validVariation(t PointType, event bool, gv app.GroupVariation) bool {
	switch t {
	case OctetString:
		return true // the variation is the length
	case TimeAndInterval:
		return gv == app.G50V4
	default:
	}
	return gv.Known()
}

// covers reports whether every index the selector names exists.
func (db *Database) covers(t PointType, s selector) bool {
	if s.indexes != nil {
		for i := range s.indexes {
			if _, ok := db.points[t][i]; !ok {
				return false
			}
		}
		return true
	}
	for i := uint64(s.start); i <= uint64(s.stop); i++ {
		if _, ok := db.points[t][uint32(i)]; !ok {
			return false
		}
	}
	return true
}

// staticGV returns the variation a point is reported in.
func staticGV(t PointType, p *point, requested uint8) app.GroupVariation {
	ti := types[t]
	if t == OctetString {
		return app.GV(ti.staticGroup, uint8(len(p.value.(app.OctetString).Data)))
	}
	v := requested
	if v == 0 {
		v = p.cfg.StaticVariation
	}
	if v == 0 {
		v = ti.staticDefault
	}
	return app.GV(ti.staticGroup, v)
}

// statics returns the static headers for the points of t the selector
// names: one ranged header per run of contiguous indexes in the same
// variation, or indexed headers for an index list. The caller holds mu.
func (db *Database) statics(t PointType, s selector, requested uint8, class0 bool) []item {
	var out []item
	var cur *item
	var last uint32
	indexed := s.indexes != nil
	for _, idx := range db.indexes(t) {
		if !s.has(idx) {
			continue
		}
		p := db.points[t][idx]
		if class0 && p.cfg.ExcludeFromClass0 {
			continue
		}
		if t == OctetString && requested != 0 && int(requested) != len(p.value.(app.OctetString).Data) {
			continue
		}
		gv := staticGV(t, p, requested)
		if f, ok := withFlags[gv]; ok && !onlineOnly(p.value) {
			gv = f
		}
		if cur == nil || cur.h.GV != gv || (!indexed && idx != last+1) {
			q := app.Qual1ByteStartStop
			if indexed {
				q = app.Qual2ByteIndexCount
			}
			out = append(out, item{h: app.Header{GV: gv, Qualifier: q}})
			cur = &out[len(out)-1]
		}
		cur.h.Objects = append(cur.h.Objects, app.Object{Index: idx, Value: p.value})
		last = idx
	}
	return out
}

// iinItem returns the IIN bits as packed g80v1 objects.
func (a *association) iinItem(s selector) item {
	iin := a.iin()
	h := app.Header{GV: app.G80V1, Qualifier: app.Qual1ByteStartStop}
	for b := uint32(0); b < 16; b++ {
		if s.has(b) {
			h.Objects = append(h.Objects, app.Object{Index: b, Value: app.Binary{Value: iin&(1<<b) != 0}})
		}
	}
	return item{h: h}
}

// eventGV returns the variation an event is reported in.
func eventGV(e *bufEvent, requested uint8) app.GroupVariation {
	ti := types[e.typ]
	if e.typ == OctetString {
		return app.GV(ti.eventGroup, uint8(len(e.value.(app.OctetString).Data)))
	}
	v := requested
	if v == 0 {
		v = e.variation
	}
	if v == 0 {
		v = ti.eventDefault
	}
	return app.GV(ti.eventGroup, v)
}

// relativeTime reports whether gv carries a time relative to a CTO.
func relativeTime(gv app.GroupVariation) bool {
	return gv == app.G2V3 || gv == app.G4V3
}

// eventItems selects the events the selectors name, in the order they
// occurred, and groups consecutive events of one variation into indexed
// headers. Each event is taken by the first selector that matches it.
func (a *association) eventItems(sels []*eventSelector) []item {
	var picked []*bufEvent
	var vars []uint8
	a.events.snapshot(func(e *bufEvent) bool {
		for _, s := range sels {
			if s.match(e) {
				s.taken++
				picked = append(picked, e)
				vars = append(vars, s.variation)
				return true
			}
		}
		return false
	}, 0)

	var out []item
	var cur *item
	var cto app.Timestamp
	for i, e := range picked {
		gv := eventGV(e, vars[i])
		ts := timeOf(e.value)
		rel := relativeTime(gv)
		if cur == nil || cur.h.GV != gv || (rel && (ts < cto || ts-cto > 0xFFFF)) {
			it := item{h: app.Header{GV: gv, Qualifier: app.Qual2ByteIndexCount}}
			if rel {
				cto = ts
				pre := app.Counted(app.G51V1, app.CTO{Time: cto})
				it.pre = &pre
			}
			out = append(out, it)
			cur = &out[len(out)-1]
		}
		cur.h.Objects = append(cur.h.Objects, app.Object{Index: e.index, Value: e.value})
		cur.events = append(cur.events, e)
	}
	return out
}

// withFlags maps the static variations that carry no flags (packed, and
// the counters and analog inputs without flag) to the variation of the same
// value with flags. A point whose flags are anything but ONLINE alone is
// reported in that variation instead, so that its quality is not hidden, as
// opendnp3 and stepfunc do and the DNP3 IED certification procedure
// requires (3.1r1 8.24).
var withFlags = map[app.GroupVariation]app.GroupVariation{
	app.G1V1:   app.G1V2,
	app.G3V1:   app.G3V2,
	app.G10V1:  app.G10V2,
	app.G20V5:  app.G20V1,
	app.G20V6:  app.G20V2,
	app.G21V9:  app.G21V1,
	app.G21V10: app.G21V2,
	app.G30V3:  app.G30V1,
	app.G30V4:  app.G30V2,
}

// onlineOnly reports whether a point's flags are ONLINE alone.
func onlineOnly(v app.Value) bool {
	var f app.Flags
	switch x := v.(type) {
	case app.Binary:
		f = x.Flags
	case app.DoubleBitBinary:
		f = x.Flags
	case app.Counter:
		f = x.Flags
	case app.Analog:
		f = x.Flags
	}
	return f == app.FlagOnline
}

// deadbandItems returns the deadbands of the analog inputs a READ of g34
// names: in the requested variation, or the smallest that holds the value
// (v1 16-bit, v2 32-bit, v3 floating point). The caller holds mu.
func (db *Database) deadbandItems(sel selector, requested uint8, p *readPlan) []item {
	if requested > 3 {
		p.iin |= app.IINObjectUnknown
		return nil
	}
	if !sel.all && !db.covers(AnalogInput, sel) {
		p.iin |= app.IINParameterError
	}
	var out []item
	var cur *item
	var last uint32
	indexed := sel.indexes != nil
	for _, idx := range db.indexes(AnalogInput) {
		if !sel.has(idx) {
			continue
		}
		d := db.points[AnalogInput][idx].cfg.Deadband
		v := requested
		if v == 0 {
			switch {
			case d == math.Trunc(d) && d >= 0 && d <= math.MaxUint16:
				v = 1
			case d == math.Trunc(d) && d >= 0 && d <= math.MaxUint32:
				v = 2
			default:
				v = 3
			}
		}
		gv := app.GV(34, v)
		if cur == nil || cur.h.GV != gv || (!indexed && idx != last+1) {
			q := app.Qual1ByteStartStop
			if indexed {
				q = app.Qual2ByteIndexCount
			}
			out = append(out, item{h: app.Header{GV: gv, Qualifier: q}})
			cur = &out[len(out)-1]
		}
		cur.h.Objects = append(cur.h.Objects, app.Object{Index: idx, Value: app.AnalogDeadband{Value: d}})
		last = idx
	}
	return out
}

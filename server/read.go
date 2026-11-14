// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"slices"

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
// a variation (0 for each event's own) and a count limit (negative for
// none).
type eventSelector struct {
	classes   uint8 // bit mask, 1<<class; 0 when the selector is a type
	typ       PointType
	variation uint8
	limit     int
	taken     int
}

// noLimit is the limit of an event header without a count: all events.
const noLimit = -1

// open reports whether the selector takes more events.
func (s *eventSelector) open() bool { return s.limit < 0 || s.taken < s.limit }

// selectorQueue finds, for each event, the first selector in request order
// that takes it, without trying every selector: the positions of the
// selectors are indexed by class and by type, and a selector whose count
// is reached is dropped from the front of its lists for good. Selecting
// the events of a buffer stays linear in the events however many event
// headers a READ repeats.
type selectorQueue struct {
	sels    []*eventSelector
	byClass [8][]int
	byType  map[PointType][]int
}

func newSelectorQueue(sels []*eventSelector) *selectorQueue {
	q := &selectorQueue{sels: sels, byType: map[PointType][]int{}}
	for i, s := range sels {
		if s.classes == 0 {
			q.byType[s.typ] = append(q.byType[s.typ], i)
			continue
		}
		for c := range q.byClass {
			if s.classes&(1<<c) != 0 {
				q.byClass[c] = append(q.byClass[c], i)
			}
		}
	}
	return q
}

// head returns the position of the first open selector of l, dropping the
// closed ones before it, or -1.
func (q *selectorQueue) head(l *[]int) int {
	for len(*l) > 0 {
		if i := (*l)[0]; q.sels[i].open() {
			return i
		}
		*l = (*l)[1:]
	}
	return -1
}

// take returns the selector that takes e, or nil.
func (q *selectorQueue) take(e *bufEvent) *eventSelector {
	best := -1
	if int(e.class) < len(q.byClass) {
		best = q.head(&q.byClass[e.class])
	}
	if l, ok := q.byType[e.typ]; ok {
		if i := q.head(&l); i >= 0 && (best < 0 || i < best) {
			best = i
		}
		q.byType[e.typ] = l
	}
	if best < 0 {
		return nil
	}
	return q.sels[best]
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
	// The objects a READ may plan are bounded by the size of the database:
	// four complete reads of it, which every reasonable request stays within,
	// so a request repeating headers that name every point is answered with
	// IIN2.2 instead of holding the database for its whole length. Each
	// header is charged with the points it selects, which is also the work
	// of planning it: a header naming one point costs one. Headers that
	// are not of points (device attributes, file blocks, statistics, IIN
	// bits) are charged with the objects they produce. Event headers are
	// not: each buffered event is reported at most once per response, so
	// the event buffer limits bound them.
	budget := 4*db.size() + 1024
	spend := func(n int) bool {
		budget -= n
		if budget < 0 {
			p.iin |= app.IINParameterError
			return false
		}
		return true
	}
	charge := func(t PointType, sel selector) bool {
		return spend(db.countSelected(t, sel))
	}
	// chargeItems charges the objects of items, or refuses them all.
	chargeItems := func(items []item) []item {
		if !spend(objectCount(items)) {
			return nil
		}
		return items
	}

	for i := range req.Headers {
		h := &req.Headers[i]
		g, v := h.GV.Group(), h.GV.Variation()
		// A count qualifier (0x07..0x09) limits an event header to that
		// many events, the oldest first; a count of zero names none.
		limit := noLimit
		if h.Qualifier.IsCount() {
			limit = int(min(h.Count, math.MaxInt32))
		}
		switch {
		case g == 60 && v == 1:
			for t := range numPointTypes {
				if t == TimeAndInterval {
					continue // read by group and variation only, as the references do
				}
				if !charge(t, selector{all: true}) {
					break
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
			if !charge(AnalogInput, sel) {
				continue
			}
			statics = append(statics, db.deadbandItems(sel, v, &p)...)
		case g == 50 && v == 1:
			// A read of the current time and date, qualifier 0x07 count 1
			// (A.23.1.2.3, p. 648; Table 14-4, p. 409). Another qualifier
			// or count is one the outstation does not support: IIN2.2
			// (4.5.11, p. 85).
			if !h.Qualifier.IsCount() || h.Count != 1 {
				p.iin |= app.IINParameterError
				continue
			}
			statics = append(statics, item{h: app.Counted(app.G50V1, app.AbsoluteTime{Time: a.srv.clock.now()})})
		case g == 70 && v == 6 && a.srv.opts.files != nil:
			// The file transport status events (A.27.6.1, p. 679).
			sels = append(sels, &eventSelector{typ: fileStatusEvent, limit: limit})
		case g == 80 && v == 1:
			sel, ok := selectorOf(h)
			if !ok {
				p.iin |= app.IINParameterError
				continue
			}
			statics = append(statics, chargeItems([]item{a.iinItem(sel)})...)
		default:
			t, isEvent, ok := pointTypeOfGroup(g)
			if !ok {
				// A READ of file blocks reads the file: it is charged with
				// one object per block before, as a block read and then
				// dropped could not be sent again. Other headers have no
				// effect beyond the plan and are charged after with the
				// objects they produced; once the budget is spent they are
				// not planned at all.
				if (h.GV == app.G70V5 && a.srv.opts.files != nil && budget < len(h.Objects)) || (g == 0 && budget < 0) {
					p.iin |= app.IINParameterError
					continue
				}
				before := len(p.items)
				if a.srv.readOther(a, h, &p) {
					if !spend(objectCount(p.items[before:])) {
						clear(p.items[before:])
						p.items = p.items[:before]
					}
					continue
				}
				p.iin |= app.IINObjectUnknown
				continue
			}
			if v != 0 && !validVariation(t, isEvent, h.GV) {
				p.iin |= app.IINObjectUnknown
				continue
			}
			if measurement(t) && len(db.points[t]) == 0 {
				// The outstation has no points of the type: a null response
				// with IIN2.1, as TB2016-001 and the DNP3 IED certification
				// procedure 3.1r1 (Table 11-1) require.
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
				statics = append(statics, chargeItems(a.statisticItems(sel, v, &p))...)
				continue
			}
			if !charge(t, sel) {
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

// objectCount returns the number of objects of items.
func objectCount(items []item) int {
	n := 0
	for _, it := range items {
		n += len(it.h.Objects)
	}
	return n
}

// measurements are the types of input and output points, whose reads are
// answered with IIN2.1 when the database has none of them.
var measurements = [numPointTypes]bool{
	BinaryInput: true, DoubleBitInput: true, BinaryOutput: true, Counter: true,
	FrozenCounter: true, AnalogInput: true, FrozenAnalogInput: true, AnalogOutput: true,
}

// measurement reports whether t is a type of input or output point.
func measurement(t PointType) bool { return measurements[t] }

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

// countSelected returns how many points of t the selector names, at most:
// every point for all objects, those within a range, the indexes of an
// index list. The caller holds mu.
func (db *Database) countSelected(t PointType, s selector) int {
	switch {
	case s.all:
		return len(db.points[t])
	case s.indexes != nil:
		return len(s.indexes)
	default:
		lo, hi := db.rangeOf(t, s)
		return hi - lo
	}
}

// rangeOf returns the positions in the sorted indexes of t of the first
// point within the range of s and of the first point beyond it. The caller
// holds mu.
func (db *Database) rangeOf(t PointType, s selector) (lo, hi int) {
	if s.start > s.stop {
		return 0, 0
	}
	idx := db.indexes(t)
	lo, _ = slices.BinarySearch(idx, s.start)
	hi, found := slices.BinarySearch(idx, s.stop)
	if found {
		hi++
	}
	return lo, hi
}

// selected returns the indexes of the points of t the selector names, in
// ascending order, without visiting the points outside it. The caller holds
// mu.
func (db *Database) selected(t PointType, s selector) []uint32 {
	switch {
	case s.all:
		return db.indexes(t)
	case s.indexes != nil:
		out := make([]uint32, 0, len(s.indexes))
		for i := range s.indexes {
			if _, ok := db.points[t][i]; ok {
				out = append(out, i)
			}
		}
		slices.Sort(out)
		return out
	default:
		lo, hi := db.rangeOf(t, s)
		return db.indexes(t)[lo:hi]
	}
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
	if s.start > s.stop {
		return true
	}
	for i := s.start; ; i++ {
		if _, ok := db.points[t][i]; !ok {
			return false
		}
		if i == s.stop { // before i++, which wraps after 0xFFFFFFFF
			break
		}
	}
	return true
}

// staticGV returns the variation a point is reported in.
func staticGV(t PointType, p *point, requested uint8) app.GroupVariation {
	ti := types[t]
	if t == OctetString {
		return app.OctetStringGV(ti.staticGroup, len(p.value.(app.OctetString).Data))
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
	for _, idx := range db.selected(t, s) {
		p := db.points[t][idx]
		if class0 && p.cfg.ExcludeFromClass0 {
			continue
		}
		// An octet string is reported in the variation of its length,
		// whichever length the master named (A.41.1, p. 715).
		gv := staticGV(t, p, requested)
		if f, ok := withFlags[gv]; ok && (!onlineOnly(p.value) || !fits(gv, p.value) || (indexed && packed[gv])) {
			// A packed variation has no index form either: by index it
			// is reported with flags, as 11.6.5 permits (4.2.2.7.2.2,
			// p. 31).
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
	for b := range uint32(16) {
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
		return app.OctetStringGV(ti.eventGroup, len(e.value.(app.OctetString).Data))
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

// relativeOf maps the event variations with absolute time that have one
// with relative time.
var relativeOf = map[app.GroupVariation]app.GroupVariation{app.G2V2: app.G2V3, app.G4V2: app.G4V3}

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
	q := newSelectorQueue(sels)
	a.events.snapshot(func(e *bufEvent) bool {
		s := q.take(e)
		if s == nil {
			return false
		}
		s.taken++
		picked = append(picked, e)
		vars = append(vars, s.variation)
		return true
	}, 0)

	var out []item
	var cur *item
	var cto app.Timestamp
	ctoGV := app.G51V1
	for i, e := range picked {
		if e.typ == fileStatusEvent {
			// A free-format object, one per header.
			out = append(out, item{h: app.FreeFormat(app.G70V6, e.value), events: []*bufEvent{e}})
			cur = nil
			continue
		}
		gv := eventGV(e, vars[i])
		unsync := a.unsynchronizedAt(e.at)
		// A binary or double-bit event recorded while the time was
		// unsynchronized is reported with relative time under an
		// unsynchronized CTO, unless the master asked for absolute time.
		if r, ok := relativeOf[gv]; ok && unsync && vars[i] == 0 {
			gv = r
		}
		ts := timeOf(e.value)
		rel := relativeTime(gv)
		eventCTO := app.G51V1
		if unsync {
			eventCTO = app.G51V2
		}
		if cur == nil || cur.h.GV != gv || (rel && (ts < cto || ts-cto > 0xFFFF || eventCTO != ctoGV)) {
			it := item{h: app.Header{GV: gv, Qualifier: app.Qual2ByteIndexCount}}
			if rel {
				cto, ctoGV = ts, eventCTO
				pre := app.Counted(ctoGV, app.CTO{Time: cto})
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
// opendnp3 does and the DNP3 IED certification procedure requires (3.1r1
// 8.24).
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
	app.G31V5:  app.G31V1,
	app.G31V6:  app.G31V2,
}

// packed are the static variations whose objects are bits packed in a
// range, which no index qualifier carries.
var packed = map[app.GroupVariation]bool{app.G1V1: true, app.G3V1: true, app.G10V1: true}

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

// fits reports whether an analog value is carried exactly enough by an
// integer variation without flag: NaN, infinities and values out of its
// range need the variation with flags, which reports OVER_RANGE.
func fits(gv app.GroupVariation, v app.Value) bool {
	a, ok := v.(app.Analog)
	if !ok {
		return true
	}
	var lo, hi float64
	switch gv {
	case app.G30V3, app.G31V5:
		lo, hi = math.MinInt32, math.MaxInt32
	case app.G30V4, app.G31V6:
		lo, hi = math.MinInt16, math.MaxInt16
	default:
		return true
	}
	r := math.Round(a.Value)
	return !math.IsNaN(r) && r >= lo && r <= hi
}

// deadbandItems returns the deadbands of the analog inputs a READ of g34
// names: in the requested variation, or the smallest that holds the value
// (v1 16-bit, v2 32-bit, v3 floating point). With WithDeadbandIntegerOnly
// they are reported in v1 and v2 only, rounded and limited to the range of
// v2 (A.18.3.2.3, p. 609). The caller holds mu.
func (db *Database) deadbandItems(sel selector, requested uint8, p *readPlan) []item {
	intOnly := db.srv != nil && db.srv.opts.deadbandIntegerOnly
	if requested > 3 || (intOnly && requested == 3) {
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
	for _, idx := range db.selected(AnalogInput, sel) {
		d := db.points[AnalogInput][idx].cfg.Deadband
		if intOnly {
			d = min(math.Round(d), math.MaxUint32)
		}
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

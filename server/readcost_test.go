// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/otfabric/go-dnp3/app"
)

// planOn plans a READ of hs on the association's goroutine, under the
// database lock, as association.read does.
func planOn(srv *Server, a *association, hs ...app.Header) readPlan {
	done := make(chan readPlan, 1)
	a.post(func() {
		srv.db.mu.RLock()
		defer srv.db.mu.RUnlock()
		done <- a.planRead(&app.Fragment{Function: app.FuncRead, Headers: hs})
	})
	return <-done
}

func repeatHeader(n int, h app.Header) []app.Header {
	hs := make([]app.Header, n)
	for i := range hs {
		hs[i] = h
	}
	return hs
}

// TestFittingMatchesLinearScan: the galloping search of fitting finds the
// same number of objects as trying every prefix, for fixed and variable
// object sizes, ranged and index-prefixed headers and any room.
func TestFittingMatchesLinearScan(t *testing.T) {
	headers := map[string]app.Header{}
	var analogs, strs []app.Value
	var objs []app.Object
	for i := range 40 {
		analogs = append(analogs, app.Analog{Value: float64(i), Flags: app.FlagOnline})
		strs = append(strs, app.OctetString{Data: make([]byte, 17)})
		objs = append(objs, app.Object{Index: uint32(i * 13), Value: app.Binary{Flags: app.FlagOnline, Time: 1}})
	}
	headers["analogs"] = app.Ranged(app.G30V5, 0, analogs...)
	headers["octet strings"] = app.Ranged(app.GV(110, 17), 250, strs...)
	headers["indexed events"] = app.Indexed(app.G2V2, objs...)
	headers["one object"] = app.Ranged(app.G30V5, 0, analogs[0])
	linear := func(h app.Header, room int) int {
		best := 0
		for k := 1; k <= len(h.Objects); k++ {
			p := h
			p.Objects = h.Objects[:k]
			np := normalize(p)
			if l, err := np.EncodedLen(); err == nil && l <= room {
				best = k
			}
		}
		return best
	}
	for name, h := range headers {
		for room := -1; room < 900; room++ {
			if got, want := fitting(h, room), linear(h, room); got != want {
				t.Fatalf("%s, room %d: fitting %d, want %d", name, room, got, want)
			}
		}
	}
}

// packAllocated returns the octets allocated by packing items into
// fragments of max octets, the smallest of a few runs.
func packAllocated(items []item, max int) uint64 {
	best := ^uint64(0)
	var ms runtime.MemStats
	for range 3 {
		runtime.GC()
		runtime.ReadMemStats(&ms)
		before := ms.TotalAlloc
		plans, _ := pack(items, max)
		runtime.ReadMemStats(&ms)
		best = min(best, ms.TotalAlloc-before)
		runtime.KeepAlive(plans)
	}
	return best
}

// TestPackAllocationsLinear: packing a READ response costs in proportion
// to its objects: twice the points allocate about twice as much, not four
// times, for long octet strings and for many small analogs.
func TestPackAllocationsLinear(t *testing.T) {
	for _, tc := range []struct {
		name  string
		n     int
		value app.Value
		gv    app.GroupVariation
	}{
		{"255-octet strings", 400, app.OctetString{Data: make([]byte, 255)}, app.GV(110, 255)},
		{"analogs", 4000, app.Analog{Value: 1, Flags: app.FlagOnline}, app.G30V5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := func(n int) []item {
				vs := make([]app.Value, n)
				for i := range vs {
					vs[i] = tc.value
				}
				return []item{{h: app.Ranged(tc.gv, 0, vs...)}}
			}
			small, large := items(tc.n), items(2*tc.n)
			a, b := packAllocated(small, 2048), packAllocated(large, 2048)
			if float64(b) > 2.5*float64(a) {
				t.Errorf("%d objects allocated %d octets, %d objects %d: %.1fx", tc.n, a, 2*tc.n, b, float64(b)/float64(a))
			}
		})
	}
}

// TestReadBudgetChargesNonPointHeaders: headers that are not of points
// (device attributes, IIN bits, file blocks) are charged with the objects
// they produce against the READ budget (four reads of the database plus
// 1024 objects): repeating them beyond it is answered with IIN2.2 and the
// objects over the budget are not planned.
func TestReadBudgetChargesNonPointHeaders(t *testing.T) {
	attrs := map[uint8]app.Attribute{}
	for v := range uint8(30) {
		attrs[200+v] = app.StringAttribute(fmt.Sprintf("attribute %02d of thirty-two octets", v))
	}
	srv, err := New(WithAttributes(attrs), WithFileServer(FSFileServer{FS: fstest.MapFS{}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	_ = srv.Database().AddBinaryInput(0, PointConfig{}, app.Binary{Flags: app.FlagOnline})
	const budget = 4*1 + 1024
	a := srv.association(1)

	perHeader := objectCount(planOn(srv, a, app.AllObjects(app.GV(0, app.AttrAllAttributes))).items)
	if perHeader < 30 {
		t.Fatalf("one g0v254 header planned %d objects, want at least 30", perHeader)
	}
	fitsIn := budget / perHeader
	blocks := func(n int) []app.Header {
		hs := make([]app.Header, n)
		for i := range hs {
			hs[i] = app.FreeFormat(app.G70V5, app.FileTransport{Handle: 7, Block: uint32(i)})
		}
		return hs
	}
	for _, tc := range []struct {
		name    string
		hs      []app.Header
		objects int
		refused bool
	}{
		{"attributes within budget", repeatHeader(fitsIn, app.AllObjects(app.GV(0, app.AttrAllAttributes))), fitsIn * perHeader, false},
		{"attributes beyond budget", repeatHeader(600, app.AllObjects(app.GV(0, app.AttrAllAttributes))), fitsIn * perHeader, true},
		{"IIN bits within budget", repeatHeader(budget/16, app.AllObjects(app.G80V1)), budget / 16 * 16, false},
		{"IIN bits beyond budget", repeatHeader(budget/16+5, app.AllObjects(app.G80V1)), budget / 16 * 16, true},
		{"file blocks within budget", blocks(budget), budget, false},
		{"file blocks beyond budget", blocks(budget + 3), budget, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := planOn(srv, a, tc.hs...)
			if got := p.iin.Has(app.IINParameterError); got != tc.refused {
				t.Errorf("IIN %s, refused %t, want %t", p.iin, got, tc.refused)
			}
			if got := objectCount(p.items); got != tc.objects {
				t.Errorf("%d objects planned, want %d", got, tc.objects)
			}
		})
	}
}

// TestEventSelectorsFirstInOrder: each event is taken by the first event
// header of the READ, in request order, that names its class or type and
// has not reached its count, as trying every header in turn would.
func TestEventSelectorsFirstInOrder(t *testing.T) {
	types := []PointType{BinaryInput, Counter, AnalogInput, fileStatusEvent}
	var evs []*bufEvent
	for i := range 300 {
		evs = append(evs, &bufEvent{event: event{typ: types[i*7%len(types)], index: uint32(i), class: Class(1 + i*5%3)}})
	}
	mkSels := func() []*eventSelector {
		var sels []*eventSelector
		for i := range 40 {
			limit := noLimit
			if i%3 != 0 {
				limit = i % 11
			}
			if i%2 == 0 {
				sels = append(sels, &eventSelector{classes: 1 << (1 + i%3), limit: limit})
			} else {
				sels = append(sels, &eventSelector{typ: types[i%len(types)], variation: uint8(i), limit: limit})
			}
		}
		sels = append(sels, &eventSelector{classes: 1<<1 | 1<<3, limit: noLimit}, &eventSelector{classes: 1 << 2, limit: 0})
		return sels
	}
	// The reference: every selector in turn.
	refSels := mkSels()
	var want []int
	for _, e := range evs {
		for i, s := range refSels {
			if !s.open() || (s.classes != 0 && s.classes&(1<<e.class) == 0) || (s.classes == 0 && s.typ != e.typ) {
				continue
			}
			s.taken++
			want = append(want, i)
			break
		}
	}
	sels := mkSels()
	q := newSelectorQueue(sels)
	pos := map[*eventSelector]int{}
	for i, s := range sels {
		pos[s] = i
	}
	var got []int
	for _, e := range evs {
		if s := q.take(e); s != nil {
			s.taken++
			got = append(got, pos[s])
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("selectors taking the events:\n got %v\nwant %v", got, want)
	}
	// An event of a class beyond the class bits is taken by no class.
	if s := q.take(&bufEvent{event: event{typ: 200, class: 9}}); s != nil {
		t.Errorf("event of class 9 taken by %+v", s)
	}
}

// SPDX-License-Identifier: MIT

package server

import (
	"reflect"
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

// packInput builds response items from fuzz input: every kind of header
// the outstation packs (ranged statics, index-prefixed events with their
// buffered events, variable-length octet strings, relative-time events
// behind a CTO) with any indexes and counts, and a fragment size.
func packInput(data []byte) (items []item, max int) {
	next := func() byte {
		if len(data) == 0 {
			return 0
		}
		b := data[0]
		data = data[1:]
		return b
	}
	max = 16 + int(next())*2 // 16..526 octets: tiny to several objects per fragment
	for len(data) > 0 && len(items) < 12 {
		kind, n := next()%4, 1+int(next())%40
		start := uint32(next())<<8 | uint32(next())
		switch kind {
		case 0: // static analogs, a range
			var vs []app.Value
			for i := range n {
				vs = append(vs, app.Analog{Value: float64(i), Flags: app.FlagOnline})
			}
			items = append(items, item{h: app.Ranged(app.G30V5, start, vs...)})
		case 1: // events with time, index-prefixed, each with its event
			var objs []app.Object
			var evs []*bufEvent
			for i := range n {
				objs = append(objs, app.Object{Index: start + uint32(i)*uint32(1+next()%7), Value: app.Binary{Value: i%2 == 0, Flags: app.FlagOnline, Time: 1}})
				evs = append(evs, &bufEvent{})
			}
			items = append(items, item{h: app.Indexed(app.G2V2, objs...), events: evs})
		case 2: // octet strings of one length, a range
			l := 1 + next()%40
			var vs []app.Value
			for range n {
				vs = append(vs, app.OctetString{Data: make([]byte, l)})
			}
			items = append(items, item{h: app.Ranged(app.GV(110, l), start, vs...)})
		case 3: // relative-time events behind a CTO
			var objs []app.Object
			var evs []*bufEvent
			for i := range n {
				objs = append(objs, app.Object{Index: start + uint32(i), Value: app.Binary{Flags: app.FlagOnline, Time: app.Timestamp(1000 + i)}})
				evs = append(evs, &bufEvent{})
			}
			cto := app.Counted(app.G51V1, app.CTO{Time: 1000})
			items = append(items, item{pre: &cto, h: app.Indexed(app.G2V3, objs...), events: evs})
		}
	}
	return items, max
}

// FuzzPack checks the invariants of splitting a response into fragments
// for any headers and fragment size: no panic, no fragment over the size,
// every object kept in order unless it cannot fit even an empty fragment,
// and each event fragment carrying the events of its objects.
func FuzzPack(f *testing.F) {
	f.Add([]byte{0, 0, 3, 0, 1, 1, 5, 0, 2, 2, 7, 1, 0, 3, 9, 0, 3})
	f.Add([]byte{100, 0, 39, 1, 44, 1, 39, 0, 0, 2, 39, 0, 0, 40})
	f.Add([]byte{1, 3, 20, 0, 0, 2, 10, 0, 0, 39})
	f.Fuzz(func(t *testing.T, data []byte) {
		items, max := packInput(data)
		plans, dropped := pack(items, max)
		var want []app.Object
		for _, it := range items {
			want = append(want, it.h.Objects...)
		}
		var got []app.Object
		for i, p := range plans {
			b, err := (&app.Fragment{Function: app.FuncResponse, Headers: p.headers}).Encode()
			if err != nil {
				t.Fatalf("fragment %d does not encode: %v", i, err)
			}
			if len(b) > max && len(p.headers) > 2 {
				t.Fatalf("fragment %d: %d octets, more than %d", i, len(b), max)
			}
			objs := 0
			for _, h := range p.headers {
				if h.GV.Group() == 51 {
					continue
				}
				if h.GV.IsEvent() {
					objs += len(h.Objects)
				}
				got = append(got, h.Objects...)
			}
			if len(p.events) != objs {
				t.Fatalf("fragment %d: %d events for %d event objects", i, len(p.events), objs)
			}
		}
		if len(got)+dropped != len(want) {
			t.Fatalf("%d objects packed and %d dropped of %d", len(got), dropped, len(want))
		}
		// In order: got is want with the dropped objects left out.
		j := 0
		for _, o := range got {
			for j < len(want) && (want[j].Index != o.Index || !reflect.DeepEqual(want[j].Value, o.Value)) {
				j++
			}
			if j == len(want) {
				t.Fatalf("object %d out of order or changed", o.Index)
			}
			j++
		}
		// Nothing is dropped when every object fits an empty fragment.
		if dropped > 0 && max >= 4+6+8+8+40+6 {
			t.Fatalf("%d objects dropped with fragments of %d octets", dropped, max)
		}
	})
}

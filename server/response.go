// SPDX-License-Identifier: MIT

package server

import (
	"sort"

	"github.com/otfabric/go-dnp3/app"
)

// item is one logical header of a response before it is split into
// fragments: the header with all its objects, the CTO it needs (for
// relative-time event variations) and, for event headers, the event behind
// each object.
type item struct {
	pre    *app.Header
	h      app.Header
	events []*bufEvent
}

// fragPlan is the content of one response fragment.
type fragPlan struct {
	headers []app.Header
	events  []*bufEvent
}

// responseHeaderLen is the size of a response's application header.
const responseHeaderLen = 4

// pack splits items into fragments of at most max octets. Headers are
// split at object boundaries; an object that does not fit an empty
// fragment is dropped and reported by the returned count.
func pack(items []item, max int) (plans []fragPlan, dropped int) {
	cur := fragPlan{}
	size := responseHeaderLen
	flush := func() {
		plans = append(plans, cur)
		cur = fragPlan{}
		size = responseHeaderLen
	}
	for _, it := range items {
		h := it.h
		evs := it.events
		for {
			preLen := 0
			if it.pre != nil {
				preLen, _ = it.pre.EncodedLen()
			}
			room := max - size - preLen
			n := len(h.Objects)
			if n == 0 {
				// A header without objects (none occur in responses today).
				l, _ := h.EncodedLen()
				if l <= max-size || len(cur.headers) == 0 {
					cur.headers = append(cur.headers, h)
					size += l
				}
				break
			}
			k := fitting(h, room)
			if k == 0 {
				if len(cur.headers) > 0 {
					flush()
					continue
				}
				// Even an empty fragment cannot take the first object.
				dropped++
				h.Objects = h.Objects[1:]
				if evs != nil {
					evs = evs[1:]
				}
				if len(h.Objects) == 0 {
					break
				}
				continue
			}
			part := h
			part.Objects = h.Objects[:k]
			part = normalize(part)
			if it.pre != nil {
				cur.headers = append(cur.headers, *it.pre)
			}
			cur.headers = append(cur.headers, part)
			l, _ := part.EncodedLen()
			size += preLen + l
			if evs != nil {
				cur.events = append(cur.events, evs[:k]...)
				evs = evs[k:]
			}
			if k == n {
				break
			}
			h.Objects = h.Objects[k:]
			flush()
		}
	}
	if len(cur.headers) > 0 || len(plans) == 0 {
		plans = append(plans, cur)
	}
	return plans, dropped
}

// fitting returns the largest k such that h with its first k objects fits
// in room octets.
func fitting(h app.Header, room int) int {
	if room <= 0 {
		return 0
	}
	sized := func(k int) int {
		p := h
		p.Objects = h.Objects[:k]
		np := normalize(p)
		l, err := np.EncodedLen()
		if err != nil {
			return room + 1
		}
		return l
	}
	n := len(h.Objects)
	if sized(n) <= room {
		return n
	}
	// sized is monotonic in k: the largest k with sized(k) <= room. When
	// not even the header without objects fits, that is none: 0, not -1.
	return max(0, sort.Search(n+1, func(k int) bool { return sized(k) > room })-1)
}

// normalize sets the range and count fields of h from its objects and
// picks the smallest qualifier of the same kind.
func normalize(h app.Header) app.Header {
	n := len(h.Objects)
	if n == 0 {
		return h
	}
	switch {
	case h.Qualifier.IsRange():
		h.Start, h.Stop = h.Objects[0].Index, h.Objects[n-1].Index
		h.Qualifier = app.RangeQualifier(h.Stop)
	case h.Qualifier.IsIndexed():
		var m uint32
		for _, o := range h.Objects {
			m = max(m, o.Index)
		}
		h.Qualifier = app.IndexQualifier(n, m)
		h.Count = uint32(n)
	case h.Qualifier.IsCount():
		h.Count = uint32(n)
		if !h.Qualifier.IsFreeFormat() {
			h.Qualifier = app.CountQualifier(n)
		}
	}
	return h
}

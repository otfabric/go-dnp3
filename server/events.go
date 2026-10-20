// SPDX-License-Identifier: MIT

package server

import (
	"sync"

	"github.com/otfabric/go-dnp3/app"
)

// event is one change of a point, waiting to be reported.
type event struct {
	typ   PointType
	index uint32
	class Class
	// variation is the point's configured event variation, 0 for the
	// default of its type.
	variation uint8
	value     app.Value
}

type bufEvent struct {
	event
	// selected marks an event written into a response that has not been
	// confirmed yet.
	selected bool
}

// eventBuffer holds the unreported events of one association in the order
// they occurred, which is the order they are reported in.
type eventBuffer struct {
	mu       sync.Mutex
	limit    [numPointTypes]int
	events   []*bufEvent
	count    [numPointTypes]int
	overflow bool
}

// DefaultEventLimit is the number of events of each point type an
// association buffers when no limit is configured.
const DefaultEventLimit = 100

func newEventBuffer(limits map[PointType]int) *eventBuffer {
	b := &eventBuffer{}
	for t := range b.limit {
		b.limit[t] = DefaultEventLimit
		if n, ok := limits[PointType(t)]; ok {
			b.limit[t] = n
		}
	}
	return b
}

// add appends events and returns the number discarded per class (index
// 1..3) to stay within the limits. A type with limit 0 buffers nothing.
func (b *eventBuffer) add(evs []event) (discarded [4]int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range evs {
		if b.limit[e.typ] <= 0 {
			discarded[e.class]++
			b.overflow = true
			continue
		}
		if b.count[e.typ] >= b.limit[e.typ] {
			if victim := b.oldest(e.typ); victim >= 0 {
				discarded[b.events[victim].class]++
				b.removeAt(victim)
				b.overflow = true
			}
		}
		b.events = append(b.events, &bufEvent{event: e})
		b.count[e.typ]++
	}
	return discarded
}

// oldest returns the position of the oldest event of type t, preferring
// one that is not part of an unconfirmed response.
func (b *eventBuffer) oldest(t PointType) int {
	first := -1
	for i, e := range b.events {
		if e.typ != t {
			continue
		}
		if !e.selected {
			return i
		}
		if first < 0 {
			first = i
		}
	}
	return first
}

func (b *eventBuffer) removeAt(i int) {
	b.count[b.events[i].typ]--
	b.events = append(b.events[:i], b.events[i+1:]...)
}

// iin returns the class event bits for unreported (unselected) events
// and the overflow bit.
func (b *eventBuffer) iin() app.IIN {
	b.mu.Lock()
	defer b.mu.Unlock()
	var i app.IIN
	for _, e := range b.events {
		if e.selected {
			continue
		}
		switch e.class {
		case 1:
			i |= app.IINClass1Events
		case 2:
			i |= app.IINClass2Events
		case 3:
			i |= app.IINClass3Events
		}
	}
	if b.overflow {
		i |= app.IINEventBufferOverflow
	}
	return i
}

// pending returns the number of unselected events in the given classes
// (a bit mask: 1<<1 for class 1, ...).
func (b *eventBuffer) pending(classes uint8) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.events {
		if !e.selected && classes&(1<<e.class) != 0 {
			n++
		}
	}
	return n
}

// snapshot returns the unselected events that match, in order, up to max
// (0 for no limit). They are not selected yet: the response writer
// selects those that fit with mark.
func (b *eventBuffer) snapshot(match func(*bufEvent) bool, max int) []*bufEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*bufEvent
	for _, e := range b.events {
		if e.selected || !match(e) {
			continue
		}
		out = append(out, e)
		if max > 0 && len(out) == max {
			break
		}
	}
	return out
}

// mark selects events written into a response.
func (b *eventBuffer) mark(evs []*bufEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range evs {
		e.selected = true
	}
}

// confirm removes the given selected events: the master confirmed the
// response that carried them. It clears the overflow indication once
// there is room again.
func (b *eventBuffer) confirm(evs []*bufEvent) {
	if len(evs) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	done := make(map[*bufEvent]bool, len(evs))
	for _, e := range evs {
		done[e] = true
	}
	kept := b.events[:0]
	for _, e := range b.events {
		if done[e] {
			b.count[e.typ]--
			continue
		}
		kept = append(kept, e)
	}
	clear(b.events[len(kept):])
	b.events = kept
	b.overflow = false
}

// release unselects events whose response was not confirmed: they are
// reported again.
func (b *eventBuffer) release(evs []*bufEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range evs {
		e.selected = false
	}
}

// SPDX-License-Identifier: MIT

package server

import (
	"sync"
	"time"
)

// syncState is the time synchronization state of the outstation's clock,
// which every association shares: a synchronization by one master serves
// them all (IEEE 1815-2012 4.5.5).
type syncState struct {
	mu sync.Mutex
	// last and prev are the latest two synchronizations, on the monotonic
	// clock.
	last, prev time.Time
	// cleared is when a master last cleared IIN1.4 with a WRITE of g80v1
	// index 4.
	cleared time.Time
}

// synchronized records a time synchronization at now.
func (s *syncState) synchronized(now time.Time) {
	s.mu.Lock()
	s.last, s.prev = now, s.last
	s.mu.Unlock()
}

// clearNeedTime records that the master cleared IIN1.4 at now: it does not
// make the clock synchronized, but the bit is set again only after the
// interval (4.5.5).
func (s *syncState) clearNeedTime(now time.Time) {
	s.mu.Lock()
	s.cleared = now
	s.mu.Unlock()
}

// reset makes the clock unsynchronized, as at the start.
func (s *syncState) reset() {
	s.mu.Lock()
	s.last, s.prev, s.cleared = time.Time{}, time.Time{}, time.Time{}
	s.mu.Unlock()
}

// needsTime reports whether the outstation asks for time synchronization
// (IIN1.4) with the interval of WithTimeSync: it has not been synchronized,
// nor the bit cleared by a master, since the start or within the interval.
func (s *syncState) needsTime(interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	s.mu.Lock()
	ref := s.last
	if s.cleared.After(ref) {
		ref = s.cleared
	}
	s.mu.Unlock()
	return ref.IsZero() || time.Since(ref) > interval
}

// unsynchronizedAt reports whether the outstation's time counted as
// unsynchronized at t, as the CTO of relative-time events says (g51v2):
// with WithTimeSync, until the first synchronization since the start or a
// restart, and once twice the interval has passed without one. The latest
// two syncs are kept, so that an event buffered shortly before a periodic
// sync still counts as synchronized. A master clearing IIN1.4 does not
// synchronize the clock.
func (s *syncState) unsynchronizedAt(t time.Time, interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, at := range [...]time.Time{s.last, s.prev} {
		if !at.IsZero() && !t.Before(at) && t.Sub(at) <= 2*interval {
			return false
		}
	}
	return true
}

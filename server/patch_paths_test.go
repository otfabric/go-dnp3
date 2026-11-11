// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// Tests of outstation paths that the other tests do not reach: refusals
// of Secure Authentication in Wait for Reply, malformed control and freeze
// requests, an event type without a buffer, the file timeout of one of two
// files, an unsolicited response given up, and the races of a freeze
// schedule with its replacement. Page numbers are printed pages.

// recMetrics records what an outstation reports to dnp3.ServerMetrics.
type recMetrics struct {
	dnp3.NopMetrics
	mu        sync.Mutex
	handled   int
	discarded [4]int
	unsol     []unsolReport
	// onDiscard, when set, is called by OnEventsDiscarded, on the
	// goroutine that published the events.
	onDiscard func(class, n int)
}

func (m *recMetrics) setOnDiscard(f func(class, n int)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDiscard = f
}

type unsolReport struct {
	events int
	err    error
}

func (m *recMetrics) OnHandled(net.Addr, app.FunctionCode, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handled++
}

func (m *recMetrics) OnEventsDiscarded(class, n int) {
	m.mu.Lock()
	m.discarded[class] += n
	hook := m.onDiscard
	m.mu.Unlock()
	if hook != nil {
		hook(class, n)
	}
}

func (m *recMetrics) OnUnsolicited(_ net.Addr, events int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsol = append(m.unsol, unsolReport{events, err})
}

func (m *recMetrics) snapshot() (handled int, discarded [4]int, unsol []unsolReport) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handled, m.discarded, append([]unsolReport(nil), m.unsol...)
}

// TestFreezeReplacedWhileFreezing: a FREEZE_AT_TIME for the points of a
// schedule that comes while the schedule's freeze runs replaces the
// schedule (Table 4-11, p. 57: a schedule lasts until a new FREEZE_AT_TIME
// is received); the freeze that was running does not end the new one. The
// replacement is made from the metrics hook that the freeze's discarded
// event calls, so that it comes in the middle of the freeze.
func TestFreezeReplacedWhileFreezing(t *testing.T) {
	rec := &recMetrics{}
	m := newMaster(t, WithMetrics(rec), WithEventLimits(map[PointType]int{FrozenCounter: 0}))
	s := m.srv
	db := s.Database()
	_ = db.AddCounter(1, PointConfig{}, app.Counter{Value: 4, Flags: app.FlagOnline})
	_ = db.AddFrozenCounter(1, PointConfig{Class: 1}, app.Counter{Flags: app.FlagOnline})
	points := app.IndexRange(app.G20V0, 1, 1)
	later := app.TimestampOf(s.Now().Add(time.Hour))
	replaced := make(chan app.IIN, 1)
	var once sync.Once
	rec.setOnDiscard(func(int, int) {
		once.Do(func() {
			replaced <- s.freezeAtTime([]app.Header{app.Counted(app.G50V2, app.AbsoluteTime{Time: later}), points})
		})
	})
	m.send(freezeReq(1, app.AbsoluteTime{Time: app.TimestampOf(s.Now().Add(200 * time.Millisecond))}, points))
	if r := m.recvFunc(app.FuncResponse); r.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("FREEZE_AT_TIME: %v", r)
	}
	select {
	case iin := <-replaced:
		if iin != 0 {
			t.Fatalf("the replacement: IIN %s", iin)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the scheduled freeze did not run")
	}
	eventually(t, "the freeze ended", func() bool { return !runs("(*Server).scheduleFreeze.func") })
	if got := schedules(s); len(got) != 1 || !got[0].Equal(later.Time()) {
		t.Fatalf("schedules %v, want the replacement at %v", got, later.Time())
	}
	if v, _ := db.Get(FrozenCounter, 1); v.(app.Counter).Value != 4 {
		t.Fatalf("frozen counter %v: the freeze did not run", v)
	}
}

// TestFreezeTimerAfterCancel: the timer of a schedule that fires as the
// schedule is cancelled, too late to be stopped, does not freeze: the
// schedule is no longer the current one. The test cancels the schedule as
// cancelFreeze does, then has its timer fire anyway.
func TestFreezeTimerAfterCancel(t *testing.T) {
	m := newMaster(t)
	s := m.srv
	db := s.Database()
	_ = db.AddCounter(1, PointConfig{}, app.Counter{Value: 4, Flags: app.FlagOnline})
	_ = db.AddFrozenCounter(1, PointConfig{}, app.Counter{Flags: app.FlagOnline})
	m.send(freezeReq(1, app.AbsoluteTime{Time: app.TimestampOf(s.Now().Add(time.Hour))}, app.IndexRange(app.G20V0, 1, 1)))
	if r := m.recvFunc(app.FuncResponse); r.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("FREEZE_AT_TIME: %v", r)
	}
	var f *scheduledFreeze
	s.mu.Lock()
	for key, sf := range s.freezes {
		f = sf
		delete(s.freezes, key)
	}
	s.mu.Unlock()
	if f == nil {
		t.Fatal("no schedule")
	}
	f.timer.Reset(0)
	eventually(t, "the timer fired", func() bool {
		if !f.timer.Stop() {
			return true // fired: its function has started
		}
		f.timer.Reset(0)
		return false
	})
	eventually(t, "the timer's function returned", func() bool { return !runs("(*Server).scheduleFreeze.func") })
	if v, _ := db.Get(FrozenCounter, 1); v.(app.Counter).Value != 0 {
		t.Fatalf("frozen counter %v: a cancelled schedule froze", v)
	}
}

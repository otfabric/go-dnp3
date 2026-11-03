// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// wireEvent is one event object of a response.
type wireEvent struct {
	gv    app.GroupVariation
	index uint32
	value app.Value
}

// eventsOf returns the objects of a response in order, skipping CTOs.
func eventsOf(f *app.Fragment) []wireEvent {
	var out []wireEvent
	for _, h := range f.Headers {
		if h.GV.Group() == 51 {
			continue
		}
		for _, o := range h.Objects {
			out = append(out, wireEvent{gv: h.GV, index: o.Index, value: o.Value})
		}
	}
	return out
}

// binaryEvents produces n events of binary input 0, alternating its state
// from on: the first event is off, the second on, and so on.
func binaryEvents(t *testing.T, db *Database, n int) {
	t.Helper()
	for i := range n {
		if err := db.UpdateBinaryInput(0, app.Binary{Value: i%2 == 1, Flags: app.FlagOnline}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLimitedEventRead: a READ of events with a count qualifier (0x07, one
// octet, or 0x08, two octets; IEEE 1815-2012 clause 4.2.2.7.3) returns at
// most that many events, the oldest first. The others stay buffered and
// keep their class's IIN bit set.
func TestLimitedEventRead(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	binaryEvents(t, db, 4)

	count16 := app.Header{GV: app.G60V2, Qualifier: app.Qual2ByteCount, Count: 1}
	cases := []struct {
		name string
		h    app.Header
		want []bool // the states of the events returned
	}{
		{"class 1, one-octet count", app.CountOf(app.G60V2, 1), []bool{false}},
		{"class 1, two-octet count", count16, []bool{true}},
		{"group 2, one-octet count", app.CountOf(app.G2V0, 1), []bool{false}},
		{"group 2, more than buffered", app.CountOf(app.G2V0, 9), []bool{true}},
	}
	seq := uint8(1)
	for i, c := range cases {
		m.send(req(seq, app.FuncRead, c.h))
		f := m.recvFunc(app.FuncResponse)
		evs := eventsOf(f)
		if len(evs) != len(c.want) {
			t.Fatalf("%s: %d events %v, want %d", c.name, len(evs), evs, len(c.want))
		}
		for j, e := range evs {
			if e.index != 0 || e.gv.Group() != 2 || e.value.(app.Binary).Value != c.want[j] {
				t.Fatalf("%s: event %d is %+v, want state %v", c.name, j, e, c.want[j])
			}
		}
		if !f.Control.CON {
			t.Fatalf("%s: event response without CON", c.name)
		}
		last := i == len(cases)-1
		if f.IIN.Has(app.IINClass1Events) == last {
			t.Fatalf("%s: IIN %s with %d events left", c.name, f.IIN, 3-i)
		}
		m.send(confirm(seq, false))
		seq++
	}
	m.send(req(seq, app.FuncRead, app.ClassHeaders(1)...))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 || f.IIN.Has(app.IINClass1Events) {
		t.Fatalf("after the limited reads: %s", f)
	}
}

// TestEventReadCountZero: a count of zero names no event; the events stay
// buffered and indicated.
func TestEventReadCountZero(t *testing.T) {
	m := newMaster(t)
	binaryEvents(t, m.srv.Database(), 2)
	for i, h := range []app.Header{app.CountOf(app.G60V2, 0), app.CountOf(app.G2V0, 0),
		{GV: app.G2V2, Qualifier: app.Qual2ByteCount}, {GV: app.G60V2, Qualifier: app.Qual4ByteCount}} {
		m.send(req(uint8(i+1), app.FuncRead, h))
		f := m.recvFunc(app.FuncResponse)
		if len(f.Headers) != 0 || f.Control.CON || !f.IIN.Has(app.IINClass1Events) {
			t.Fatalf("count 0 (%s %s): %s", h.GV, h.Qualifier, f)
		}
	}
	m.send(req(9, app.FuncRead, app.ClassHeaders(1)...))
	if f := m.recvFunc(app.FuncResponse); len(eventsOf(f)) != 2 {
		t.Fatalf("events after the count 0 reads: %s", f)
	}
}

// TestLimitedEventReadUnconfirmed: the events of a limited read that is not
// confirmed are reported again, still the oldest first.
func TestLimitedEventReadUnconfirmed(t *testing.T) {
	m := newMaster(t)
	binaryEvents(t, m.srv.Database(), 3)
	for seq := uint8(1); seq <= 2; seq++ {
		m.send(req(seq, app.FuncRead, app.CountOf(app.G60V2, 2)))
		f := m.recvFunc(app.FuncResponse)
		evs := eventsOf(f)
		if len(evs) != 2 || evs[0].value.(app.Binary).Value || !evs[1].value.(app.Binary).Value {
			t.Fatalf("read %d: %v", seq, evs)
		}
		if !f.IIN.Has(app.IINClass1Events) {
			t.Fatalf("read %d: the third event is not indicated: %s", seq, f.IIN)
		}
	}
}

// TestEventReadByGroup: a READ of an event group returns the events of that
// group only, of every class, and leaves the others buffered: the object
// header names the objects requested (IEEE 1815-2012 clause 4.2.2.7).
func TestEventReadByGroup(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	if err := db.AddBinaryInput(2, PointConfig{Class: 3}, app.Binary{Flags: app.FlagOnline}); err != nil {
		t.Fatal(err)
	}
	// In order: BI 0 (class 1), AI 0 (class 2), BI 2 (class 3), counter 0
	// (class 3), BI 1 (class 1).
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 6, Flags: app.FlagOnline})
	_ = db.UpdateBinaryInput(2, app.Binary{Value: true, Flags: app.FlagOnline})
	_ = db.UpdateCounter(0, app.Counter{Value: 2, Flags: app.FlagOnline})
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})

	m.send(req(1, app.FuncRead, app.AllObjects(app.G2V0)))
	f := m.recvFunc(app.FuncResponse)
	evs := eventsOf(f)
	if len(evs) != 3 || evs[0].index != 0 || evs[1].index != 2 || evs[2].index != 1 {
		t.Fatalf("group 2 read: %v", evs)
	}
	for _, e := range evs {
		if e.gv != app.G2V2 {
			t.Fatalf("group 2 read returned %s", e.gv)
		}
	}
	// The other events are still there: IIN1.2 and IIN1.3.
	if f.IIN.Has(app.IINClass1Events) || !f.IIN.Has(app.IINClass2Events) || !f.IIN.Has(app.IINClass3Events) {
		t.Fatalf("IIN %s after the group 2 read", f.IIN)
	}
	m.send(confirm(1, false))

	m.send(req(2, app.FuncRead, app.AllObjects(app.G32V0)))
	f = m.recvFunc(app.FuncResponse)
	if evs := eventsOf(f); len(evs) != 1 || evs[0].gv.Group() != 32 || evs[0].index != 0 {
		t.Fatalf("group 32 read: %v", evs)
	}
	m.send(confirm(2, false))

	m.send(req(3, app.FuncRead, app.ClassHeaders(1, 2, 3)...))
	f = m.recvFunc(app.FuncResponse)
	if evs := eventsOf(f); len(evs) != 1 || evs[0].gv.Group() != 22 {
		t.Fatalf("class poll after the group reads: %v", evs)
	}
	m.send(confirm(3, false))
}

// TestBinaryInputEventVariations: a READ of g2v1, g2v2 or g2v3 is answered
// in that variation: without time, with absolute time, and with time
// relative to a preceding CTO (g51) that adds up to the event's time
// (IEEE 1815-2012 Annex A, groups 2 and 51). The configured event variation
// is used for class polls and g2v0.
func TestBinaryInputEventVariations(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	at := app.Timestamp(1_700_000_000_123)
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline, Time: at})

	// Unconfirmed, the same event is reported again by each read.
	m.send(req(1, app.FuncRead, app.AllObjects(app.G2V1)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G2V1 || f.Headers[0].Objects[0].Value.(app.Binary).Time != 0 {
		t.Fatalf("g2v1: %s", f)
	}
	m.send(req(2, app.FuncRead, app.AllObjects(app.G2V2)))
	f = m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G2V2 || f.Headers[0].Objects[0].Value.(app.Binary).Time != at {
		t.Fatalf("g2v2: %s", f)
	}
	m.send(req(3, app.FuncRead, app.AllObjects(app.G2V3)))
	f = m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 2 || f.Headers[0].GV != app.G51V1 || f.Headers[1].GV != app.G2V3 {
		t.Fatalf("g2v3: %s", f)
	}
	// The decoder adds the 16-bit relative time to the CTO.
	cto := f.Headers[0].Objects[0].Value.(app.CTO).Time
	got := f.Headers[1].Objects[0].Value.(app.Binary).Time
	if cto > at || at-cto > 0xFFFF || got != at {
		t.Fatalf("g2v3: CTO %d and time %d for an event at %d", cto, got, at)
	}
	m.send(confirm(3, false))

	// A point configured for g2v1 or g2v3 is reported so in a class poll.
	for _, v := range []uint8{1, 3} {
		srv := m.srv
		_ = srv.Database().Remove(BinaryInput, 5)
		if err := srv.Database().AddBinaryInput(5, PointConfig{Class: 1, EventVariation: v}, app.Binary{Flags: app.FlagOnline}); err != nil {
			t.Fatal(err)
		}
		_ = srv.Database().UpdateBinaryInput(5, app.Binary{Value: true, Flags: app.FlagOnline, Time: at})
		seq := 10 + v
		m.send(req(seq, app.FuncRead, app.ClassHeaders(1)...))
		f = m.recvFunc(app.FuncResponse)
		evs := eventsOf(f)
		if len(evs) != 1 || evs[0].gv != app.GV(2, v) {
			t.Fatalf("configured g2v%d: %s", v, f)
		}
		if v == 3 && f.Headers[0].GV != app.G51V1 {
			t.Fatalf("configured g2v3 without a CTO: %s", f)
		}
		m.send(confirm(seq, false))
	}
}

// TestPerPointEventClass: a point's event class decides the class its
// events are reported in; a point in class 0 produces no event at all but
// is still reported in class 0. ASSIGN_CLASS (IEEE 1815-2012 Table 4-1)
// changes it, and an event after it reports a change from the value the
// point has, not from the one it had when it was added.
func TestPerPointEventClass(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	if err := db.AddBinaryInput(7, PointConfig{Class: 0}, app.Binary{Flags: app.FlagOnline}); err != nil {
		t.Fatal(err)
	}
	_ = db.UpdateBinaryInput(7, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.ClassHeaders(1, 2, 3)...))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 0 || f.IIN&(app.IINClass1Events|app.IINClass2Events|app.IINClass3Events) != 0 {
		t.Fatalf("class 0 point produced an event: %s", f)
	}
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	f = m.recvFunc(app.FuncResponse)
	found := false
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			if h.GV.Group() == 1 && o.Index == 7 && o.Value.(app.Binary).Value {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("class 0 point missing from the class 0 poll: %s", f)
	}

	// ASSIGN_CLASS moves it to class 2 and binary input 0 to class 0.
	m.send(req(3, app.FuncAssignClass, app.AllObjects(app.G60V3), app.IndexRange(app.G1V0, 7, 7),
		app.AllObjects(app.G60V1), app.IndexRange(app.G1V0, 0, 0)))
	if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("assign class: %s", f.IIN)
	}
	_ = db.UpdateBinaryInput(7, app.Binary{Flags: app.FlagOnline})
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	m.send(req(4, app.FuncRead, app.ClassHeaders(1)...))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
		t.Fatalf("class 1 after the assignment: %s", f)
	}
	m.send(req(5, app.FuncRead, app.ClassHeaders(2)...))
	f = m.recvFunc(app.FuncResponse)
	if evs := eventsOf(f); len(evs) != 1 || evs[0].gv.Group() != 2 || evs[0].index != 7 {
		t.Fatalf("class 2 after the assignment: %v", evs)
	}
	m.send(confirm(5, false))
}

// TestClass0Exclusion: a point configured out of class 0 is left out of a
// class 0 poll, for every static type, and is still returned by a READ of
// its group (PointConfig.ExcludeFromClass0).
func TestClass0Exclusion(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	out := PointConfig{ExcludeFromClass0: true}
	on := app.FlagOnline
	adds := []struct {
		t     PointType
		group uint8
		add   func() error
	}{
		{BinaryInput, 1, func() error { return db.AddBinaryInput(9, out, app.Binary{Flags: on}) }},
		{DoubleBitInput, 3, func() error { return db.AddDoubleBitInput(9, out, app.DoubleBitBinary{Flags: on}) }},
		{BinaryOutput, 10, func() error { return db.AddBinaryOutput(9, out, app.Binary{Flags: on}) }},
		{Counter, 20, func() error { return db.AddCounter(9, out, app.Counter{Flags: on}) }},
		{FrozenCounter, 21, func() error { return db.AddFrozenCounter(9, out, app.Counter{Flags: on}) }},
		{AnalogInput, 30, func() error { return db.AddAnalogInput(9, out, app.Analog{Flags: on}) }},
		{FrozenAnalogInput, 31, func() error { return db.AddFrozenAnalogInput(9, out, app.Analog{Flags: on}) }},
		{AnalogOutput, 40, func() error { return db.AddAnalogOutput(9, out, app.Analog{Flags: on}) }},
		{OctetString, 110, func() error { return db.AddOctetString(9, out, []byte{1}) }},
	}
	for _, a := range adds {
		if err := a.add(); err != nil {
			t.Fatalf("%s: %v", a.t, err)
		}
	}
	m.send(req(1, app.FuncRead, app.ClassHeaders(0)...))
	f := m.recvFunc(app.FuncResponse)
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			if o.Index == 9 {
				t.Fatalf("excluded point %s %d in the class 0 poll", h.GV, o.Index)
			}
		}
	}
	// The binary and analog inputs and the counter of newMaster are there.
	if len(f.Headers) < 3 {
		t.Fatalf("class 0 poll: %s", f)
	}
	for i, a := range adds {
		seq := uint8(2 + i)
		m.send(req(seq, app.FuncRead, app.IndexRange(app.GV(a.group, 0), 9, 9)))
		f := m.recvFunc(app.FuncResponse)
		if len(f.Headers) != 1 || f.Headers[0].GV.Group() != a.group || len(f.Headers[0].Objects) != 1 || f.Headers[0].Objects[0].Index != 9 {
			t.Fatalf("READ of the excluded %s: %s", a.t, f)
		}
	}
}

// TestEventResponseConfirmation: a response that carries events asks for
// confirmation (CON) and one without events does not (IEEE 1815-2012
// clause 4.2.2.4.3); the events stay buffered until confirmed and a
// confirmation removes exactly the events of the response it confirms, not
// events buffered since.
func TestEventResponseConfirmation(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	m.send(req(1, app.FuncRead, app.ClassHeaders(1, 2, 3)...))
	if f := m.recvFunc(app.FuncResponse); f.Control.CON || len(f.Headers) != 0 {
		t.Fatalf("response without events: %s", f)
	}
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.Control.CON {
		t.Fatalf("class 0 response asks for confirmation: %s", f)
	}

	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline}) // A
	m.send(req(3, app.FuncRead, app.ClassHeaders(1)...))
	f := m.recvFunc(app.FuncResponse)
	if !f.Control.CON || len(eventsOf(f)) != 1 {
		t.Fatalf("event response: %s", f)
	}
	// B is buffered while A waits for its confirmation.
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(confirm(3, false))
	m.send(req(4, app.FuncRead, app.ClassHeaders(1)...))
	f = m.recvFunc(app.FuncResponse)
	if evs := eventsOf(f); len(evs) != 1 || evs[0].index != 1 || !evs[0].value.(app.Binary).Value {
		t.Fatalf("after confirming A: %v", evs)
	}
	m.send(confirm(4, false))
}

// TestNoAckFunctionsUnanswered: the no-acknowledgement functions are never
// answered, whether they succeed or fail (IEEE 1815-2012 clause 4.2.2.5,
// Table 4-1: IMMED_FREEZE_NR, FREEZE_CLEAR_NR and FREEZE_AT_TIME_NR), and
// they are executed.
func TestNoAckFunctionsUnanswered(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	if err := db.AddFrozenCounter(0, PointConfig{}, app.Counter{Flags: app.FlagOnline}); err != nil {
		t.Fatal(err)
	}
	_ = db.UpdateCounter(0, app.Counter{Value: 42, Flags: app.FlagOnline})
	now := app.AbsoluteTime{Time: 0, Interval: 0}
	cases := []struct {
		name string
		f    *app.Fragment
	}{
		{"FREEZE_AT_TIME_NR now", req(1, app.FuncFreezeAtTimeNoAck, app.Counted(app.G50V2, now), app.AllObjects(app.G20V0))},
		{"FREEZE_AT_TIME_NR without time", req(2, app.FuncFreezeAtTimeNoAck, app.AllObjects(app.G20V0))},
		{"FREEZE_AT_TIME_NR passed time", req(3, app.FuncFreezeAtTimeNoAck,
			app.Counted(app.G50V2, app.AbsoluteTime{Time: app.TimestampOf(time.Unix(1, 0))}), app.AllObjects(app.G20V0))},
		{"FREEZE_AT_TIME_NR unknown object", req(4, app.FuncFreezeAtTimeNoAck, app.Counted(app.G50V2, now), app.AllObjects(app.G1V0))},
		{"IMMED_FREEZE_NR", req(5, app.FuncImmediateFreezeNoAck, app.AllObjects(app.G20V0))},
		{"FREEZE_CLEAR_NR", req(6, app.FuncFreezeClearNoAck, app.AllObjects(app.G20V0))},
	}
	for _, c := range cases {
		m.send(c.f)
		m.none(150 * time.Millisecond)
	}
	// The undecodable form: FREEZE_AT_TIME_NR with a truncated time.
	m.sendRaw([]byte{0xC7, 0x0C, 0x32, 0x02, 0x07, 0x01, 0x00, 0x00})
	m.none(150 * time.Millisecond)

	// They were executed: frozen at 42, then the counter cleared.
	if v, _ := db.Get(FrozenCounter, 0); v.(app.Counter).Value != 42 {
		t.Fatalf("frozen counter %v", v)
	}
	if v, _ := db.Get(Counter, 0); v.(app.Counter).Value != 0 {
		t.Fatalf("counter after FREEZE_CLEAR_NR %v", v)
	}
	// The outstation still answers.
	m.send(req(8, app.FuncRead, app.ClassHeaders(0)...))
	m.recvFunc(app.FuncResponse)
}

type restarter struct {
	NopHandler
	mu    sync.Mutex
	delay time.Duration
	cold  []bool
}

func (r *restarter) Restart(_ context.Context, cold bool) (time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cold = append(r.cold, cold)
	return r.delay, nil
}

func (r *restarter) set(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delay = d
}

func (r *restarter) calls() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.cold...)
}

// TestColdRestartResponse: COLD_RESTART and WARM_RESTART are answered with
// the time until the outstation is available again, g52v2 below 65.536 s
// and g52v1 above (IEEE 1815-2012 Table 4-1, Annex A group 52); without a
// RestartHandler, with NO_FUNC_CODE_SUPPORT. After the restart the
// outstation reports DEVICE_RESTART (IIN1.7) again.
func TestColdRestartResponse(t *testing.T) {
	m := newMaster(t)
	m.send(req(1, app.FuncColdRestart))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINNoFuncCodeSupport) || len(f.Headers) != 0 {
		t.Fatalf("without a handler: %s", f)
	}

	r := &restarter{}
	r.set(1500 * time.Millisecond)
	m = newMaster(t, WithHandler(r))
	// Clear IIN1.7 first.
	m.send(req(1, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("IIN1.7 not cleared: %s", f.IIN)
	}
	m.send(req(2, app.FuncColdRestart))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G52V2 || f.Headers[0].Objects[0].Value.(app.TimeDelay).Delay != 1500*time.Millisecond {
		t.Fatalf("cold restart: %s", f)
	}
	r.set(70 * time.Second)
	m.send(req(3, app.FuncWarmRestart))
	f = m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G52V1 || f.Headers[0].Objects[0].Value.(app.TimeDelay).Delay != 70*time.Second {
		t.Fatalf("warm restart: %s", f)
	}
	if cold := r.calls(); len(cold) != 2 || !cold[0] || cold[1] {
		t.Fatalf("handler saw %v", cold)
	}
	// The application restarts: IIN1.7 is reported again.
	m.srv.Restart()
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("after Restart: %s", f.IIN)
	}
}

// TestUnsolicitedEventsKeptUntilConfirmed: an unsolicited response asks for
// confirmation (CON and UNS, IEEE 1815-2012 clause 4.2.2.4.3); until it
// comes, its events are kept and repeated, and once it comes they are gone
// while a later event is reported in the next one.
func TestUnsolicitedEventsKeptUntilConfirmed(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1}, Retries: -1}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	u := m.recvFunc(app.FuncUnsolicitedResponse)
	if !u.Control.CON || !u.Control.UNS || len(eventsOf(u)) != 1 {
		t.Fatalf("unsolicited response %s", u)
	}
	// Not confirmed: repeated with the same event.
	again := m.recvFunc(app.FuncUnsolicitedResponse)
	if evs := eventsOf(again); again.Control.Seq != u.Control.Seq || len(evs) != 1 || evs[0].index != 1 {
		t.Fatalf("repeat %s", again)
	}
	m.send(confirm(u.Control.Seq, true))
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	next := m.recvFunc(app.FuncUnsolicitedResponse)
	if evs := eventsOf(next); next.Control.Seq != app.NextSeq(u.Control.Seq) || len(evs) != 1 || evs[0].index != 0 {
		t.Fatalf("after the confirmation: %s", next)
	}
	m.send(confirm(next.Control.Seq, true))
}

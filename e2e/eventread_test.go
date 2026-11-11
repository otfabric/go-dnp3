// SPDX-License-Identifier: MIT

package e2e

import (
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// TestLimitedEventReadsDrainInOrder: a master that reads events a few at a
// time (count qualifier, IEEE 1815-2012 clause 4.2.2.7.3) and confirms each
// response receives every event once, in the order they occurred, and
// stops when the outstation no longer indicates class 1 events (IIN1.1).
func TestLimitedEventReadsDrainInOrder(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	const n = 23
	for i := range n {
		_ = p.db.UpdateBinaryInput(uint32(i%5), app.Binary{Value: i%2 == 1, Flags: app.FlagOnline, Time: app.Timestamp(1_000 + i)})
	}
	var got []client.Measurement
	for reads := 0; ; reads++ {
		if reads > n {
			t.Fatal("events not drained")
		}
		res, err := p.c.Read(c, app.CountOf(app.G60V2, 4))
		if err != nil {
			t.Fatal(err)
		}
		ms := res.Measurements()
		if len(ms) > 4 {
			t.Fatalf("read %d: %d events for a count of 4", reads, len(ms))
		}
		got = append(got, ms...)
		if !res.IIN.Has(app.IINClass1Events) {
			break
		}
	}
	if len(got) != n {
		t.Fatalf("%d events, want %d", len(got), n)
	}
	for i, m := range got {
		b := m.Value.(app.Binary)
		if m.Index != uint32(i%5) || b.Time != app.Timestamp(1_000+i) {
			t.Fatalf("event %d: index %d time %d", i, m.Index, b.Time)
		}
	}
}

// TestEventReadByGroupAcrossClasses: a READ of one event group returns the
// events of that group in every class and leaves the others for the class
// poll that follows.
func TestEventReadByGroupAcrossClasses(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	if err := p.c.AssignClass(c, 3, app.IndexRange(app.G1V0, 4, 4)); err != nil {
		t.Fatal(err)
	}
	_ = p.db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})             // class 1
	_ = p.db.UpdateAnalogInput(0, app.Analog{Value: 9, Flags: app.FlagOnline})   // class 2
	_ = p.db.UpdateBinaryInput(4, app.Binary{Flags: app.FlagOnline})             // class 3
	_ = p.db.UpdateCounter(0, app.Counter{Value: 101, Flags: app.FlagOnline})    // class 3
	_ = p.db.UpdateDoubleBitInput(0, app.DoubleBitBinary{Flags: app.FlagOnline}) // class 1

	res, err := p.c.Read(c, app.AllObjects(app.G2V1))
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if len(ms) != 2 || ms[0].Index != 0 || ms[1].Index != 4 || ms[0].GV != app.G2V1 || ms[1].GV != app.G2V1 {
		t.Fatalf("group 2 read: %v", gvs(ms))
	}
	res, err = p.c.EventPoll(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := gvs(res.Measurements()); len(got) != 3 || got[0] != "g32v7" || got[1] != "g22v5" || got[2] != "g4v2" {
		t.Fatalf("event poll after the group read: %v", got)
	}
}

// TestAssignedClassReportsCurrentChange: a point added without an event
// class and given one later by ASSIGN_CLASS reports the next change of its
// value, measured from the value the master reads, not from the one it was
// added with.
func TestAssignedClassReportsCurrentChange(t *testing.T) {
	p := newPair(t, func(db *server.Database) {
		_ = db.AddBinaryInput(0, server.PointConfig{}, app.Binary{Flags: app.FlagOnline})
		_ = db.AddAnalogInput(0, server.PointConfig{Deadband: 5}, app.Analog{Flags: app.FlagOnline})
	}, nil)
	c := ctx(t)
	_ = p.db.UpdateBinaryInput(0, app.Binary{Value: true, Flags: app.FlagOnline})
	_ = p.db.UpdateAnalogInput(0, app.Analog{Value: 100, Flags: app.FlagOnline})
	if res, _ := p.c.EventPoll(c); len(res.Measurements()) != 0 {
		t.Fatalf("events of points without a class: %v", gvs(res.Measurements()))
	}
	if err := p.c.AssignClass(c, 1, app.AllObjects(app.G1V0), app.AllObjects(app.G30V0)); err != nil {
		t.Fatal(err)
	}
	// Back to the values they were added with: a change of what the
	// master reads now, above the deadband.
	_ = p.db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	_ = p.db.UpdateAnalogInput(0, app.Analog{Value: 0, Flags: app.FlagOnline})
	res, err := p.c.EventPoll(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := gvs(res.Measurements()); len(got) != 2 || got[0] != "g2v2" || got[1] != "g32v3" {
		t.Fatalf("events after ASSIGN_CLASS: %v", got)
	}
}

// TestAnalogOutputStatusOutOfClass0: analog output status (g40) configured
// out of class 0 is left out of the integrity poll and read by group, and an
// update of it reports no g42 event: an output event is generated only for
// a point a class 0 response returns (IEEE 1815-2012 A.21.1.1, p. 620). The
// same point in class 0 reports one.
func TestAnalogOutputStatusOutOfClass0(t *testing.T) {
	p := newPair(t, func(db *server.Database) {
		_ = db.AddAnalogInput(0, server.PointConfig{Class: 2}, app.Analog{Value: 1, Flags: app.FlagOnline})
		_ = db.AddAnalogOutput(0, server.PointConfig{Class: 2, ExcludeFromClass0: true, StaticVariation: 3}, app.Analog{Value: 2.5, Flags: app.FlagOnline})
		_ = db.AddAnalogOutput(1, server.PointConfig{Class: 2, StaticVariation: 3}, app.Analog{Value: 2.5, Flags: app.FlagOnline})
	}, nil)
	c := ctx(t)
	res, err := p.c.IntegrityPoll(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := gvs(res.Measurements()); len(got) != 2 || got[0] != "g30v1" || got[1] != "g40v3" {
		t.Fatalf("integrity poll: %v", got)
	}
	res, err = p.c.Read(c, app.IndexRange(app.G40V0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if ms := res.Measurements(); len(ms) != 1 || ms[0].GV != app.G40V3 || ms[0].Value.(app.Analog).Value != 2.5 {
		t.Fatalf("g40 read: %v", ms)
	}
	_ = p.db.UpdateAnalogOutput(0, app.Analog{Value: 4, Flags: app.FlagOnline})
	_ = p.db.UpdateAnalogOutput(1, app.Analog{Value: 5, Flags: app.FlagOnline})
	res, err = p.c.EventPoll(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ms := res.Measurements(); len(ms) != 1 || ms[0].GV != app.G42V3 || ms[0].Index != 1 || ms[0].Value.(app.Analog).Value != 5 {
		t.Fatalf("g42 events: %v", gvs(ms))
	}
}

// TestOfflineFlagsReported: a point marked offline keeps its index, its
// flags are reported in class 0 (in a variation with flags) and the change
// to offline is an event.
func TestOfflineFlagsReported(t *testing.T) {
	p := newPair(t, func(db *server.Database) {
		for i := range uint32(3) {
			_ = db.AddBinaryInput(i, server.PointConfig{Class: 1, StaticVariation: 1}, app.Binary{Flags: app.FlagOnline})
		}
	}, nil)
	c := ctx(t)
	_ = p.db.UpdateBinaryInput(1, app.Binary{}) // ONLINE cleared
	res, err := p.c.IntegrityPoll(c)
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if len(ms) != 4 { // three statics, one event
		t.Fatalf("integrity poll: %v", gvs(ms))
	}
	var statics []client.Measurement
	for _, m := range ms {
		if !m.Event {
			statics = append(statics, m)
		} else if m.Index != 1 || m.Value.(app.Binary).Flags&app.FlagOnline != 0 {
			t.Fatalf("offline event: %+v", m)
		}
	}
	// The points are configured packed (g1v1, no flags); the offline one
	// is reported with its flags instead.
	for i, m := range statics {
		want := app.G1V1
		if i == 1 {
			want = app.G1V2
		}
		if m.Index != uint32(i) || m.GV != want {
			t.Fatalf("static %d: %s %+v", i, m.GV, m.Value)
		}
		if i == 1 && m.Value.(app.Binary).Flags&app.FlagOnline != 0 {
			t.Fatalf("offline point reported online: %+v", m.Value)
		}
	}
}

// TestNoAckFreezeAtTime: FREEZE_AT_TIME_NR is executed without a response
// (IEEE 1815-2012 Table 4-1), so the master does not wait for one.
func TestNoAckFreezeAtTime(t *testing.T) {
	p := newPair(t, fullDatabase, nil, client.WithResponseTimeout(time.Second))
	c := ctx(t)
	start := time.Now()
	_, err := p.c.Request(c, app.FuncFreezeAtTimeNoAck, app.Counted(app.G50V2, app.AbsoluteTime{}), app.AllObjects(app.G20V0))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("FREEZE_AT_TIME_NR took %v: the master waited for a response", d)
	}
	waitUntil(t, "frozen counter", func() bool {
		v, _ := p.db.Get(server.FrozenCounter, 0)
		return v.(app.Counter).Value == 100
	})
	// The outstation answers the next request as usual.
	if _, err := p.c.IntegrityPoll(c); err != nil {
		t.Fatal(err)
	}
}

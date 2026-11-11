// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// Spec tests of freezes, point data and device attributes at the
// outstation (IEEE 1815-2012 4.4.8, 5.5, 11.9 and Annex A).

// schedules returns the FREEZE_AT_TIME schedules by first time.
func schedules(s *Server) []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []time.Time
	for _, f := range s.freezes {
		out = append(out, f.first)
	}
	return out
}

func freezeReq(seq uint8, at app.AbsoluteTime, hs ...app.Header) *app.Fragment {
	return req(seq, app.FuncFreezeAtTime, append([]app.Header{app.Counted(app.G50V2, at)}, hs...)...)
}

// TestSpecTable4_11_FreezeAtTime: Table 4-11 (pp. 56-57): time 0 and an
// interval freeze every interval from the beginning of the current hour;
// time 0 and interval 0 freeze at once; a time of all ones cancels; and a
// periodic schedule continues until a new FREEZE_AT_TIME for its points,
// which replaces it. Every schedule of a request is checked before any is
// applied.
func TestSpecTable4_11_FreezeAtTime(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddCounter(1, PointConfig{}, app.Counter{Value: 4, Flags: app.FlagOnline})
	_ = db.AddFrozenCounter(0, PointConfig{}, app.Counter{Flags: app.FlagOnline})
	ok := func(f *app.Fragment) {
		t.Helper()
		if r := m.recvFunc(app.FuncResponse); r.IIN&app.IINRequestErrors != 0 {
			t.Fatalf("%s: %s", f, r)
		}
	}
	send := func(f *app.Fragment) { t.Helper(); m.send(f); ok(f) }

	// Time 0, interval 7 minutes: from the start of the hour.
	const interval = 7 * time.Minute
	before := m.srv.Now()
	send(freezeReq(1, app.AbsoluteTime{Interval: uint32(interval.Milliseconds())}, app.IndexRange(app.G20V0, 0, 0)))
	after := m.srv.Now()
	got := schedules(m.srv)
	if len(got) != 1 {
		t.Fatalf("%d schedules", len(got))
	}
	first := got[0]
	onGrid := func(base time.Time) bool { return first.Sub(base)%interval == 0 }
	if first.Before(before) || first.After(after.Add(interval)) || (!onGrid(before.Truncate(time.Hour)) && !onGrid(after.Truncate(time.Hour))) {
		t.Fatalf("first freeze at %v, requested between %v and %v", first, before, after)
	}

	// A new FREEZE_AT_TIME for the same points replaces the schedule.
	inTwoHours := m.srv.Now().Add(2 * time.Hour).Truncate(time.Millisecond)
	send(freezeReq(2, app.AbsoluteTime{Time: app.TimestampOf(inTwoHours)}, app.IndexRange(app.G20V0, 0, 0)))
	if got := schedules(m.srv); len(got) != 1 || !got[0].Equal(inTwoHours) {
		t.Fatalf("after the replacement: %v, want %v", got, inTwoHours)
	}

	// Two schedules in one request, for other points.
	inAnHour := app.TimestampOf(m.srv.Now().Add(time.Hour))
	send(freezeReq(3, app.AbsoluteTime{Time: inAnHour}, app.IndexRange(app.G20V0, 1, 1),
		app.Counted(app.G50V2, app.AbsoluteTime{Time: inAnHour, Interval: 1000}), app.IndexRange(app.G20V0, 2, 2)))
	if n := len(schedules(m.srv)); n != 3 {
		t.Fatalf("%d schedules after a request with two", n)
	}

	// All ones cancels the schedule of the points.
	send(freezeReq(4, app.AbsoluteTime{Time: app.MaxTimestamp}, app.IndexRange(app.G20V0, 0, 0)))
	if n := len(schedules(m.srv)); n != 2 {
		t.Fatalf("%d schedules after a cancel", n)
	}

	// A request with one bad schedule applies none.
	m.send(freezeReq(5, app.AbsoluteTime{Time: inAnHour}, app.IndexRange(app.G20V0, 5, 5),
		app.Counted(app.G50V2, app.AbsoluteTime{Time: inAnHour}), app.AllObjects(app.G1V0)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) || len(schedules(m.srv)) != 2 {
		t.Fatalf("a request with a bad schedule: %s, %d schedules", f, len(schedules(m.srv)))
	}

	// Time 0, interval 0: at once.
	send(freezeReq(6, app.AbsoluteTime{}, app.IndexRange(app.G20V0, 1, 1)))
	if v, _ := db.Get(FrozenCounter, 0); v.(app.Counter).Value != 0 {
		t.Fatalf("frozen counter 0 changed: %v", v)
	}
	if n := len(schedules(m.srv)); n != 1 {
		t.Fatalf("%d schedules: a freeze at once ends the schedule of its points", n)
	}
}

// TestSpecTable12_14_FreezeClearOfAnalogInputs: freeze-and-clear applies
// to counters. The guideline lists function codes 9 and 10 for g20v0
// (Table 12-10, p. 355), not for g30v0 (Table 12-14, p. 356): an analog
// input header is an object the function does not support (IIN2.1,
// Table 4-14, p. 85), and nothing is frozen.
func TestSpecTable12_14_FreezeClearOfAnalogInputs(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddFrozenAnalogInput(0, PointConfig{}, app.Analog{Flags: app.FlagOnline})
	for i, fc := range []app.FunctionCode{app.FuncFreezeClear, app.FuncFreezeClearNoAck} {
		m.send(req(uint8(i+1), fc, app.AllObjects(app.G30V0)))
	}
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("FREEZE_CLEAR of g30: %s", f)
	}
	m.send(req(3, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 {
		t.Fatalf("the no-ack request was answered: %s", f)
	}
	if v, _ := db.Get(FrozenAnalogInput, 0); v.(app.Analog).Value != 0 {
		t.Fatalf("frozen: %v", v)
	}
}

// TestSpec11_9_1_2_FrozenAnalogEventAtEveryFreeze: 11.9.1.2 (p. 333): a
// frozen analog input event is generated at every freeze, also when the
// value did not change.
func TestSpec11_9_1_2_FrozenAnalogEventAtEveryFreeze(t *testing.T) {
	m := newMaster(t)
	_ = m.srv.Database().AddFrozenAnalogInput(0, PointConfig{Class: 1}, app.Analog{Flags: app.FlagOnline})
	for i := range uint8(3) {
		m.send(req(2*i+1, app.FuncImmediateFreeze, app.AllObjects(app.G30V0)))
		m.recvFunc(app.FuncResponse)
		m.send(req(2*i+2, app.FuncRead, app.AllObjects(app.G60V2)))
		f := m.recvFunc(app.FuncResponse)
		if len(f.Headers) != 1 || f.Headers[0].GV.Group() != 33 || len(f.Headers[0].Objects) != 1 || f.Headers[0].Objects[0].Value.(app.Analog).Value != 5 {
			t.Fatalf("freeze %d: %s", i+1, f)
		}
		m.send(confirm(2*i+2, false))
	}
}

// TestSpecA_23_1_2_3_ReadTimeAndDate: A.23.1.2.3 (p. 648): outstations
// shall answer a READ of g50v1 with qualifier 0x07 and count 1 with their
// current time. Another count or qualifier is one the outstation does not
// support: IIN2.2 (4.5.11, p. 85).
func TestSpecA_23_1_2_3_ReadTimeAndDate(t *testing.T) {
	m := newMaster(t)
	before := app.TimestampOf(m.srv.Now())
	m.send(req(1, app.FuncRead, app.CountOf(app.G50V1, 1)))
	f := m.recvFunc(app.FuncResponse)
	after := app.TimestampOf(m.srv.Now())
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G50V1 || f.Headers[0].Qualifier != app.Qual1ByteCount || len(f.Headers[0].Objects) != 1 {
		t.Fatalf("READ g50v1: %s", f)
	}
	if at := f.Headers[0].Objects[0].Value.(app.AbsoluteTime).Time; at < before || at > after {
		t.Fatalf("time %d, read between %d and %d", at, before, after)
	}

	// After a WRITE of the time, the time written.
	set := app.TimestampOf(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	m.send(req(2, app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: set})))
	m.recvFunc(app.FuncResponse)
	m.send(req(3, app.FuncRead, app.CountOf(app.G50V1, 1)))
	f = m.recvFunc(app.FuncResponse)
	if at := f.Headers[0].Objects[0].Value.(app.AbsoluteTime).Time; at < set || at > set+5_000 {
		t.Fatalf("time %d after writing %d", at, set)
	}

	for i, h := range []app.Header{app.CountOf(app.G50V1, 2), app.AllObjects(app.G50V1), app.IndexRange(app.G50V1, 0, 0)} {
		m.send(req(uint8(4+i), app.FuncRead, h))
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) || f.IIN.Has(app.IINObjectUnknown) || len(f.Headers) != 0 {
			t.Fatalf("READ g50v1 with qualifier %#x count %d: %s", uint8(h.Qualifier), h.Count, f)
		}
	}
}

// TestSpec4_2_2_7_2_2_PackedReadByIndex: a packed variation (g1v1, g10v1)
// has no index form; read by index, the points are reported in the
// variation with flags (4.2.2.7.2.2, p. 31; 11.6.5).
func TestSpec4_2_2_7_2_2_PackedReadByIndex(t *testing.T) {
	m := newMaster(t)
	m.send(req(1, app.FuncRead, app.IndexList(app.G1V1, 0, 1)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G1V2 || !f.Headers[0].Qualifier.IsIndexed() || len(f.Headers[0].Objects) != 2 {
		t.Fatalf("READ g1v1 by index: %s", f)
	}
	m.send(req(2, app.FuncRead, app.IndexRange(app.G1V1, 0, 1)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || f.Headers[0].GV != app.G1V1 {
		t.Fatalf("READ g1v1 by range: %s", f)
	}
}

// TestSpecA_41_1_OctetStringOfOtherLength: A.41.1 (p. 715): the variation
// of an octet string is its length. A READ naming another length is
// answered with the string in the variation of its own length.
func TestSpecA_41_1_OctetStringOfOtherLength(t *testing.T) {
	m := newMaster(t)
	_ = m.srv.Database().Add(OctetString, 0, PointConfig{}, app.OctetString{Data: []byte{1, 2}})
	m.send(req(1, app.FuncRead, app.IndexRange(app.GV(110, 5), 0, 0)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.GV(110, 2) {
		t.Fatalf("READ g110v5 of a 2-octet string: %s", f)
	}
}

// TestSpecA_18_3_2_3_DeadbandIntegerOnly: A.18.3.2.3 (pp. 608-609):
// outstations shall provide a configuration option for integer-only
// deadbands, without variation 3. With WithDeadbandIntegerOnly a deadband
// is rounded, a READ of g34v3 is IIN2.1, and g34v0 reads the integers.
func TestSpecA_18_3_2_3_DeadbandIntegerOnly(t *testing.T) {
	m := newMaster(t, WithDeadbandIntegerOnly(true))
	db := m.srv.Database()
	_ = db.AddAnalogInput(1, PointConfig{Deadband: 2.5}, app.Analog{Flags: app.FlagOnline})
	_ = db.AddAnalogInput(2, PointConfig{Deadband: 70000.2}, app.Analog{Flags: app.FlagOnline})
	_ = db.AddAnalogInput(3, PointConfig{Deadband: math.Inf(1)}, app.Analog{Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.IndexRange(app.G34V0, 1, 3)))
	f := m.recvFunc(app.FuncResponse)
	want := map[uint32]struct {
		gv app.GroupVariation
		v  float64
	}{1: {app.G34V1, 3}, 2: {app.G34V2, 70000}, 3: {app.G34V2, math.MaxUint32}}
	n := 0
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			w := want[o.Index]
			if h.GV != w.gv || o.Value.(app.AnalogDeadband).Value != w.v {
				t.Errorf("deadband %d: %s %v, want %s %v", o.Index, h.GV, o.Value, w.gv, w.v)
			}
			n++
		}
	}
	if n != 3 || f.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("READ g34v0: %s", f)
	}
	m.send(req(2, app.FuncRead, app.AllObjects(app.G34V3)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) || len(f.Headers) != 0 {
		t.Fatalf("READ g34v3: %s", f)
	}

	// Without the option, variation 3 carries the fraction and infinity.
	o := newMaster(t)
	_ = o.srv.Database().AddAnalogInput(1, PointConfig{Deadband: 2.5}, app.Analog{Flags: app.FlagOnline})
	_ = o.srv.Database().AddAnalogInput(2, PointConfig{Deadband: math.Inf(1)}, app.Analog{Flags: app.FlagOnline})
	o.send(req(1, app.FuncRead, app.IndexRange(app.G34V0, 1, 2)))
	f = o.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G34V3 || f.Headers[0].Objects[0].Value.(app.AnalogDeadband).Value != 2.5 ||
		!math.IsInf(f.Headers[0].Objects[1].Value.(app.AnalogDeadband).Value, 1) {
		t.Fatalf("READ g34v0 without the option: %s", f)
	}
}

// TestSpecA_18_3_2_3_InfiniteDeadbandSuppressesEvents: A.18.3.2.3
// (p. 608): a deadband of positive infinity prevents event generation for
// the point; its value is still reported when read.
func TestSpecA_18_3_2_3_InfiniteDeadbandSuppressesEvents(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	if err := db.AddAnalogInput(1, PointConfig{Class: 2, Deadband: math.Inf(1)}, app.Analog{Flags: app.FlagOnline}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []float64{1, 1e30, -1e30, math.MaxFloat64} {
		_ = db.UpdateAnalogInput(1, app.Analog{Value: v, Flags: app.FlagOnline})
	}
	m.send(req(1, app.FuncRead, app.AllObjects(app.G60V3)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
		t.Fatalf("events of a point with an infinite deadband: %s", f)
	}
	// It prevents event generation, not only for the value: a change of
	// flags raises none either.
	_ = db.UpdateAnalogInput(1, app.Analog{Value: math.MaxFloat64})
	m.send(req(2, app.FuncRead, app.AllObjects(app.G60V3)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
		t.Fatalf("event of a change of flags: %s", f)
	}
	m.send(req(3, app.FuncRead, app.IndexRange(app.G30V0, 1, 1)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || f.Headers[0].Objects[0].Value.(app.Analog).Flags&app.FlagOnline != 0 {
		t.Fatalf("static value: %s", f)
	}
}

// TestSpecTable11_5_ReservedFlagsCleared: outstations shall not set the
// ROLLOVER flag of counters (Table 11-5, p. 325), and the bits Annex A
// reserves are 0: bits 5 and 6 of binary outputs (A.10.2.2.2), bit 7 of
// counters and analogs. The database clears them on Add and on update.
func TestSpecTable11_5_ReservedFlagsCleared(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	on := app.FlagOnline
	_ = db.AddCounter(1, PointConfig{}, app.Counter{Value: 1, Flags: on | app.FlagRollover | 0x80})
	_ = db.AddBinaryOutput(0, PointConfig{}, app.Binary{Flags: on | 0x60})
	_ = db.AddAnalogInput(1, PointConfig{}, app.Analog{Flags: on | 0x80})
	_ = db.AddBinaryInput(2, PointConfig{}, app.Binary{Flags: on | 0x40})
	check := func(when string) {
		t.Helper()
		for _, c := range []struct {
			t   PointType
			idx uint32
		}{{Counter, 1}, {BinaryOutput, 0}, {AnalogInput, 1}, {BinaryInput, 2}} {
			v, _ := db.Get(c.t, c.idx)
			var f app.Flags
			switch x := v.(type) {
			case app.Counter:
				f = x.Flags
			case app.Binary:
				f = x.Flags
			case app.Analog:
				f = x.Flags
			}
			if f != on {
				t.Errorf("%s: %s %d flags %#x", when, c.t, c.idx, f)
			}
		}
	}
	check("added")
	_ = db.UpdateCounter(1, app.Counter{Value: 2, Flags: on | app.FlagRollover})
	_ = db.UpdateBinaryOutput(0, app.Binary{Value: true, Flags: on | 0x20})
	_ = db.UpdateAnalogInput(1, app.Analog{Value: 3, Flags: on | 0x80})
	_ = db.UpdateBinaryInput(2, app.Binary{Value: true, Flags: on | 0x40})
	check("updated")
	// What the master reads: g20v1 and g22 without ROLLOVER.
	m.send(req(1, app.FuncRead, app.IndexRange(app.G20V1, 1, 1), app.AllObjects(app.G22V1)))
	f := m.recvFunc(app.FuncResponse)
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			if c, ok := o.Value.(app.Counter); ok && c.Flags&app.FlagRollover != 0 {
				t.Fatalf("%s %d with ROLLOVER", h.GV, o.Index)
			}
		}
	}
}

// TestSpec4_4_1_AttributesWithoutSets: an outstation without device
// attributes supports no group 0 object: a READ of one is IIN2.1
// (Table 4-14, p. 85).
func TestSpec4_4_1_AttributesWithoutSets(t *testing.T) {
	m := newMaster(t)
	for i, h := range []app.Header{app.AllObjects(app.GV(0, app.AttrAllAttributes)), app.AllObjects(app.GV(0, app.AttrListOfVariations)), app.IndexRange(app.GV(0, 250), 0, 0)} {
		m.send(req(uint8(i+1), app.FuncRead, h))
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) || len(f.Headers) != 0 {
			t.Fatalf("READ %s: %s", h.GV, f)
		}
	}
}

// TestSpec5_5_6_AttributeSetByIndex: 5.5.6 (pp. 151-152): a header with
// an index qualifier names the attribute sets by its indexes; the list of
// variations of a set (g0v255) carries the set as the index of qualifier
// 0x17 (5.5.6.2 b, p. 151).
func TestSpec5_5_6_AttributeSetByIndex(t *testing.T) {
	m := newMaster(t, WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: app.StringAttribute("m")}),
		WithAttributeSet(1, map[uint8]app.Attribute{1: app.UintAttribute(1), 10: app.StringAttribute("x")}))
	m.send(req(1, app.FuncRead, app.IndexList(app.GV(0, app.AttrAllAttributes), 1)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 2 || f.Headers[0].Start != 1 || f.Headers[1].Start != 1 {
		t.Fatalf("READ g0v254 of set 1 by index: %s", f)
	}
	m.send(req(2, app.FuncRead, app.IndexList(app.GV(0, app.AttrAllAttributes), 7)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("an unknown set by index: %s", f)
	}
	m.send(req(3, app.FuncRead, app.IndexRange(app.GV(0, app.AttrListOfVariations), 1, 1)))
	f = m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].Qualifier != app.Qual1ByteIndexCount || f.Headers[0].Objects[0].Index != 1 {
		t.Fatalf("READ g0v255 of set 1: %s", f)
	}
}

// TestSpec5_5_8_AcceptedWriteChangesAttribute: 5.5.8 (p. 153): a WRITE of
// a writable attribute that the outstation accepts changes the attribute it
// reports; one the handler refuses changes nothing.
func TestSpec5_5_8_AcceptedWriteChangesAttribute(t *testing.T) {
	m := newMaster(t, WithHandler(&attrRecorder{}), WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: app.StringAttribute("m")}))
	read := func(seq uint8) string {
		t.Helper()
		m.send(req(seq, app.FuncRead, app.AllObjects(app.GV(0, app.AttrManufacturerName))))
		f := m.recvFunc(app.FuncResponse)
		return string(f.Headers[0].Objects[0].Value.(app.Attribute).Data)
	}
	m.send(req(1, app.FuncWrite, app.Ranged(app.GV(0, app.AttrManufacturerName), 0, app.StringAttribute("new"))))
	m.recvFunc(app.FuncResponse)
	if got := read(2); got != "new" {
		t.Fatalf("after the write: %q", got)
	}
	m.send(req(3, app.FuncWrite, app.Ranged(app.GV(0, app.AttrManufacturerName), 0, app.StringAttribute("no"))))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("refused write: %s", f)
	}
	if got := read(4); got != "new" {
		t.Fatalf("after a refused write: %q", got)
	}
}

// TestSpecA_8_3_PatternMaskWithoutBlock: A.8.2.1 (p. 511) and A.8.3.1 (p.
// 513): pattern masks (g12v3) follow the pattern control block (g12v2) they
// apply to. A mask without one, first in the request or after another
// control block, is a parameter error (IIN2.2), and nothing is executed.
// With DIRECT_OPERATE_NR such a request is not executed and, as 4.4.5 (p.
// 55) has it for that function, not answered.
func TestSpecA_8_3_PatternMaskWithoutBlock(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	mask := app.Ranged(app.G12V3, 0, app.Binary{Value: true})
	ctl := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	for i, hs := range [][]app.Header{{mask}, {ctl, mask}} {
		seq := uint8(1 + i)
		m.send(req(seq, app.FuncDirectOperate, hs...))
		if f := m.recvFunc(app.FuncResponse); f.Control.Seq != seq || !f.IIN.Has(app.IINParameterError) {
			t.Fatalf("headers %d: %v", i, f)
		}
	}
	m.send(req(3, app.FuncDirectOperateNoAck, ctl, mask))
	m.send(readIIN(4))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 4 {
		t.Fatalf("after DIRECT_OPERATE_NR: %v, want the response to the READ", f)
	}
	if h.count() != 0 {
		t.Fatalf("%d controls executed", h.count())
	}
}

// TestSpec4_4_8_FreezeAtTimeStructure: 4.4.8 (pp. 56-57): a FREEZE_AT_TIME
// request holds time-and-interval objects (g50v2), each followed by the
// headers of the points it freezes. One without any header, or whose g50v2
// no point header follows, is a parameter error. Points named by index
// (qualifier 0x17) are frozen as points named by range are (Table 4-11,
// time and interval zero: at once), and schedules for different indexes
// are different schedules: one does not replace the other.
func TestSpec4_4_8_FreezeAtTimeStructure(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	for i, v := range []uint32{4, 9} {
		_ = db.AddCounter(uint32(1+i), PointConfig{}, app.Counter{Value: v, Flags: app.FlagOnline})
		_ = db.AddFrozenCounter(uint32(1+i), PointConfig{}, app.Counter{Flags: app.FlagOnline})
	}
	for i, f := range []*app.Fragment{req(1, app.FuncFreezeAtTime), freezeReq(2, app.AbsoluteTime{})} {
		m.send(f)
		if r := m.recvFunc(app.FuncResponse); !r.IIN.Has(app.IINParameterError) {
			t.Fatalf("request %d: %v", i, r)
		}
	}
	m.send(freezeReq(3, app.AbsoluteTime{}, app.IndexList(app.G20V0, 1)))
	if r := m.recvFunc(app.FuncResponse); r.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("freeze by index: %v", r)
	}
	one, _ := db.Get(FrozenCounter, 1)
	two, _ := db.Get(FrozenCounter, 2)
	if one.(app.Counter).Value != 4 || two.(app.Counter).Value != 0 {
		t.Fatalf("frozen counters %v and %v, want 4 and 0", one, two)
	}
	inAnHour := app.TimestampOf(m.srv.Now().Add(time.Hour))
	for i, idx := range []uint32{1, 2} {
		m.send(freezeReq(uint8(4+i), app.AbsoluteTime{Time: inAnHour}, app.IndexList(app.G20V0, idx)))
		if r := m.recvFunc(app.FuncResponse); r.IIN&app.IINRequestErrors != 0 {
			t.Fatalf("schedule of index %d: %v", idx, r)
		}
	}
	if n := len(schedules(m.srv)); n != 2 {
		t.Fatalf("%d schedules for two indexes", n)
	}
}

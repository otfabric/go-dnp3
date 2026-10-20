// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

func TestCommandEvents(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	db := m.srv.Database()
	_ = db.AddBinaryOutput(0, PointConfig{CommandEventClass: 1}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddAnalogOutput(0, PointConfig{CommandEventClass: 1}, app.Analog{Flags: app.FlagOnline})
	crobs := []app.CROB{
		{Op: app.OpLatchOn, Count: 1}, {Op: app.OpLatchOff, Count: 1}, {Op: app.OpPulseOn, Count: 1},
		{Op: app.OpPulseOff, Count: 1}, {Op: app.OpPulseOn, TripClose: app.TCCClose, Count: 1}, {Op: app.OpPulseOn, TripClose: app.TCCTrip, Count: 1},
	}
	want := []bool{true, false, true, false, true, false}
	seq := uint8(0)
	for _, c := range crobs {
		seq = app.NextSeq(seq)
		m.send(req(seq, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 0, Value: c})))
		m.recvFunc(app.FuncResponse)
	}
	// Select-before-operate: the OPERATE raises the event, not the SELECT.
	sbo := app.Indexed(app.G12V1, app.Object{Index: 0, Value: crobs[0]})
	seq = app.NextSeq(seq)
	m.send(req(seq, app.FuncSelect, sbo))
	m.recvFunc(app.FuncResponse)
	seq = app.NextSeq(seq)
	m.send(req(seq, app.FuncOperate, sbo))
	m.recvFunc(app.FuncResponse)
	crobs, want = append(crobs, crobs[0]), append(want, true)
	seq = app.NextSeq(seq)
	m.send(req(seq, app.FuncDirectOperateNoAck, app.Indexed(app.G41V3, app.Object{Index: 0, Value: app.AnalogOutput{Value: 3.5}})))
	// A control of an output that does not exist raises no event.
	seq = app.NextSeq(seq)
	m.send(req(seq, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 7, Value: crobs[0]})))
	m.recvFunc(app.FuncResponse)

	seq = app.NextSeq(seq)
	m.send(req(seq, app.FuncRead, app.AllObjects(app.G13V0), app.AllObjects(app.G43V0)))
	f := m.recvFunc(app.FuncResponse)
	var states []bool
	var analog []float64
	for _, hdr := range f.Headers {
		for _, o := range hdr.Objects {
			switch v := o.Value.(type) {
			case app.BinaryCommandEvent:
				if hdr.GV != app.G13V2 {
					t.Errorf("binary command event as %s", hdr.GV)
				}
				states = append(states, v.Value)
			case app.AnalogCommandEvent:
				if hdr.GV != app.G43V3 {
					t.Errorf("analog command event as %s", hdr.GV)
				}
				analog = append(analog, v.Value)
			}
		}
	}
	if len(states) != len(want) || len(analog) != 1 {
		t.Fatalf("events: %v %v", states, analog)
	}
	for i := range want {
		if states[i] != want[i] {
			t.Errorf("CROB %+v: commanded state %v, want %v", crobs[i], states[i], want[i])
		}
	}
	if BinaryOutputCommand.String() != "binary output command" || AnalogOutputCommand.String() != "analog output command" ||
		SecurityStatistic.String() != "security statistic" {
		t.Fatal("point type names")
	}
	// Configuration that does not apply is refused.
	for _, c := range []struct {
		t   PointType
		cfg PointConfig
		v   app.Value
	}{
		{AnalogInput, PointConfig{CommandEventClass: 1}, app.Analog{}},
		{BinaryOutput, PointConfig{CommandEventClass: 4}, app.Binary{}},
		{AnalogOutput, PointConfig{CommandEventClass: 1, CommandEventVariation: 9}, app.Analog{}},
		{AnalogOutputCommand, PointConfig{}, app.AnalogCommandEvent{}},
	} {
		if err := db.Add(c.t, 1, c.cfg, c.v); err == nil {
			t.Errorf("%s with %+v accepted", c.t, c.cfg)
		}
	}
}

func TestTimeAndInterval(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	ti := app.AbsoluteTime{Time: app.Timestamp(1767225600000), Interval: 15, Units: app.UnitMinutes}
	if err := db.Add(TimeAndInterval, 0, PointConfig{}, ti); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []PointConfig{{Class: 1}, {StaticVariation: 1}, {EventVariation: 1}} {
		if err := db.Add(TimeAndInterval, 1, cfg, ti); err == nil {
			t.Errorf("time and interval with %+v accepted", cfg)
		}
	}
	if err := db.Add(TimeAndInterval, 1, PointConfig{}, app.Analog{}); err == nil {
		t.Error("time and interval with an analog value accepted")
	}
	m.send(req(1, app.FuncRead, app.IndexRange(app.G50V4, 0, 0)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G50V4 || f.Headers[0].Objects[0].Value.(app.AbsoluteTime) != ti {
		t.Fatalf("read of g50v4: %v", f)
	}
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	for _, h := range m.recvFunc(app.FuncResponse).Headers {
		if h.GV.Group() == 50 {
			t.Fatal("time and interval in class 0")
		}
	}
	m.send(req(2, app.FuncRead, app.AllObjects(app.G50V1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("read of g50v1: %v", f)
	}
	m.send(req(3, app.FuncAssignClass, app.AllObjects(app.G60V2), app.AllObjects(app.G50V4)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("assign class of a time and interval: %v", f)
	}
	if TimeAndInterval.String() != "time and interval" {
		t.Fatal("name")
	}
}

func TestDeadbandRead(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddAnalogInput(0, PointConfig{Deadband: 5}, app.Analog{})
	_ = db.AddAnalogInput(1, PointConfig{Deadband: 70000}, app.Analog{})
	_ = db.AddAnalogInput(2, PointConfig{Deadband: 0.25}, app.Analog{})
	m.send(req(1, app.FuncRead, app.AllObjects(app.G34V0)))
	f := m.recvFunc(app.FuncResponse)
	got := map[uint32]app.GroupVariation{}
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			got[o.Index] = h.GV
			if want := map[uint32]float64{0: 5, 1: 70000, 2: 0.25}[o.Index]; o.Value.(app.AnalogDeadband).Value != want {
				t.Errorf("deadband %d = %v", o.Index, o.Value)
			}
		}
	}
	if got[0] != app.G34V1 || got[1] != app.G34V2 || got[2] != app.G34V3 {
		t.Fatalf("variations %v", got)
	}
	// A requested variation, an index list, a missing point, an unknown
	// variation.
	m.send(req(2, app.FuncRead, app.IndexRange(app.G34V3, 0, 1)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || f.Headers[0].GV != app.G34V3 || len(f.Headers[0].Objects) != 2 {
		t.Fatalf("g34v3 range: %v", f)
	}
	m.send(req(3, app.FuncRead, app.IndexList(app.G34V0, 0, 2)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 2 {
		t.Fatalf("index list: %v", f)
	}
	m.send(req(4, app.FuncRead, app.IndexRange(app.G34V1, 0, 5)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("range past the points: %v", f)
	}
	m.send(req(5, app.FuncRead, app.AllObjects(app.GV(34, 9))))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("g34v9: %v", f)
	}
	m.send(req(6, app.FuncRead, app.CountOf(app.G34V0, 2)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("count qualifier: %v", f)
	}
}

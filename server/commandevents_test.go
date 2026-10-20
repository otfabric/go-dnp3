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

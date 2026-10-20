// SPDX-License-Identifier: MIT

package e2e

import (
	"testing"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// TestCommandEvents: the outstation reports the controls it executed as
// g13 and g43 events, with the commanded state or value and the status.
func TestCommandEvents(t *testing.T) {
	h := &relay{status: app.StatusSuccess}
	p := newPair(t, func(db *server.Database) {
		_ = db.AddBinaryOutput(0, server.PointConfig{CommandEventClass: 1}, app.Binary{Flags: app.FlagOnline})
		_ = db.AddBinaryOutput(1, server.PointConfig{}, app.Binary{Flags: app.FlagOnline}) // no command events
		_ = db.AddAnalogOutput(0, server.PointConfig{CommandEventClass: 2, CommandEventVariation: 7}, app.Analog{Flags: app.FlagOnline})
	}, []server.Option{server.WithHandler(h)})
	c := ctx(t)
	trip := client.Command{Index: 0, Value: app.CROB{Op: app.OpPulseOn, TripClose: app.TCCTrip, Count: 1, OnTime: 100}}
	if _, err := p.c.Operate(c, client.SelectBeforeOperate, trip); err != nil {
		t.Fatal(err)
	}
	_, _ = p.c.Operate(c, client.DirectOperate, client.CROB(1, app.OpLatchOn, 0, 0))
	if _, err := p.c.Operate(c, client.DirectOperate, client.SetPoint(0, 12.5)); err != nil {
		t.Fatal(err)
	}
	res, err := p.c.Read(c, app.AllObjects(app.G60V2), app.AllObjects(app.G60V3))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range res.Measurements() {
		switch v := m.Value.(type) {
		case app.BinaryCommandEvent:
			if m.GV != app.G13V2 || m.Index != 0 || v.Value || v.Status != app.StatusSuccess || v.Time == 0 {
				t.Errorf("binary command event %s %d %+v", m.GV, m.Index, v)
			}
			got = append(got, "g13")
		case app.AnalogCommandEvent:
			if m.GV != app.G43V7 || m.Index != 0 || v.Value != 12.5 || v.Status != app.StatusSuccess {
				t.Errorf("analog command event %s %d %+v", m.GV, m.Index, v)
			}
			got = append(got, "g43")
		}
	}
	if len(got) != 2 {
		t.Fatalf("command events %v, want one g13 (the SELECT is not one) and one g43", got)
	}
	// A refused control is reported with its status.
	h.mu.Lock()
	h.status = app.StatusHardwareError
	h.mu.Unlock()
	_, _ = p.c.Operate(c, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0))
	res, err = p.c.Read(c, app.AllObjects(app.G13V0))
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if len(ms) != 1 || ms[0].Value.(app.BinaryCommandEvent).Status != app.StatusHardwareError || !ms[0].Value.(app.BinaryCommandEvent).Value {
		t.Fatalf("refused control's event: %v", ms)
	}
	// Command events are configured on outputs only.
	if err := p.db.AddBinaryInput(9, server.PointConfig{CommandEventClass: 1}, app.Binary{}); err == nil {
		t.Fatal("command events on a binary input accepted")
	}
	if err := p.db.AddBinaryOutput(9, server.PointConfig{CommandEventClass: 1, CommandEventVariation: 9}, app.Binary{}); err == nil {
		t.Fatal("command event variation g13v9 accepted")
	}
	if err := p.db.Add(server.BinaryOutputCommand, 0, server.PointConfig{}, app.BinaryCommandEvent{}); err == nil {
		t.Fatal("command event point added")
	}
}

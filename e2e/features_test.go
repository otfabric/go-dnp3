// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"errors"
	"math"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// fullDatabase adds points of every type.
func fullDatabase(db *server.Database) {
	on := app.FlagOnline
	for i := uint32(0); i < 5; i++ {
		_ = db.AddBinaryInput(i, server.PointConfig{Class: 1}, app.Binary{Value: i%2 == 0, Flags: on})
	}
	_ = db.AddBinaryInput(10, server.PointConfig{Class: 1}, app.Binary{Flags: on}) // a gap
	_ = db.AddDoubleBitInput(0, server.PointConfig{Class: 1}, app.DoubleBitBinary{Value: app.DoubleBitOn, Flags: on})
	_ = db.AddBinaryOutput(0, server.PointConfig{Class: 1}, app.Binary{Flags: on})
	_ = db.AddCounter(0, server.PointConfig{Class: 3}, app.Counter{Value: 100, Flags: on})
	_ = db.AddFrozenCounter(0, server.PointConfig{Class: 3}, app.Counter{Flags: on})
	_ = db.AddAnalogInput(0, server.PointConfig{Class: 2, StaticVariation: 5, EventVariation: 7}, app.Analog{Value: 1.5, Flags: on})
	_ = db.AddAnalogInput(1, server.PointConfig{Class: 2, Deadband: 10}, app.Analog{Value: 1000, Flags: on})
	_ = db.AddAnalogInput(2, server.PointConfig{Class: 2, ExcludeFromClass0: true}, app.Analog{Value: 7, Flags: on})
	_ = db.AddFrozenAnalogInput(0, server.PointConfig{}, app.Analog{Flags: on})
	_ = db.AddAnalogOutput(0, server.PointConfig{Class: 1, StaticVariation: 3}, app.Analog{Value: 2.25, Flags: on})
	_ = db.AddOctetString(0, server.PointConfig{Class: 3}, []byte("hello"))
}

func TestIntegrityPoll(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	res, err := p.c.IntegrityPoll(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	want := []string{"g1v2", "g1v2", "g1v2", "g1v2", "g1v2", "g1v2", "g3v2", "g10v2", "g20v1", "g21v1",
		"g30v5", "g30v1", "g31v1", "g40v3", "g110v5"}
	if got := gvs(ms); !reflect.DeepEqual(got, want) {
		t.Fatalf("integrity poll objects\n got %v\nwant %v", got, want)
	}
	k := byKey(ms)
	if v := k[[2]uint32{30, 0}].Value.(app.Analog); v.Value != 1.5 || v.Flags != app.FlagOnline {
		t.Errorf("analog 0: %+v", v)
	}
	if v := k[[2]uint32{110, 0}].Value.(app.OctetString); string(v.Data) != "hello" {
		t.Errorf("octet string: %q", v.Data)
	}
	if v := k[[2]uint32{1, 10}].Value.(app.Binary); v.Value {
		t.Error("binary 10")
	}
	// Two headers for the binary inputs: indexes 0..4 and 10.
	n := 0
	for _, h := range res.Headers() {
		if h.GV == app.G1V2 {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d g1v2 headers, want 2", n)
	}
	if ms[0].Event {
		t.Error("static reported as event")
	}
}

func TestReadByGroupAndRange(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	res, err := p.c.Read(c, app.IndexRange(app.G1V1, 0, 4))
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if len(ms) != 5 || ms[0].GV != app.G1V1 || !ms[0].Value.(app.Binary).Value || ms[1].Value.(app.Binary).Value {
		t.Fatalf("packed read: %v", ms)
	}
	res, err = p.c.Read(c, app.AllObjects(app.G30V2), app.IndexList(app.G1V2, 10, 2))
	if err != nil {
		t.Fatal(err)
	}
	if got := gvs(res.Measurements()); !reflect.DeepEqual(got, []string{"g30v2", "g30v2", "g30v2", "g1v2", "g1v2"}) {
		t.Fatalf("read: %v", got)
	}
	// An index that does not exist: the others are reported, with IIN2.2.
	res, err = p.c.Read(c, app.IndexRange(app.G1V2, 3, 7))
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINParameterError) || len(res.Measurements()) != 2 {
		t.Fatalf("missing index: %v %v", err, res)
	}
	// An object the outstation does not have.
	_, err = p.c.Read(c, app.AllObjects(app.G101V1))
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("unknown object: %v", err)
	}
}

func TestEvents(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	if _, err := p.c.IntegrityPoll(c); err != nil {
		t.Fatal(err)
	}
	db := p.db
	on := app.FlagOnline
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: on}) // class 1
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 2.5, Flags: on})  // class 2, g32v7
	_ = db.UpdateAnalogInput(1, app.Analog{Value: 1005, Flags: on}) // within deadband: no event
	_ = db.UpdateAnalogInput(1, app.Analog{Value: 1020, Flags: on}) // beyond it
	_ = db.UpdateCounter(0, app.Counter{Value: 150, Flags: on})     // class 3
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: on}) // unchanged: no event
	_ = db.Update(server.BinaryInput, 1, app.Binary{Value: true, Flags: on}, server.EventForce)
	_ = db.UpdateOctetString(0, []byte("world!"))

	// Class 2 only.
	res, err := p.c.EventPoll(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := gvs(res.Measurements()); !reflect.DeepEqual(got, []string{"g32v7", "g32v3"}) {
		t.Fatalf("class 2 events: %v", got)
	}
	if !res.IIN.Has(app.IINClass1Events) || !res.IIN.Has(app.IINClass3Events) || res.IIN.Has(app.IINClass2Events) {
		t.Fatalf("IIN after class 2: %s", res.IIN)
	}
	if v := res.Measurements()[0].Value.(app.Analog); v.Value != 2.5 || v.Time == 0 {
		t.Fatalf("event value %+v", v)
	}
	// Classes 1 and 3, in the order the events occurred.
	res, err = p.c.EventPoll(c, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := gvs(res.Measurements()); !reflect.DeepEqual(got, []string{"g2v2", "g22v5", "g2v2", "g111v6"}) {
		t.Fatalf("class 1+3 events: %v", got)
	}
	for _, m := range res.Measurements() {
		if !m.Event {
			t.Error("event not marked")
		}
	}
	if res.IIN&app.IINClassEvents != 0 {
		t.Fatalf("events left: %s", res.IIN)
	}
	// Confirmed events are gone.
	res, _ = p.c.EventPoll(c)
	if len(res.Measurements()) != 0 {
		t.Fatalf("events reported twice: %v", gvs(res.Measurements()))
	}
}

func TestEventVariationsAndLimits(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	for i := range 5 {
		_ = p.db.UpdateBinaryInput(0, app.Binary{Value: i%2 == 1, Flags: app.FlagOnline})
	}
	// At most two binary input events, in relative time with a CTO.
	res, err := p.c.Read(c, app.CountOf(app.G2V3, 2))
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if len(ms) != 2 || ms[0].GV != app.G2V3 || ms[0].Value.(app.Binary).Time == 0 {
		t.Fatalf("limited relative-time read: %v", ms)
	}
	hs := res.Headers()
	if hs[0].GV != app.G51V1 {
		t.Fatalf("no CTO before the relative-time events: %v", hs[0].GV)
	}
	if !res.IIN.Has(app.IINClass1Events) {
		t.Fatal("remaining events not indicated")
	}
	// The rest, in the variation without time.
	res, _ = p.c.Read(c, app.AllObjects(app.G2V1))
	if len(res.Measurements()) != 3 || res.Measurements()[0].Value.(app.Binary).Time != 0 {
		t.Fatalf("rest: %v", res.Measurements())
	}
}

func TestMultiFragmentResponse(t *testing.T) {
	const n = 600
	p := newPair(t, func(db *server.Database) {
		for i := uint32(0); i < n; i++ {
			_ = db.AddAnalogInput(i, server.PointConfig{Class: 2, StaticVariation: 1}, app.Analog{Value: float64(i), Flags: app.FlagOnline})
		}
	}, []server.Option{server.WithMaxFragment(249, 2048)})
	c := ctx(t)
	res, err := p.c.IntegrityPoll(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fragments) < 10 {
		t.Fatalf("%d fragments, want many", len(res.Fragments))
	}
	ms := res.Measurements()
	if len(ms) != n {
		t.Fatalf("%d measurements", len(ms))
	}
	for i, m := range ms {
		if m.Index != uint32(i) || m.Value.(app.Analog).Value != float64(i) {
			t.Fatalf("measurement %d: %+v", i, m)
		}
	}
	// Events across fragments are confirmed fragment by fragment.
	_ = p.db.Batch(func(b *server.Batch) error {
		for i := uint32(0); i < 90; i++ {
			_ = b.Update(server.AnalogInput, i, app.Analog{Value: -1, Flags: app.FlagOnline}, server.EventOnChange)
		}
		return nil
	})
	res, err = p.c.EventPoll(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Measurements()) != 90 || len(res.Fragments) < 2 {
		t.Fatalf("%d events in %d fragments", len(res.Measurements()), len(res.Fragments))
	}
	if res, _ := p.c.EventPoll(c); len(res.Measurements()) != 0 {
		t.Fatal("events reported twice")
	}
}

func TestEventBufferOverflow(t *testing.T) {
	m := &countingMetrics{}
	p := newPair(t, fullDatabase, []server.Option{
		server.WithEventLimits(map[server.PointType]int{server.BinaryInput: 3}),
		server.WithMetrics(m),
	}, client.WithAutoIntegrity(false))
	for i := range 10 {
		_ = p.db.UpdateBinaryInput(0, app.Binary{Value: i%2 == 0, Flags: app.FlagOnline})
	}
	res, err := p.c.EventPoll(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Measurements()) != 3 || !res.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("%d events, IIN %s", len(res.Measurements()), res.IIN)
	}
	// The newest events are kept.
	if last := res.Measurements()[2].Value.(app.Binary); last.Value {
		t.Fatal("oldest events kept instead of newest")
	}
	if m.get(&m.eventsDropped) == 0 {
		t.Fatal("OnEventsDiscarded not called")
	}
	res, _ = p.c.EventPoll(ctx(t))
	if res.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatal("overflow not cleared after the events were confirmed")
	}
}

func TestControls(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r)})
	c := ctx(t)

	st, err := p.c.Operate(c, client.SelectBeforeOperate, client.CROB(3, app.OpLatchOn, 0, 0))
	if err != nil || len(st) != 1 || st[0] != app.StatusSuccess {
		t.Fatalf("SBO: %v %v", st, err)
	}
	sel, op, ops := r.snapshot()
	if len(sel) != 1 || len(op) != 1 || ops[0] != server.SelectBeforeOperate || op[0].Index != 3 || op[0].GV != app.G12V1 {
		t.Fatalf("handler saw %v %v %v", sel, op, ops)
	}
	if crob := op[0].Value.(app.CROB); crob.Op != app.OpLatchOn || crob.Count != 1 {
		t.Fatalf("crob %v", crob)
	}

	// Direct operate of several set-points in different variations.
	st, err = p.c.Operate(c, client.DirectOperate, client.SetPoint(0, 12), client.SetPoint(1, 2.5),
		client.Command{Index: 2, Value: app.AnalogOutput{Value: 7}, GV: app.G41V2})
	if err != nil || len(st) != 3 {
		t.Fatalf("direct operate: %v %v", st, err)
	}
	_, op, ops = r.snapshot()
	got := op[len(op)-3:]
	if got[0].GV != app.G41V1 || got[1].GV != app.G41V3 || got[2].GV != app.G41V2 || ops[len(ops)-1] != server.DirectOperate {
		t.Fatalf("set-points %v", got)
	}
	if got[1].Value.(app.AnalogOutput).Value != 2.5 {
		t.Fatal("float set-point")
	}

	// No acknowledgement.
	if _, err := p.c.Operate(c, client.DirectOperateNoAck, client.CROB(5, app.OpPulseOn, 100, 100)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "no-ack operate", func() bool { _, op, _ := r.snapshot(); return len(op) == 5 })
	_, _, ops = r.snapshot()
	if ops[4] != server.DirectOperateNoAck {
		t.Fatalf("op type %v", ops[4])
	}

	// A refused control.
	r.mu.Lock()
	r.status = app.StatusLocal
	r.mu.Unlock()
	_, err = p.c.Operate(c, client.SelectBeforeOperate, client.CROB(3, app.OpLatchOff, 0, 0))
	var ce *dnp3.CommandError
	if !errors.As(err, &ce) || ce.Status != app.StatusLocal || ce.Index != 3 {
		t.Fatalf("refused: %v", err)
	}
	_, op, _ = r.snapshot()
	if len(op) != 5 {
		t.Fatal("OPERATE sent after a refused SELECT")
	}
}

func TestOperateWithoutSelect(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r)})
	hs := []app.Header{app.Indexed(app.G12V1, app.Object{Index: 1, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})}
	res, err := p.c.Request(ctx(t), app.FuncOperate, hs...)
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Headers()[0].Objects[0].Value.(app.CROB).Status; s != app.StatusNoSelect {
		t.Fatalf("status %s, want NO_SELECT", s)
	}
	if _, op, _ := r.snapshot(); len(op) != 0 {
		t.Fatal("operated without select")
	}
}

func TestTooManyControls(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r), server.WithMaxControls(2)})
	st, err := p.c.Operate(ctx(t), client.DirectOperate,
		client.CROB(1, app.OpPulseOn, 1, 1), client.CROB(2, app.OpPulseOn, 1, 1), client.CROB(3, app.OpPulseOn, 1, 1))
	var ce *dnp3.CommandError
	if !errors.As(err, &ce) || st[2] != app.StatusTooManyObjects || st[0] != app.StatusSuccess {
		t.Fatalf("%v %v", st, err)
	}
}

func TestTimeSync(t *testing.T) {
	r := &relay{}
	for _, proc := range []client.TimeSync{client.TimeSyncLAN, client.TimeSyncNonLAN} {
		p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r), server.WithTimeSync(time.Hour)})
		res, err := p.c.IntegrityPoll(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IIN.Has(app.IINNeedTime) {
			t.Fatal("NEED_TIME not reported")
		}
		if err := p.c.SyncTime(ctx(t), proc); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(p.srv.Now()); d > 100*time.Millisecond || d < -100*time.Millisecond {
			t.Fatalf("procedure %d: outstation clock off by %v", proc, d)
		}
		res, _ = p.c.IntegrityPoll(ctx(t))
		if res.IIN.Has(app.IINNeedTime) {
			t.Fatal("NEED_TIME after synchronization")
		}
	}
	r.mu.Lock()
	n := len(r.times)
	r.mu.Unlock()
	if n != 2 {
		t.Fatalf("TimeHandler called %d times", n)
	}
	// An explicit time.
	p := newPair(t, fullDatabase, nil)
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := p.c.WriteTime(ctx(t), at); err != nil {
		t.Fatal(err)
	}
	if d := p.srv.Now().Sub(at); d < 0 || d > time.Second {
		t.Fatalf("outstation time %v", p.srv.Now())
	}
	if proc, rtt, err := p.c.DelayMeasure(ctx(t)); err != nil || proc > rtt {
		t.Fatalf("delay measure %v %v %v", proc, rtt, err)
	}
}

func TestAutomaticTimeSync(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithTimeSync(time.Hour)}, client.WithTimeSync(client.TimeSyncLAN))
	_, _ = p.c.IntegrityPoll(ctx(t))
	waitUntil(t, "automatic time synchronization", func() bool {
		res, err := p.c.Read(ctx(t), app.AllObjects(app.G80V1))
		return err == nil && !res.IIN.Has(app.IINNeedTime)
	})
}

func TestRestarts(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r)})
	d, err := p.c.ColdRestart(ctx(t))
	if err != nil || d != 90*time.Second {
		t.Fatalf("cold: %v %v", d, err)
	}
	d, err = p.c.WarmRestart(ctx(t))
	if err != nil || d != 1500*time.Millisecond {
		t.Fatalf("warm: %v %v", d, err)
	}
	// Without a RestartHandler the function is not supported.
	q := newPair(t, fullDatabase, nil)
	_, err = q.c.ColdRestart(ctx(t))
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINNoFuncCodeSupport) {
		t.Fatalf("unsupported restart: %v", err)
	}
	// Server.Restart makes the master see DEVICE_RESTART again. A client
	// that does not clear it on its own is used, to observe the bit.
	r2 := newPair(t, fullDatabase, []server.Option{server.WithHandler(r)}, client.WithAutoClearRestart(false))
	if err := r2.c.ClearRestart(ctx(t)); err != nil {
		t.Fatal(err)
	}
	res, _ := r2.c.Read(ctx(t), app.AllObjects(app.G80V1))
	if res.IIN.Has(app.IINDeviceRestart) {
		t.Fatal("restart bit not cleared")
	}
	r2.srv.Restart()
	res, err = r2.c.Read(ctx(t), app.IndexRange(app.G80V1, 7, 7))
	if err != nil || len(res.Measurements()) != 0 || !res.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("after Server.Restart: %v IIN=%s n=%d", err, res.IIN, len(res.Measurements()))
	}
}

func TestUnsolicited(t *testing.T) {
	m := &countingMetrics{}
	p := newPair(t, fullDatabase, []server.Option{
		server.WithUnsolicited(server.Unsolicited{Enabled: true}), server.WithMetrics(m),
	}, client.WithStartup(client.Startup{DisableUnsolicited: true, Integrity: true, EnableUnsolicited: []int{1, 2, 3}}))
	_ = p.db.UpdateBinaryInput(4, app.Binary{Value: false, Flags: app.FlagOnline})
	_ = p.db.UpdateAnalogInput(0, app.Analog{Value: -3, Flags: app.FlagOnline})
	uns := p.rec.waitFor(t, "unsolicited events", func(ms []client.Measurement) bool { return len(ms) >= 2 })
	if uns[0].GV != app.G2V2 || uns[0].Index != 4 || uns[1].GV != app.G32V7 {
		t.Fatalf("unsolicited %v", gvs(uns))
	}
	waitUntil(t, "unsolicited confirmed", func() bool { return m.get(&m.unsolicited) >= 2 })
	// Confirmed: nothing is left for a poll.
	if res, _ := p.c.EventPoll(ctx(t)); len(res.Measurements()) != 0 {
		t.Fatalf("events left after unsolicited: %v", gvs(res.Measurements()))
	}
	// Disabled: events wait for a poll.
	if err := p.c.DisableUnsolicited(ctx(t)); err != nil {
		t.Fatal(err)
	}
	_ = p.db.UpdateBinaryInput(4, app.Binary{Value: true, Flags: app.FlagOnline})
	time.Sleep(200 * time.Millisecond)
	if res, _ := p.c.EventPoll(ctx(t)); len(res.Measurements()) != 1 {
		t.Fatalf("polled %d events after disable", len(res.Measurements()))
	}
}

func TestUnsolicitedWithoutSupport(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	err := p.c.EnableUnsolicited(ctx(t))
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINNoFuncCodeSupport) {
		t.Fatalf("%v", err)
	}
}

func TestAssignClassAndFreeze(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	// Analog inputs to class 3, counter to class 1.
	if err := p.c.AssignClass(c, 3, app.AllObjects(app.G30V0)); err != nil {
		t.Fatal(err)
	}
	if err := p.c.AssignClass(c, 1, app.IndexRange(app.G20V0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	_, _ = p.c.EventPoll(c)
	_ = p.db.UpdateAnalogInput(0, app.Analog{Value: 9, Flags: app.FlagOnline})
	_ = p.db.UpdateCounter(0, app.Counter{Value: 500, Flags: app.FlagOnline})
	res, _ := p.c.EventPoll(c, 3)
	if got := gvs(res.Measurements()); !reflect.DeepEqual(got, []string{"g32v7"}) {
		t.Fatalf("class 3 after assign: %v", got)
	}
	res, _ = p.c.EventPoll(c, 1)
	if got := gvs(res.Measurements()); !reflect.DeepEqual(got, []string{"g22v5"}) {
		t.Fatalf("class 1 after assign: %v", got)
	}

	// Freeze and clear: the frozen counter holds 500, the counter 0, and
	// the frozen counter produced an event.
	if err := p.c.Freeze(c, true, false, app.AllObjects(app.G20V0)); err != nil {
		t.Fatal(err)
	}
	res, _ = p.c.Read(c, app.AllObjects(app.G21V0), app.AllObjects(app.G20V0))
	k := byKey(res.Measurements())
	if k[[2]uint32{21, 0}].Value.(app.Counter).Value != 500 || k[[2]uint32{20, 0}].Value.(app.Counter).Value != 0 {
		t.Fatalf("after freeze-clear: %v", res.Measurements())
	}
	res, _ = p.c.EventPoll(c, 3)
	found := false
	for _, m := range res.Measurements() {
		found = found || m.GV.Group() == 23
	}
	if !found {
		t.Fatalf("no frozen counter event: %v", gvs(res.Measurements()))
	}
	// Analog freeze and a no-ack freeze.
	if err := p.c.Freeze(c, false, true, app.AllObjects(app.G30V0)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "frozen analog", func() bool {
		res, err := p.c.Read(c, app.AllObjects(app.G31V0))
		return err == nil && res.Measurements()[0].Value.(app.Analog).Value == 9
	})
	if err := p.c.FreezeAtTime(c, time.Now().Add(-time.Second), 0, app.AllObjects(app.G20V0)); err != nil {
		t.Fatal(err)
	}
	var ie *dnp3.IINError
	if err := p.c.FreezeAtTime(c, time.Now().Add(time.Hour), time.Minute, app.AllObjects(app.G20V0)); !errors.As(err, &ie) {
		t.Fatalf("scheduled freeze: %v", err)
	}
}

func TestAttributes(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithAttributes(map[uint8]app.Attribute{
		app.AttrManufacturerName:    app.StringAttribute("OT Fabric"),
		app.AttrProductNameAndModel: app.StringAttribute("go-dnp3"),
		app.AttrNumBinaryInputs:     app.UintAttribute(6),
	})})
	c := ctx(t)
	all, err := p.c.ReadAttributes(c, app.AttrAllAttributes)
	if err != nil || len(all) != 3 || all[app.AttrManufacturerName].Text() != "OT Fabric" {
		t.Fatalf("all attributes: %v %v", all, err)
	}
	if n, _ := all[app.AttrNumBinaryInputs].Uint(); n != 6 {
		t.Fatal("uint attribute")
	}
	list, err := p.c.ReadAttributes(c, app.AttrListOfVariations)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := list[app.AttrListOfVariations].List()
	if err != nil || len(entries) != 3 || entries[0].Variation != app.AttrManufacturerName {
		t.Fatalf("list: %v %v", entries, err)
	}
	one, err := p.c.ReadAttributes(c, app.AttrProductNameAndModel)
	if err != nil || one[app.AttrProductNameAndModel].Text() != "go-dnp3" {
		t.Fatalf("one: %v %v", one, err)
	}
	var ie *dnp3.IINError
	if _, err := p.c.ReadAttributes(c, app.AttrSerialNumber); !errors.As(err, &ie) {
		t.Fatalf("absent attribute: %v", err)
	}
}

func TestOctetStringWrite(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	if _, err := p.c.Write(c, app.Indexed(app.GV(110, 3), app.Object{Index: 0, Value: app.OctetString{Data: []byte("abc")}})); err != nil {
		t.Fatal(err)
	}
	v, _ := p.db.Get(server.OctetString, 0)
	if string(v.(app.OctetString).Data) != "abc" {
		t.Fatalf("stored %q", v.(app.OctetString).Data)
	}
}

func TestFiles(t *testing.T) {
	fs := newMemFS()
	big := bytes.Repeat([]byte("0123456789abcdef"), 400) // 6400 octets
	fs.files["/logs/a.csv"] = big
	p := newPair(t, fullDatabase, []server.Option{server.WithFileServer(fs), server.WithMaxFragment(512, 2048)})
	c := ctx(t)

	var buf bytes.Buffer
	n, err := p.c.ReadFile(c, "/logs/a.csv", &buf, client.FileOptions{MaxBlockSize: 1000})
	if err != nil || n != int64(len(big)) || !bytes.Equal(buf.Bytes(), big) {
		t.Fatalf("read: %d %v", n, err)
	}
	_, err = p.c.ReadFile(c, "/missing", &buf, client.FileOptions{})
	var fe *dnp3.FileError
	if !errors.As(err, &fe) || fe.Status != app.FileNotFound {
		t.Fatalf("missing file: %v", err)
	}

	key, err := p.c.AuthenticateFile(c, "operator", "secret")
	if err != nil || key != 42 {
		t.Fatalf("authenticate: %v %v", key, err)
	}
	if _, err := p.c.AuthenticateFile(c, "operator", "wrong"); !errors.As(err, &fe) {
		t.Fatalf("bad credentials: %v", err)
	}
	payload := []byte(strings.Repeat("payload ", 300))
	n, err = p.c.WriteFile(c, "/up.bin", bytes.NewReader(payload), uint32(len(payload)), client.FileOptions{AuthKey: key, MaxBlockSize: 256})
	if err != nil || n != int64(len(payload)) || !bytes.Equal(fs.files["/up.bin"], payload) {
		t.Fatalf("write: %d %v", n, err)
	}
	if _, err := p.c.WriteFile(c, "/x", bytes.NewReader([]byte{1}), 1, client.FileOptions{AuthKey: 7}); !errors.As(err, &fe) || fe.Status != app.FilePermissionDenied {
		t.Fatalf("write with bad key: %v", err)
	}

	info, err := p.c.FileInfo(c, "/up.bin")
	if err != nil || info.Size != uint32(len(payload)) || info.Name != "/up.bin" {
		t.Fatalf("info: %+v %v", info, err)
	}
	entries, err := p.c.ListDirectory(c, "/", client.FileOptions{})
	if err != nil || len(entries) != 2 || entries[0].Name != "/logs/a.csv" || entries[1].Size != uint32(len(payload)) {
		t.Fatalf("directory: %+v %v", entries, err)
	}
	if err := p.c.DeleteFile(c, "/up.bin", client.FileOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := p.c.DeleteFile(c, "/up.bin", client.FileOptions{}); !errors.As(err, &fe) {
		t.Fatalf("delete twice: %v", err)
	}
	// Without a file server the functions are not supported.
	q := newPair(t, fullDatabase, nil)
	var ie *dnp3.IINError
	if _, err := q.c.FileInfo(c, "/x"); !errors.As(err, &ie) {
		t.Fatalf("no file server: %v", err)
	}
}

func TestLinkConfirmedMode(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithLink(server.Link{Confirmed: true})},
		client.WithLink(client.Link{Confirmed: true}))
	for range 3 {
		if _, err := p.c.IntegrityPoll(ctx(t)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalogValues(t *testing.T) {
	p := newPair(t, func(db *server.Database) {
		_ = db.AddAnalogInput(0, server.PointConfig{StaticVariation: 2}, app.Analog{Value: 40000, Flags: app.FlagOnline})
		_ = db.AddAnalogInput(1, server.PointConfig{StaticVariation: 6}, app.Analog{Value: math.Pi, Flags: app.FlagOnline})
	}, nil)
	res, err := p.c.IntegrityPoll(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if v := ms[0].Value.(app.Analog); v.Value != 32767 || v.Flags&app.FlagOverRange == 0 {
		t.Fatalf("clamped 16-bit: %+v", v)
	}
	if v := ms[1].Value.(app.Analog); v.Value != math.Pi {
		t.Fatalf("double: %+v", v)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAutomaticIntegrity(t *testing.T) {
	p := newPair(t, fullDatabase, nil, client.WithAutoIntegrity(true))
	_ = p.db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	// The first response reports DEVICE_RESTART: the client clears it and
	// runs an integrity poll, whose measurements reach the handler.
	if _, err := p.c.Read(ctx(t), app.AllObjects(app.G80V1)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "automatic integrity poll", func() bool {
		p.rec.mu.Lock()
		defer p.rec.mu.Unlock()
		statics, events := 0, 0
		for _, m := range p.rec.ms {
			if m.Event {
				events++
			} else {
				statics++
			}
		}
		return statics >= 15 && events >= 1
	})
	waitUntil(t, "restart cleared", func() bool {
		res, err := p.c.Read(ctx(t), app.AllObjects(app.G80V1))
		return err == nil && !res.IIN.Has(app.IINDeviceRestart)
	})
}

// readCounter counts the READ requests an outstation handled.
type readCounter struct {
	dnp3.NopMetrics
	mu    sync.Mutex
	reads int
}

func (r *readCounter) OnHandled(_ net.Addr, fc app.FunctionCode, _ time.Duration) {
	if fc == app.FuncRead {
		r.mu.Lock()
		r.reads++
		r.mu.Unlock()
	}
}
func (r *readCounter) OnEventsDiscarded(int, int)         {}
func (r *readCounter) OnUnsolicited(net.Addr, int, error) {}

// TestNoRedundantIntegrityPoll: the startup sequence's integrity poll
// makes the automatic one, queued by the restart bit of an earlier
// response, unnecessary. It used to run as well and take the events meant
// for unsolicited reporting.
func TestNoRedundantIntegrityPoll(t *testing.T) {
	m := &readCounter{}
	_ = newPair(t, fullDatabase, []server.Option{server.WithMetrics(m), server.WithUnsolicited(server.Unsolicited{Enabled: true})},
		client.WithAutoIntegrity(true),
		client.WithStartup(client.Startup{DisableUnsolicited: true, Integrity: true, EnableUnsolicited: []int{1, 2, 3}}))
	time.Sleep(300 * time.Millisecond) // let any automatic task run
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reads != 1 {
		t.Fatalf("%d READs, want only the startup integrity poll", m.reads)
	}
}

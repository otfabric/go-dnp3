// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

func freezeAt(seq uint8, at time.Time, interval time.Duration, hs ...app.Header) *app.Fragment {
	ts := app.Timestamp(0)
	if !at.IsZero() {
		ts = app.TimestampOf(at)
	}
	return req(seq, app.FuncFreezeAtTime, append([]app.Header{app.Counted(app.G50V2,
		app.AbsoluteTime{Time: ts, Interval: uint32(interval.Milliseconds())})}, hs...)...)
}

func TestFreezeAtTime(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddCounter(0, PointConfig{}, app.Counter{Value: 1, Flags: app.FlagOnline})
	_ = db.AddFrozenCounter(0, PointConfig{}, app.Counter{Flags: app.FlagOnline})
	frozen := func() uint32 {
		v, _ := db.Get(FrozenCounter, 0)
		return v.(app.Counter).Value
	}
	waitFrozen := func(want uint32) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for frozen() != want {
			if time.Now().After(deadline) {
				t.Fatalf("frozen counter %d, want %d", frozen(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	counters := app.AllObjects(app.G20V0)

	// Every 30 ms from a start that has passed: the next occurrences.
	m.send(freezeAt(1, time.Now().Add(-time.Hour), 30*time.Millisecond, counters))
	if f := m.recvFunc(app.FuncResponse); f.IIN&(app.IINParameterError|app.IINObjectUnknown) != 0 {
		t.Fatalf("periodic freeze: %v", f)
	}
	waitFrozen(1)
	_ = db.UpdateCounter(0, app.Counter{Value: 2, Flags: app.FlagOnline})
	waitFrozen(2)

	// At most MaxScheduledFreezes wait; Close stops them.
	for i := range MaxScheduledFreezes - 1 {
		m.send(freezeAt(uint8(2+i), time.Now().Add(time.Hour), 0, counters))
		if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINParameterError) {
			t.Fatalf("schedule %d refused", i+2)
		}
	}
	m.send(freezeAt(20, time.Now().Add(time.Hour), 0, counters))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatal("a schedule past the limit was accepted")
	}
	// Headers that cannot be frozen, and a request without the time.
	m.send(freezeAt(21, time.Now().Add(time.Hour), 0, app.AllObjects(app.G1V0)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("freeze of binary inputs: %v", f)
	}
	m.send(freezeAt(22, time.Now().Add(time.Hour), 0, app.CountOf(app.G20V0, 1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("freeze with a count qualifier: %v", f)
	}
	m.send(req(23, app.FuncFreezeAtTime, counters))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("FREEZE_AT_TIME without the time: %v", f)
	}
	_ = m.srv.Close()
	if n := len(m.srv.freezes); n != 0 {
		t.Fatalf("%d scheduled freezes after Close", n)
	}
	if m.srv.scheduleFreeze(time.Now().Add(time.Hour), 0, nil) {
		t.Fatal("a freeze scheduled on a closed server")
	}
}

func TestAttributeSetReadWrite(t *testing.T) {
	m := newMaster(t, WithAttributeSet(1, map[uint8]app.Attribute{
		1: app.StringAttribute("fixed"), 10: app.StringAttribute("text"),
	}, 10), WithAttributeSet(2, map[uint8]app.Attribute{1: app.UintAttribute(5)}))
	m.send(req(1, app.FuncRead, app.IndexRange(app.GV(0, app.AttrAllAttributes), 1, 2)))
	f := m.recvFunc(app.FuncResponse)
	sets := map[uint32]int{}
	for _, h := range f.Headers {
		sets[h.Start]++
	}
	if sets[1] != 2 || sets[2] != 1 {
		t.Fatalf("read of sets 1 and 2: %v", f)
	}
	m.send(req(2, app.FuncRead, app.IndexRange(app.GV(0, 7), 1, 1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("unknown variation: %v", f)
	}
	m.send(req(3, app.FuncRead, app.IndexRange(app.GV(0, app.AttrAllAttributes), 3, 3)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("unknown set: %v", f)
	}
	// A write by index prefix and by range; the handler is no
	// AttributeSetWriteHandler, so the outstation only stores it.
	m.send(req(4, app.FuncWrite, app.Indexed(app.GV(0, 10), app.Object{Index: 1, Value: app.StringAttribute("new")})))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINParameterError) {
		t.Fatalf("indexed write: %v", f)
	}
	m.send(req(5, app.FuncRead, app.IndexRange(app.GV(0, 10), 1, 1)))
	if f := m.recvFunc(app.FuncResponse); string(f.Headers[0].Objects[0].Value.(app.Attribute).Data) != "new" {
		t.Fatalf("after the write: %v", f)
	}
	m.send(req(6, app.FuncWrite, app.Ranged(app.GV(0, 1), 2, app.UintAttribute(9))))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("write of a read-only attribute: %v", f)
	}
}

// attrRecorder is a handler with both attribute write interfaces.
type attrRecorder struct {
	NopHandler
	set0, sets []string
}

func (r *attrRecorder) WriteAttribute(_ context.Context, _ uint8, a app.Attribute) error {
	if string(a.Data) == "no" {
		return errors.New("refused")
	}
	r.set0 = append(r.set0, string(a.Data))
	return nil
}
func (r *attrRecorder) WriteOctetString(context.Context, uint32, []byte) error { return nil }
func (r *attrRecorder) WriteAttributeSet(_ context.Context, _ uint16, _ uint8, a app.Attribute) error {
	if string(a.Data) == "no" {
		return errors.New("refused")
	}
	r.sets = append(r.sets, string(a.Data))
	return nil
}

func TestAttributeWriteHandlers(t *testing.T) {
	h := &attrRecorder{}
	m := newMaster(t, WithHandler(h), WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: app.StringAttribute("m")}),
		WithAttributeSet(1, map[uint8]app.Attribute{10: app.StringAttribute("t"), 11: app.StringAttribute("r")}, 10))
	write := func(seq uint8, set uint32, v uint8, val string) app.IIN {
		m.send(req(seq, app.FuncWrite, app.Ranged(app.GV(0, v), set, app.StringAttribute(val))))
		return m.recvFunc(app.FuncResponse).IIN
	}
	if iin := write(1, 0, app.AttrManufacturerName, "new"); iin.Has(app.IINParameterError) || len(h.set0) != 1 {
		t.Fatalf("set 0 write: %s %v", iin, h.set0)
	}
	if iin := write(2, 0, app.AttrManufacturerName, "no"); !iin.Has(app.IINParameterError) {
		t.Fatal("set 0 write refused by the handler was accepted")
	}
	if iin := write(3, 1, 10, "fine"); iin.Has(app.IINParameterError) || len(h.sets) != 1 {
		t.Fatalf("set 1 write: %s %v", iin, h.sets)
	}
	if iin := write(4, 1, 10, "no"); !iin.Has(app.IINParameterError) {
		t.Fatal("set 1 write refused by the handler was accepted")
	}
	if iin := write(5, 7, 10, "x"); !iin.Has(app.IINParameterError) {
		t.Fatal("write to an unknown set accepted")
	}
	// The list of variations says which are writable: set 0 all (the
	// handler is a WriteHandler), set 1 the ones named.
	for _, c := range []struct {
		set  uint32
		want map[uint8]bool
	}{{0, map[uint8]bool{app.AttrManufacturerName: true}}, {1, map[uint8]bool{10: true, 11: false}}} {
		m.send(req(6, app.FuncRead, app.IndexRange(app.GV(0, app.AttrListOfVariations), c.set, c.set)))
		entries, _ := m.recvFunc(app.FuncResponse).Headers[0].Objects[0].Value.(app.Attribute).List()
		for _, e := range entries {
			if e.Writable != c.want[e.Variation] {
				t.Errorf("set %d variation %d writable %v", c.set, e.Variation, e.Writable)
			}
		}
	}
	if _, err := New(WithAttributeSet(1, map[uint8]app.Attribute{1: app.UintAttribute(1)}, 2)); err == nil {
		t.Fatal("a writable variation that does not exist was accepted")
	}
}

func TestFreezeEdges(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddFrozenCounter(0, PointConfig{}, app.Counter{Flags: app.FlagOnline})
	counters := app.AllObjects(app.G20V0)
	// An immediate freeze.
	m.send(req(1, app.FuncImmediateFreeze, counters))
	m.recvFunc(app.FuncResponse)
	if v, _ := db.Get(FrozenCounter, 0); v.(app.Counter).Value != 1 {
		t.Fatalf("immediate freeze: %v", v)
	}
	// A time that has passed, without an interval: refused.
	m.send(freezeAt(2, time.Now().Add(-time.Minute), 0, counters))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("past time without an interval: %v", f)
	}
	// Once, soon: done, it is no longer waiting.
	_ = db.UpdateCounter(0, app.Counter{Value: 2, Flags: app.FlagOnline})
	m.send(freezeAt(4, time.Now().Add(30*time.Millisecond), 0, counters))
	m.recvFunc(app.FuncResponse)
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.srv.mu.Lock()
		n := len(m.srv.freezes)
		m.srv.mu.Unlock()
		if v, _ := db.Get(FrozenCounter, 0); v.(app.Counter).Value == 2 && n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("one-shot freeze: %d waiting", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Time 0 with an interval: from now, every interval.
	_ = db.UpdateCounter(0, app.Counter{Value: 3, Flags: app.FlagOnline})
	m.send(freezeAt(3, time.Time{}, 20*time.Millisecond, counters))
	m.recvFunc(app.FuncResponse)
	deadline = time.Now().Add(3 * time.Second)
	for {
		if v, _ := db.Get(FrozenCounter, 0); v.(app.Counter).Value == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the periodic freeze from time 0 did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBroadcastFirst: a broadcast as the master's first request.
func TestBroadcastFirst(t *testing.T) {
	h := &countingHandler{}
	srv, err := New(WithHandler(h))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ch := channel.New(conn, channel.Config{})
	sess := ch.AddSession(channel.SessionConfig{Local: 1, Remote: 10, Master: true})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	b, _ := req(0, app.FuncDirectOperateNoAck, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})).Encode()
	if err := sess.SendBroadcast(context.Background(), b, link.BroadcastNoConfirm); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.count() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("broadcast as the first frame not executed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAttributeHugeRange(t *testing.T) {
	m := newMaster(t, WithAttributeSet(1, map[uint8]app.Attribute{1: app.UintAttribute(1)}))
	m.send(req(1, app.FuncRead, app.Header{GV: app.GV(0, app.AttrAllAttributes), Qualifier: app.Qual4ByteStartStop, Start: 0, Stop: 0xFFFFFFFF}))
	f := m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINParameterError) || len(f.Headers) != 1 {
		t.Fatalf("read of every set: %v", f)
	}
}

// TestHugeRanges: a READ, deadband read or freeze naming four billion
// indexes is answered at once.
func TestHugeRanges(t *testing.T) {
	m := newMaster(t)
	huge := func(gv app.GroupVariation) app.Header {
		return app.Header{GV: gv, Qualifier: app.Qual4ByteStartStop, Start: 0, Stop: 0xFFFFFFFF}
	}
	for i, h := range []app.Header{huge(app.G30V0), huge(app.G34V0), huge(app.G121V1), huge(app.G1V0)} {
		start := time.Now()
		m.send(req(uint8(i), app.FuncRead, h))
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) && h.GV != app.G121V1 {
			t.Errorf("%s over every index: %v", h.GV, f)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s over every index took %v", h.GV, d)
		}
	}
}

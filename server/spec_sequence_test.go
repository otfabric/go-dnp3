// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// Spec tests of request sequencing, response construction and
// unsolicited responses at the outstation (IEEE 1815-2012 4.3, 4.4.2,
// 4.6.6, 4.7).

func latchOn(idx uint32) app.Header {
	return app.Indexed(app.G12V1, app.Object{Index: idx, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
}

// TestSpec4_3_Rule22_FirstRequestAfterRestart: 4.3 Rule 22 (p. 40): an
// outstation that restarts shall ignore the sequence number of the first
// request it receives after the restart and execute it, also when it
// repeats the last request before.
func TestSpec4_3_Rule22_FirstRequestAfterRestart(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	op := req(3, app.FuncDirectOperate, latchOn(0))
	m.send(op)
	m.recvFunc(app.FuncResponse)
	m.send(op) // a repeat: answered, not executed
	m.recvFunc(app.FuncResponse)
	if h.count() != 1 {
		t.Fatalf("%d controls before the restart", h.count())
	}
	m.srv.Restart()
	m.send(op)
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 || h.count() != 2 {
		t.Fatalf("after the restart: %s, %d controls", f, h.count())
	}
}

// TestSpec4_3_Rule19_BroadcastSeqIgnored: 4.3 Rule 19 (p. 39): the
// sequence number of a broadcast is ignored. It is not a request a
// unicast one could repeat: the same octets sent unicast are executed and
// answered.
func TestSpec4_3_Rule19_BroadcastSeqIgnored(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	op := req(6, app.FuncDirectOperate, latchOn(0))
	m.sendBroadcastTo(op, link.BroadcastNoConfirm)
	m.send(op)
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 6 || h.count() != 2 {
		t.Fatalf("unicast after the broadcast: %s, %d controls", f, h.count())
	}
}

// TestSpecTable4_9_RepeatedSelectKeepsTimer: Table 4-9 (p. 50): a SELECT
// repeated with the same sequence number and octets is answered with the
// response to the first; the select timer is not started again.
func TestSpecTable4_9_RepeatedSelectKeepsTimer(t *testing.T) {
	m := newMaster(t, WithHandler(&countingHandler{}), WithSelectTimeout(400*time.Millisecond))
	sel := req(1, app.FuncSelect, latchOn(0))
	m.send(sel)
	first := m.recvFunc(app.FuncResponse)
	time.Sleep(250 * time.Millisecond)
	m.send(sel)
	again := m.recvFunc(app.FuncResponse)
	a, _ := first.Encode()
	b, _ := again.Encode()
	if string(a) != string(b) {
		t.Fatalf("repeat answered with %s, want %s", again, first)
	}
	time.Sleep(250 * time.Millisecond) // 500 ms after the first SELECT
	m.send(req(2, app.FuncOperate, latchOn(0)))
	if f := m.recvFunc(app.FuncResponse); f.Headers[0].Objects[0].Value.(app.CROB).Status != app.StatusTimeout {
		t.Fatalf("OPERATE 500 ms after the first SELECT: %s", f)
	}
}

// TestSpec4_4_2_1_Rules4_5_EventsOnceAndFirst: 4.4.2.1 Rule 4 (p. 42): an
// event should appear once in a response, also when two headers name it;
// Rule 5: the events come before the static data.
func TestSpec4_4_2_1_Rules4_5_EventsOnceAndFirst(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.AllObjects(app.G60V2), app.AllObjects(app.G2V0)))
	f := m.recvFunc(app.FuncResponse)
	n := 0
	for _, h := range f.Headers {
		n += len(h.Objects)
	}
	if n != 2 {
		t.Fatalf("class 1 and g2 in one READ: %s", f)
	}
	m.send(confirm(1, false))
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 99, Flags: app.FlagOnline})
	m.send(req(2, app.FuncRead, app.ClassHeaders(0, 1, 2, 3)...))
	f = m.recvFunc(app.FuncResponse)
	static := false
	for _, h := range f.Headers {
		if !h.GV.IsEvent() {
			static = true
		} else if static {
			t.Fatalf("event header %s after static data: %s", h.GV, f)
		}
	}
	if !static || !f.Headers[0].GV.IsEvent() {
		t.Fatalf("integrity poll: %s", f)
	}
}

// manyEvents adds binary inputs 10 to 10+n-1 in class 1 and changes each
// in one batch.
func manyEvents(t *testing.T, db *Database, n uint32) {
	t.Helper()
	for i := range n {
		_ = db.AddBinaryInput(10+i, PointConfig{Class: 1, EventVariation: 2}, app.Binary{Flags: app.FlagOnline})
	}
	_ = db.Batch(func(b *Batch) error {
		for i := range n {
			_ = b.Update(BinaryInput, 10+i, app.Binary{Value: true, Flags: app.FlagOnline}, EventOnChange)
		}
		return nil
	})
}

// TestSpec4_4_2_1_Rule1_NewRequestCancelsResponse: 4.4.2.1 Rule 1
// (p. 41) and 6.2 (p. 161): a fragment of a multi-fragment response is
// sent when the previous one is confirmed; a confirmation with another
// sequence number is ignored; a new request ends the response, and the
// events of the fragments not confirmed stay in the buffer (IIN1.1).
func TestSpec4_4_2_1_Rule1_NewRequestCancelsResponse(t *testing.T) {
	m := newMaster(t, WithMaxFragment(249, 2048))
	manyEvents(t, m.srv.Database(), 60)
	m.send(req(1, app.FuncRead, app.AllObjects(app.G60V2)))
	f := m.recvFunc(app.FuncResponse)
	if f.Control.FIN || !f.Control.CON {
		t.Fatalf("first fragment %s", f)
	}
	m.send(confirm(9, false))
	m.none(150 * time.Millisecond)
	m.send(req(2, app.FuncRead, app.AllObjects(app.G80V1)))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 2 || !f.IIN.Has(app.IINClass1Events) {
		t.Fatalf("the new request: %s", f)
	}
	m.send(req(3, app.FuncRead, app.AllObjects(app.G60V2)))
	g := m.recvFunc(app.FuncResponse)
	if g.Headers[0].Objects[0].Index != f.Headers[0].Objects[0].Index {
		t.Fatalf("the unconfirmed events again: %s, before %s", g, f)
	}
}

// unsolMaster is an outstation reporting classes unsolicited, with the
// null response confirmed.
func unsolMaster(t *testing.T, u Unsolicited, opts ...Option) *master {
	t.Helper()
	u.Enabled = true
	m := newMaster(t, append([]Option{WithUnsolicited(u)}, opts...)...)
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	return m
}

// TestSpec4_6_6_Rule3_UnsolicitedSingleFragment: 4.6.6 Rule 3 (p. 91):
// an unsolicited response is a single fragment, FIR and FIN set; events
// that do not fit wait for the next one.
func TestSpec4_6_6_Rule3_UnsolicitedSingleFragment(t *testing.T) {
	m := unsolMaster(t, Unsolicited{Classes: []Class{1}}, WithMaxFragment(249, 2048))
	manyEvents(t, m.srv.Database(), 60)
	n, responses := 0, 0
	for n < 60 {
		u := m.recvFunc(app.FuncUnsolicitedResponse)
		if !u.Control.FIR || !u.Control.FIN {
			t.Fatalf("unsolicited %s", u)
		}
		for _, h := range u.Headers {
			n += len(h.Objects)
		}
		responses++
		m.send(confirm(u.Control.Seq, true))
	}
	if n != 60 || responses < 2 {
		t.Fatalf("%d events in %d responses", n, responses)
	}
}

// TestSpec4_6_6_Rule8_NoUnsolicitedDuringSolicitedConfirm: 4.6.6 Rule 8
// (p. 92): no unsolicited response is sent while a solicited response
// waits for its confirmation.
func TestSpec4_6_6_Rule8_NoUnsolicitedDuringSolicitedConfirm(t *testing.T) {
	m := unsolMaster(t, Unsolicited{Classes: []Class{2}}, WithConfirmTimeout(5*time.Second))
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline}) // class 1: not unsolicited
	m.send(req(1, app.FuncRead, app.AllObjects(app.G60V2)))
	if f := m.recvFunc(app.FuncResponse); !f.Control.CON {
		t.Fatalf("event response %s", f)
	}
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 77, Flags: app.FlagOnline})
	m.none(200 * time.Millisecond)
	m.send(confirm(1, false))
	if u := m.recvFunc(app.FuncUnsolicitedResponse); len(u.Headers) != 1 {
		t.Fatalf("after the confirmation: %s", u)
	}
}

// TestSpec4_6_6_Rule10_WrongSeqConfirmIgnored: 4.6.6 Rule 10 (p. 92): a
// confirmation of an unsolicited response with another sequence number is
// not its confirmation; the response is repeated, identical (Rule 12).
func TestSpec4_6_6_Rule10_WrongSeqConfirmIgnored(t *testing.T) {
	m := unsolMaster(t, Unsolicited{Classes: []Class{1}, Retries: 2})
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	u := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(app.NextSeq(u.Control.Seq), true))
	m.send(confirm(u.Control.Seq, false)) // a solicited confirmation
	r := m.recvFunc(app.FuncUnsolicitedResponse)
	a, _ := u.Encode()
	b, _ := r.Encode()
	if string(a) != string(b) {
		t.Fatalf("repeat %s, want %s", r, u)
	}
	m.send(confirm(u.Control.Seq, true))
	m.none(450 * time.Millisecond)
}

// TestSpec4_6_6_Rules16_18_DeferredRead: 4.6.6 Rule 16 (p. 93): a READ
// received while an unsolicited response waits for its confirmation is
// answered after it; Rule 18 (p. 94): a newer request replaces it, and
// only the newer READ is answered. Rule 17: a request other than READ is
// answered at once, and the confirmation is still awaited.
func TestSpec4_6_6_Rules16_18_DeferredRead(t *testing.T) {
	m := unsolMaster(t, Unsolicited{Classes: []Class{1}}, WithConfirmTimeout(5*time.Second))
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	u := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(req(1, app.FuncRead, app.ClassHeaders(0)...))
	m.send(req(2, app.FuncRead, app.AllObjects(app.G80V1)))
	m.none(150 * time.Millisecond)
	m.send(req(3, app.FuncDelayMeasure))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 3 {
		t.Fatalf("DELAY_MEASURE during the wait: %s", f)
	}
	m.send(req(4, app.FuncRead, app.AllObjects(app.G80V1)))
	m.send(confirm(u.Control.Seq, true))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 4 {
		t.Fatalf("after the confirmation: %s, want the response to seq 4", f)
	}
	m.none(150 * time.Millisecond)
}

// TestSpec4_4_13_NoUnsolicitedBeforeEnable: 4.4.13 (p. 60) and 5.1.1.1.1
// Rule 3 (p. 101): with no class enabled at startup, events are not sent
// unsolicited, also after the null response is confirmed, until the
// master enables their class; then they are.
func TestSpec4_4_13_NoUnsolicitedBeforeEnable(t *testing.T) {
	m := unsolMaster(t, Unsolicited{})
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.none(200 * time.Millisecond)
	m.send(req(1, app.FuncEnableUnsolicited, app.AllObjects(app.G60V2)))
	if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("ENABLE_UNSOLICITED: %s", f)
	}
	if u := m.recvFunc(app.FuncUnsolicitedResponse); len(u.Headers) != 1 {
		t.Fatalf("after ENABLE_UNSOLICITED: %s", u)
	}
}

// appRecorder is an ApplicationHandler that records the functions.
type appRecorder struct {
	NopHandler
	mu  sync.Mutex
	fcs []app.FunctionCode
}

func (h *appRecorder) Application(_ context.Context, fc app.FunctionCode, _ []app.Header) app.IIN {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fcs = append(h.fcs, fc)
	return 0
}

// TestSpec4_4_11_ApplicationFunctions: INITIALIZE_APPL, START_APPL and
// STOP_APPL (4.4.11, p. 59) go to the ApplicationHandler; an outstation
// without one does not support them (IIN2.0, 4.5.9, p. 84).
func TestSpec4_4_11_ApplicationFunctions(t *testing.T) {
	fcs := []app.FunctionCode{app.FuncInitializeApplication, app.FuncStartApplication, app.FuncStopApplication}
	without := newMaster(t)
	h := &appRecorder{}
	with := newMaster(t, WithHandler(h))
	for i, fc := range fcs {
		without.send(req(uint8(i+1), fc))
		if f := without.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != app.IINNoFuncCodeSupport {
			t.Errorf("%s without a handler: %s", fc, f)
		}
		with.send(req(uint8(i+1), fc))
		if f := with.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 {
			t.Errorf("%s with a handler: %s", fc, f)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.fcs) != 3 || h.fcs[0] != fcs[0] || h.fcs[1] != fcs[1] || h.fcs[2] != fcs[2] {
		t.Fatalf("handler called for %v", h.fcs)
	}
}

// TestSpec4_5_8_ClearRestartTwice: clearing IIN1.7 when it is already
// clear is a valid write of 0 to g80v1 index 7 (4.5.8, p. 84).
func TestSpec4_5_8_ClearRestartTwice(t *testing.T) {
	m := newMaster(t)
	for seq := range uint8(2) {
		m.send(req(seq, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})))
		if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 || f.IIN.Has(app.IINDeviceRestart) {
			t.Fatalf("write %d: %s", seq+1, f)
		}
	}
}

// crobRecorder records the controls it operates.
type crobRecorder struct {
	NopHandler
	mu   sync.Mutex
	cmds []Command
}

func (h *crobRecorder) Select(context.Context, Command) app.CommandStatus { return app.StatusSuccess }
func (h *crobRecorder) Operate(_ context.Context, c Command, _ OperateType) app.CommandStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cmds = append(h.cmds, c)
	return app.StatusSuccess
}

// TestSpecA_8_1_2_2_CROBPassedOn: the fields of a CROB reach the handler
// as the master sent them, a count of 0 among them, whose meaning is the
// handler's to implement (A.8.1.2.2, p. 506).
func TestSpecA_8_1_2_2_CROBPassedOn(t *testing.T) {
	h := &crobRecorder{}
	m := newMaster(t, WithHandler(h))
	crobs := []app.CROB{
		{Op: app.OpPulseOn, Count: 0, OnTime: 100, OffTime: 200},
		{Op: app.OpPulseOff, Count: 3, OnTime: 1000, OffTime: 2000},
	}
	m.send(req(1, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 4, Value: crobs[0]}, app.Object{Index: 5, Value: crobs[1]})))
	m.recvFunc(app.FuncResponse)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.cmds) != 2 {
		t.Fatalf("%d controls", len(h.cmds))
	}
	for i, c := range h.cmds {
		if c.Value.(app.CROB) != crobs[i] || c.Index != uint32(4+i) || c.GV != app.G12V1 {
			t.Errorf("control %d: %+v, want %+v", i, c, crobs[i])
		}
	}
}

// TestSpecTable4_16_BroadcastFunctions: 4.7 (p. 99): an outstation shall
// support the functions of Table 4-16 (p. 100) sent to a broadcast address
// as it does sent to its own: they are carried out, and not answered.
func TestSpecTable4_16_BroadcastFunctions(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithTimeSync(time.Hour), WithUnsolicited(Unsolicited{Enabled: true}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	db := m.srv.Database()
	_ = db.AddFrozenCounter(0, PointConfig{}, app.Counter{Flags: app.FlagOnline})
	seq := uint8(0)
	// broadcast sends r to 0xFFFD; the outstation answers only the
	// unicast request after it.
	broadcast := func(fc app.FunctionCode, hs ...app.Header) {
		t.Helper()
		seq = app.NextSeq(seq)
		m.sendBroadcastTo(req(seq, fc, hs...), link.BroadcastNoConfirm)
		seq = app.NextSeq(seq)
		m.send(req(seq, app.FuncDelayMeasure))
		if f := m.recvFunc(app.FuncResponse); f.Control.Seq != seq {
			t.Fatalf("broadcast %s answered: %s", fc, f)
		}
	}
	frozen := func() uint32 { v, _ := db.Get(FrozenCounter, 0); return v.(app.Counter).Value }
	counter := func() uint32 { v, _ := db.Get(Counter, 0); return v.(app.Counter).Value }

	at := time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)
	broadcast(app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.TimestampOf(at)}))
	if d := m.srv.Now().Sub(at); d < 0 || d > 5*time.Second {
		t.Fatalf("clock after WRITE g50v1: %v", m.srv.Now())
	}
	broadcast(app.FuncRecordCurrentTime)
	at = at.Add(time.Hour)
	broadcast(app.FuncWrite, app.Counted(app.G50V3, app.AbsoluteTime{Time: app.TimestampOf(at)}))
	if d := m.srv.Now().Sub(at); d < 0 || d > 5*time.Second {
		t.Fatalf("clock after WRITE g50v3: %v", m.srv.Now())
	}
	broadcast(app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{}))
	broadcast(app.FuncDirectOperateNoAck, latchOn(0))
	if h.count() != 1 {
		t.Fatalf("DIRECT_OPERATE_NR: %d controls", h.count())
	}
	broadcast(app.FuncImmediateFreezeNoAck, app.AllObjects(app.G20V0))
	if frozen() != 1 {
		t.Fatalf("IMMED_FREEZE_NR: frozen %d", frozen())
	}
	_ = db.UpdateCounter(0, app.Counter{Value: 5, Flags: app.FlagOnline})
	broadcast(app.FuncFreezeClearNoAck, app.AllObjects(app.G20V0))
	if frozen() != 5 || counter() != 0 {
		t.Fatalf("FREEZE_CLEAR_NR: frozen %d, counter %d", frozen(), counter())
	}
	_ = db.UpdateCounter(0, app.Counter{Value: 8, Flags: app.FlagOnline})
	broadcast(app.FuncFreezeAtTimeNoAck, app.Counted(app.G50V2, app.AbsoluteTime{}), app.AllObjects(app.G20V0))
	if frozen() != 8 {
		t.Fatalf("FREEZE_AT_TIME_NR: frozen %d", frozen())
	}
	broadcast(app.FuncAssignClass, app.AllObjects(app.G60V3), app.IndexRange(app.G1V0, 1, 1))
	broadcast(app.FuncEnableUnsolicited, app.AllObjects(app.G60V3))
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	u := m.recvFunc(app.FuncUnsolicitedResponse)
	if len(u.Headers) != 1 || u.Headers[0].GV.Group() != 2 || u.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("unsolicited after ASSIGN_CLASS and ENABLE_UNSOLICITED: %s", u)
	}
	m.send(confirm(u.Control.Seq, true))
	broadcast(app.FuncDisableUnsolicited, app.AllObjects(app.G60V3))
	_ = db.UpdateBinaryInput(1, app.Binary{Flags: app.FlagOnline})
	m.none(200 * time.Millisecond)
}

// connectMaster connects a scripted master with link address local to the
// outstation listening at addr.
func connectMaster(t *testing.T, srv *Server, addr string, local link.Address) *master {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	m := &master{t: t, in: make(chan *app.Fragment, 32), srv: srv}
	m.ch = channel.New(conn, channel.Config{})
	m.sess = m.ch.AddSession(channel.SessionConfig{Local: local, Remote: 10, Master: true,
		OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil {
				m.in <- f
			}
		}})
	m.ch.Start()
	t.Cleanup(func() {
		m.ch.Close(nil)
		<-m.ch.Done()
	})
	return m
}

// TestSpec5_1_1_1_1_NullOnEveryConnection: an outstation configured for
// unsolicited reporting starts it with a null unsolicited response
// (5.1.1.1.1 Rule 2, p. 101). go-dnp3 starts it on every connection of the
// master, as Unsolicited.Enabled documents: a master that connects again
// gets the null response again, retried until it is confirmed.
func TestSpec5_1_1_1_1_NullOnEveryConnection(t *testing.T) {
	srv, err := New(WithMasters(1), WithConfirmTimeout(100*time.Millisecond), WithUnsolicited(Unsolicited{Enabled: true, Retries: 1}))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	first := connectMaster(t, srv, l.Addr().String(), 1)
	null := first.recvFunc(app.FuncUnsolicitedResponse)
	first.send(confirm(null.Control.Seq, true))
	first.none(250 * time.Millisecond)
	first.ch.Close(nil)
	<-first.ch.Done()

	again := connectMaster(t, srv, l.Addr().String(), 1)
	for range 3 { // past Retries
		if u := again.recvFunc(app.FuncUnsolicitedResponse); len(u.Headers) != 0 {
			t.Fatalf("on the new connection: %s", u)
		}
	}
}

// TestSpec4_5_5_NeedTimeOfTheDeviceClock: IIN1.4 says the outstation's
// clock needs time (4.5.5, p. 83). There is one clock: a time written by
// one master clears IIN1.4 for every master.
func TestSpec4_5_5_NeedTimeOfTheDeviceClock(t *testing.T) {
	srv, err := New(WithMasters(1, 2), WithTimeSync(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	one := connectMaster(t, srv, l.Addr().String(), 1)
	two := connectMaster(t, srv, l.Addr().String(), 2)
	two.send(req(1, app.FuncRead, app.AllObjects(app.G80V1)))
	if f := two.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("before the time is written: %s", f)
	}
	one.send(req(1, app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.Now()})))
	if f := one.recvFunc(app.FuncResponse); f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("master 1 after its write: %s", f)
	}
	two.send(req(2, app.FuncRead, app.AllObjects(app.G80V1)))
	if f := two.recvFunc(app.FuncResponse); f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("master 2 after master 1 wrote the time: %s", f)
	}
}

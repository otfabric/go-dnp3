// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
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

// TestSpecTable7_8_Row24_KeyChangeInWaitForReply: Table 7-8 row 24, p.221:
// a valid session key change received in Wait for Reply discards the
// pending critical ASDU, stores the new keys with Key Status OK and is
// answered with a key status message; the reply to the challenge that
// comes after it is unexpected in Security Idle and executes nothing, and
// the new keys authenticate the next critical request.
func TestSpecTable7_8_Row24_KeyChangeInWaitForReply(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	st := m.keyStatus(0, 1)
	chf, raw, critical := m.challenge(req(1, app.FuncDirectOperate, specCROB))
	// The key change wraps the key status sent before the challenge.
	st.MACValue = nil
	msg, _ := app.AppendObjectValue(nil, app.G120V5, st)
	control, monitoring := bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x32}, 16)
	plain, _ := secauth.KeyChangeData(control, monitoring, msg)
	wrapped, _ := secauth.KeyWrap(specUpdateKey, plain)
	m.send(req(2, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: 1, WrappedKeys: wrapped})))
	f := m.recvFunc(app.FuncAuthResponse)
	if done, ok := f.Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus); !ok || done.Status != app.KeyStatusOK || f.Control.Seq != 2 {
		t.Fatalf("key change in Wait for Reply: %v", f)
	}
	m.reply(chf, raw, critical, control)
	m.send(readIIN(3))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 3 {
		t.Fatalf("after the late reply: %v, want the response to the READ", f)
	}
	if h.count() != 0 {
		t.Fatalf("%d controls executed: the discarded request ran", h.count())
	}
	chf, raw, critical = m.challenge(req(4, app.FuncDirectOperate, specCROB))
	m.reply(chf, raw, critical, control)
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 4 || h.count() != 1 {
		t.Fatalf("with the new keys: %v, %d executed", f, h.count())
	}
}

// TestSpecTable7_8_Row21_NoAggressiveModeInWaitForReply: Table 7-8 row 21,
// p.220: with aggressive mode disabled, an aggressive mode request in Wait
// for Reply, while Error Messages Sent <= Max Error Messages Sent, also
// discards the pending critical ASDU and transmits error 4, aggressive
// mode not supported, returning to Security Idle: the reply to the
// challenge that comes after it executes nothing.
func TestSpecTable7_8_Row21_NoAggressiveModeInWaitForReply(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, NoAggressiveMode: true}))
	chf, raw, critical := m.challenge(req(1, app.FuncDirectOperate, specCROB))
	ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	m.send(aggressiveReq(2, ch.CSQ+1, raw, testSessionKey, specCROB))
	f := m.recvFunc(app.FuncAuthResponse)
	if e := authErr(t, f); e.Code != app.AuthErrAggressiveModeNotSupported || f.Control.Seq != 2 {
		t.Fatalf("aggressive mode in Wait for Reply: %v %+v", f.Control, e)
	}
	m.reply(chf, raw, critical, testSessionKey)
	m.send(readIIN(3))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 3 {
		t.Fatalf("after the reply: %v, want the response to the READ", f)
	}
	if h.count() != 0 {
		t.Fatalf("%d controls executed: the discarded request ran", h.count())
	}
}

// TestSpecTable7_8_Row20_NoAggressiveModeWithoutError: Table 7-8 row 20,
// p.220: with aggressive mode disabled an aggressive mode request is
// discarded; the error message is transmitted only while Error Messages
// Sent <= Max Error Messages Sent (threshold 2, Table 7-6 #10, p.206), and
// in Wait for Reply the outstation stays there (row 21 applies only below
// that maximum): the pending critical request runs when its reply comes.
// Table 6-1 row 4, p.157: a broadcast is never answered, not even with the
// error.
func TestSpecTable7_8_Row20_NoAggressiveModeWithoutError(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, NoAggressiveMode: true}))
	m.sendBroadcast(aggressiveReq(1, 1, []byte{1}, testSessionKey, specCROB))
	m.send(readIIN(2))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 2 || h.count() != 0 {
		t.Fatalf("after the broadcast: %v, %d executed", f, h.count())
	}
	for seq := uint8(3); seq <= 5; seq++ {
		m.send(aggressiveReq(seq, 1, []byte{1}, testSessionKey, specCROB))
		if e := authErr(t, m.recvFunc(app.FuncAuthResponse)); e.Code != app.AuthErrAggressiveModeNotSupported {
			t.Fatalf("error %d: %+v", seq, e)
		}
	}
	chf, raw, critical := m.challenge(req(6, app.FuncDirectOperate, specCROB))
	ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
	m.send(aggressiveReq(7, ch.CSQ+1, raw, testSessionKey, specCROB))
	m.reply(chf, raw, critical, testSessionKey)
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 6 || h.count() != 1 {
		t.Fatalf("reply after the silent refusal: %v, %d executed", f, h.count())
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

// TestSpec4_5_12_ZeroEventLimit: 4.5.12 (p. 86): IIN2.3 is set once an
// event is lost, and stays set until every event buffer has room for one
// more event. WithEventLimits may give a type no buffer at all: an event of
// it is lost at once, reported to dnp3.ServerMetrics, and IIN2.3 stays set,
// also after events of other types were read and confirmed, until a
// restart.
func TestSpec4_5_12_ZeroEventLimit(t *testing.T) {
	rec := &recMetrics{}
	m := newMaster(t, WithMetrics(rec), WithEventLimits(map[PointType]int{BinaryInput: 0}))
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	if _, d, _ := rec.snapshot(); d[1] != 1 {
		t.Fatalf("discarded %v, want one class 1 event", d)
	}
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 7, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.ClassHeaders(1, 2)...))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV.Group() != 32 || !f.IIN.Has(app.IINEventBufferOverflow) || !f.Control.CON {
		t.Fatalf("event poll: %v", f)
	}
	m.send(confirm(1, false))
	m.send(readIIN(2))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("after the confirmation: IIN %s", f.IIN)
	}
	m.srv.Restart()
	m.send(readIIN(3))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("after a restart: IIN %s", f.IIN)
	}
}

// TestSpec4_4_17_1_1_OnlyIdleFileExpires: 4.4.17.1.1 (p. 67): the timeout
// is per file: of two open files only the one that no request named for
// the file timeout is closed and reported with HANDLE_EXPIRED (5.3.8 Rule
// 12, p. 120); the other stays open and is written and closed as usual.
// The test makes the first file's last request an hour old.
func TestSpec4_4_17_1_1_OnlyIdleFileExpires(t *testing.T) {
	s := &sink{written: map[string][]byte{}}
	m := newFileMaster(t, WithFileServer(s), WithFileTimeout(time.Hour, 1))
	idle := m.open(app.FileCommand{Name: "/idle", Mode: app.FileModeWrite, RequestID: 1})
	busy := m.open(app.FileCommand{Name: "/busy", Mode: app.FileModeWrite, RequestID: 2})
	if idle.Status != app.FileSuccess || busy.Status != app.FileSuccess {
		t.Fatalf("open: %+v %+v", idle, busy)
	}
	a := m.srv.association(1)
	onAssoc(t, a, func() bool {
		a.files[idle.Handle].used = time.Now().Add(-2 * time.Hour)
		return true
	})
	var ev *app.Fragment
	eventually(t, "the HANDLE_EXPIRED event", func() bool {
		m.send(req(m.next(), app.FuncRead, app.AllObjects(app.G60V2)))
		if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
			ev = f
			return true
		}
		return false
	})
	if ts := transportStatus(t, ev); len(ev.Headers[0].Objects) != 1 || ts.Handle != idle.Handle || ts.Status != app.FileHandleExpired {
		t.Fatalf("events %v", ev)
	}
	m.send(confirm(m.seq, false))
	if got := m.write(busy.Handle, 0, "ok"); got.Status != app.FileSuccess {
		t.Fatalf("write to the other file: %s", got.Status)
	}
	if got := m.write(idle.Handle, 0, "x"); got.Status != app.FileInvalidHandle {
		t.Fatalf("write to the expired file: %s", got.Status)
	}
	if got := m.closeFile(app.FuncCloseFile, app.FileCommandStatus{Handle: busy.Handle}); got.Status != app.FileSuccess {
		t.Fatalf("close: %s", got.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted != 1 || string(s.written["/busy"]) != "ok" {
		t.Fatalf("%d aborted, written %q", s.aborted, s.written)
	}
}

// TestSpec4_6_6_Rule13_UnsolicitedGivenUp: 4.6.6 Rule 13 (p. 92): once the
// configured retries of an unsolicited response have gone unconfirmed,
// the series ends and its events are reported later, here to a READ. The
// end is reported to dnp3.ServerMetrics as a timeout, as a confirmed
// response (the null one) is reported without an error, and every request
// handled is reported too.
func TestSpec4_6_6_Rule13_UnsolicitedGivenUp(t *testing.T) {
	rec := &recMetrics{}
	m := unsolMaster(t, Unsolicited{Classes: []Class{1}, Retries: 1}, WithMetrics(rec))
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	for range 2 { // the response and its one retry, unconfirmed
		if u := m.recvFunc(app.FuncUnsolicitedResponse); len(u.Headers) != 1 {
			t.Fatalf("unsolicited %v", u)
		}
	}
	var unsol []unsolReport
	eventually(t, "the series given up", func() bool {
		_, _, unsol = rec.snapshot()
		return len(unsol) == 2
	})
	if unsol[0].events != 0 || unsol[0].err != nil || unsol[1].events != 1 || !errors.Is(unsol[1].err, dnp3.ErrTimeout) {
		t.Fatalf("unsolicited reports %+v", unsol)
	}
	m.send(req(1, app.FuncRead, app.ClassHeaders(1)...))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV.Group() != 2 || f.Headers[0].Objects[0].Index != 1 {
		t.Fatalf("READ after the series ended: %v", f)
	}
	if handled, _, _ := rec.snapshot(); handled == 0 {
		t.Fatal("no request reported handled")
	}
}

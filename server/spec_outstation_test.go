// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Spec tests of the outstation's application layer against IEEE 1815-2012.
// Each names the clause, the printed page and the requirement it checks.

// checkResponseHeaders fails t when a response of the outstation carries a
// header that Table 4-8 (p. 35) and 4.2.2.7.2.1 (p. 31) do not permit in a
// response: qualifier 0x06, a class (group 60) or variation 0. Every
// fragment a test of this package receives passes through it.
func checkResponseHeaders(t *testing.T, f *app.Fragment) {
	t.Helper()
	if f.Function != app.FuncResponse && f.Function != app.FuncUnsolicitedResponse {
		return
	}
	for _, h := range f.Headers {
		if h.Qualifier == app.QualAll || h.GV.Group() == 60 || h.GV.Variation() == 0 {
			t.Errorf("response header %s qualifier %#x: not permitted in a response", h.GV, uint8(h.Qualifier))
		}
	}
}

// TestSpec4_3_Rule12_RequestWithCONConfirmed: 4.3 Rule 12 (p. 39):
// "Outstations that receive a properly formatted fragment with the CON bit
// set shall" answer it with a confirmation, with the request's sequence
// number, before the response.
func TestSpec4_3_Rule12_RequestWithCONConfirmed(t *testing.T) {
	m := newMaster(t)
	r := req(3, app.FuncRead, app.ClassHeaders(0)...)
	r.Control.CON = true
	m.send(r)
	c := m.recv()
	if c.Function != app.FuncConfirm || c.Control.Seq != 3 || c.Control.UNS {
		t.Fatalf("first fragment %s, want the CONFIRM of seq 3", c)
	}
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 3 {
		t.Fatalf("then %s, want the response", f)
	}
	// A malformed request with CON is not confirmed: only the response
	// with its IIN2.x follows.
	bad := []byte{0xE4, byte(app.FuncRead), 1, 2, 0x0C}
	m.sendRaw(bad)
	if f := m.recv(); f.Function != app.FuncResponse || !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("malformed request with CON: %s", f)
	}
}

// TestSpec4_3_RequestFlags_Discarded: a request is a single fragment, FIR
// and FIN set (4.3 Rule 4, p. 39: masters shall only send requests that fit
// a single fragment), with UNS clear (4.2.2.4.4, p. 22: masters clear it in
// requests). A fragment that is not is no request and is discarded without
// a response.
func TestSpec4_3_RequestFlags_Discarded(t *testing.T) {
	m := newMaster(t)
	for _, c := range []app.Control{
		{FIR: true, FIN: true, UNS: true, Seq: 1},
		{FIR: false, FIN: true, Seq: 2},
		{FIR: true, FIN: false, Seq: 3},
	} {
		f := req(c.Seq, app.FuncRead, app.ClassHeaders(0)...)
		f.Control = c
		m.send(f)
	}
	m.none(200 * time.Millisecond)
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 4 {
		t.Fatalf("a valid request after the discarded ones: %s", f)
	}
}

// TestSpecTable6_1_Row17_RepeatWhileConfirmAwaited: Table 6-1 row 17
// (pp. 157-158): a repeat of the request (same sequence number and octets)
// while the outstation waits for the confirmation of its response is
// answered with that response again, octet for octet, not executed again;
// its events are confirmed once.
func TestSpecTable6_1_Row17_RepeatWhileConfirmAwaited(t *testing.T) {
	m := newMaster(t)
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	read := req(1, app.FuncRead, app.AllObjects(app.G60V2))
	m.send(read)
	first := m.recvFunc(app.FuncResponse)
	if !first.Control.CON || len(first.Headers) != 1 {
		t.Fatalf("event response %s", first)
	}
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Flags: app.FlagOnline}) // a second event meanwhile
	m.send(read)
	again := m.recvFunc(app.FuncResponse)
	a, _ := first.Encode()
	b, _ := again.Encode()
	if !bytes.Equal(a, b) {
		t.Fatalf("repeat answered with %s, want %s again", again, first)
	}
	m.send(confirm(1, false))
	m.send(req(2, app.FuncRead, app.AllObjects(app.G60V2)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || len(f.Headers[0].Objects) != 1 || f.Headers[0].Objects[0].Value.(app.Binary).Value {
		t.Fatalf("after the confirmation, only the second event: %s", f)
	}
}

// TestSpec4_4_4_3_SelectionEndsWithOtherRequest: 4.4.4.3 Rules 1 to 3
// (p. 50): the OPERATE shall follow its SELECT directly, with the next
// sequence number and the same objects. A request in between ends the
// selection, and a SELECT that fails leaves none.
func TestSpec4_4_4_3_SelectionEndsWithOtherRequest(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	ctl := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	status := func(f *app.Fragment) app.CommandStatus {
		t.Helper()
		if len(f.Headers) != 1 {
			t.Fatalf("echo %s", f)
		}
		return f.Headers[0].Objects[0].Value.(app.CROB).Status
	}
	m.send(req(1, app.FuncSelect, ctl))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusSuccess {
		t.Fatalf("SELECT: %s", s)
	}
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	m.recvFunc(app.FuncResponse)
	m.send(req(2, app.FuncOperate, ctl))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusNoSelect {
		t.Fatalf("OPERATE after a READ: %s, want NO_SELECT", s)
	}

	// A SELECT that fails (the queue bit) replaces the good one.
	m.send(req(5, app.FuncSelect, ctl))
	m.recvFunc(app.FuncResponse)
	queued := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1, Queue: true}})
	m.send(req(6, app.FuncSelect, queued))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusNotSupported {
		t.Fatalf("SELECT with the queue bit: %s", s)
	}
	m.send(req(6, app.FuncOperate, ctl))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusNoSelect {
		t.Fatalf("OPERATE after a failed SELECT: %s, want NO_SELECT", s)
	}
	if h.count() != 0 {
		t.Fatalf("%d controls carried out", h.count())
	}
}

// TestSpec4_4_4_3_Rule4_SelectSameSeqDiscarded: 4.4.4.3 Rule 4 and
// Table 4-9 (p. 50): a SELECT with the sequence number of the selection and
// other objects is not a new SELECT; it is discarded, and the selection's
// OPERATE still works.
func TestSpec4_4_4_3_Rule4_SelectSameSeqDiscarded(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	a := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	b := app.Indexed(app.G12V1, app.Object{Index: 1, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	m.send(req(3, app.FuncSelect, a))
	m.recvFunc(app.FuncResponse)
	m.send(req(3, app.FuncSelect, b))
	m.none(200 * time.Millisecond)
	m.send(req(4, app.FuncOperate, a))
	f := m.recvFunc(app.FuncResponse)
	if s := f.Headers[0].Objects[0].Value.(app.CROB).Status; s != app.StatusSuccess || h.count() != 1 {
		t.Fatalf("OPERATE of the selection: %s, %d controls", s, h.count())
	}
}

// TestSpecA_8_1_2_2_QueueBitNotSupported: A.8.1.2.2 (p. 506): the queue
// field is obsolete; an outstation receiving it set shall answer
// NOT_SUPPORTED and not carry the control out.
func TestSpecA_8_1_2_2_QueueBitNotSupported(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	m.send(req(1, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpPulseOn, Count: 1, Queue: true}})))
	f := m.recvFunc(app.FuncResponse)
	if s := f.Headers[0].Objects[0].Value.(app.CROB).Status; s != app.StatusNotSupported || h.count() != 0 {
		t.Fatalf("queue bit: %s, %d controls", s, h.count())
	}
}

// TestSpec4_4_4_1_UnknownHeaderExecutesNothing: 4.4.4.1 (pp. 48-49): a
// control request with an object the outstation does not support should
// not be executed at all. Nothing runs, and the response has IIN2.1 and no
// objects.
func TestSpec4_4_4_1_UnknownHeaderExecutesNothing(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h))
	ctl := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	for i, fc := range []app.FunctionCode{app.FuncDirectOperate, app.FuncSelect} {
		m.send(req(uint8(i+1), fc, ctl, app.AllObjects(app.G30V0)))
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) || len(f.Headers) != 0 {
			t.Fatalf("%s with an unknown header: %s", fc, f)
		}
	}
	m.send(req(3, app.FuncDirectOperateNoAck, ctl, app.IndexRange(app.G12V3, 0, 0)))
	m.none(150 * time.Millisecond)
	if h.count() != 0 {
		t.Fatalf("%d controls carried out", h.count())
	}
	// The selection did not survive either: an OPERATE gets NO_SELECT.
	m.send(req(3, app.FuncOperate, ctl))
	if f := m.recvFunc(app.FuncResponse); f.Headers[0].Objects[0].Value.(app.CROB).Status != app.StatusNoSelect {
		t.Fatalf("OPERATE: %s", f)
	}
}

// TestSpec4_3_Rule1_ControlEchoWithinFragment: the response to a control
// echoes the request, and no fragment exceeds the configured maximum size
// (4.3 Rule 1, p. 38; WithMaxFragment). When the echo cannot fit,
// nothing is executed and the request is answered with IIN2.2 (4.5.11,
// p. 85); one octet less and it is executed.
func TestSpec4_3_Rule1_ControlEchoWithinFragment(t *testing.T) {
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithMaxFragment(249, 2048), WithMaxControls(64))
	ctls := func(n int) app.Header {
		objs := make([]app.Object, n)
		for i := range objs {
			objs[i] = app.Object{Index: uint32(i), Value: app.CROB{Op: app.OpLatchOn, Count: 1}}
		}
		return app.Indexed(app.G12V1, objs...)
	}
	fits := ctls(20)
	if n, _ := fits.EncodedLen(); responseHeaderLen+n > 249 {
		t.Fatalf("20 controls echo in %d octets", responseHeaderLen+n)
	}
	m.send(req(1, app.FuncDirectOperate, ctls(21)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) || len(f.Headers) != 0 || h.count() != 0 {
		t.Fatalf("echo larger than the fragment: %s, %d controls", f, h.count())
	}
	m.send(req(2, app.FuncDirectOperate, fits))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINParameterError) || len(f.Headers) != 1 || h.count() != 20 {
		t.Fatalf("echo that fits: %s, %d controls", f, h.count())
	}
}

// TestSpec4_6_6_Rule15_DisableEndsSeries: 4.6.6 Rule 15 (p. 92): a
// DISABLE_UNSOLICITED received while an unsolicited response waits for its
// confirmation shall end the series at the confirm timeout without a
// retry, whatever its headers; the events are reported later, and a class
// still enabled starts a new series.
func TestSpec4_6_6_Rule15_DisableEndsSeries(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1, 2}, Retries: 3}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	u := m.recvFunc(app.FuncUnsolicitedResponse)
	if len(u.Headers) == 0 {
		t.Fatalf("unsolicited %s", u)
	}
	// Class 2 alone is disabled; class 1, of the event, stays enabled.
	m.send(req(1, app.FuncDisableUnsolicited, app.AllObjects(app.G60V3)))
	if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("DISABLE: %s", f)
	}
	n := m.recvFunc(app.FuncUnsolicitedResponse)
	if n.Control.Seq != app.NextSeq(u.Control.Seq) || len(n.Headers) == 0 {
		t.Fatalf("after the confirm timeout: %s, want a new series with seq %d", n, app.NextSeq(u.Control.Seq))
	}
	// Class 1 disabled too: the new series ends without a retry, and a
	// READ reports the event.
	m.send(req(2, app.FuncDisableUnsolicited, app.AllObjects(app.G60V2)))
	m.recvFunc(app.FuncResponse)
	m.none(500 * time.Millisecond)
	m.send(req(3, app.FuncRead, app.AllObjects(app.G60V2)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 {
		t.Fatalf("READ after the series ended: %s", f)
	}
}

// TestSpec5_1_1_1_1_Rule2_NullRetriedUntilConfirmed: 5.1.1.1.1 Rule 2
// (p. 101): the null unsolicited response after a restart shall be retried
// until the master confirms it, beyond Unsolicited.Retries. The retries
// are identical (4.6.6 Rule 12, p. 92): the same sequence number and IIN.
func TestSpec5_1_1_1_1_Rule2_NullRetriedUntilConfirmed(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Retries: 1}), WithConfirmTimeout(50*time.Millisecond))
	first := m.recvFunc(app.FuncUnsolicitedResponse)
	for i := range 4 {
		r := m.recvFunc(app.FuncUnsolicitedResponse)
		if r.Control.Seq != first.Control.Seq || r.IIN != first.IIN || len(r.Headers) != 0 {
			t.Fatalf("retry %d: %s, want %s again", i+1, r, first)
		}
	}
	m.send(confirm(first.Control.Seq, true))
	m.none(200 * time.Millisecond)
}

// TestSpecTable4_13_BroadcastIndication: Table 4-13 (p. 82): after a
// broadcast to 0xFFFF the response reporting IIN1.0 asks for confirmation,
// and its confirmation clears the bit, an unsolicited one as well; after a
// broadcast to 0xFFFD the bit is cleared once a response reported it.
func TestSpecTable4_13_BroadcastIndication(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1}}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	m.sendBroadcastTo(req(1, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})), link.BroadcastOptionalConfirm)
	broadcastReceived(t, m)
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	u := m.recvFunc(app.FuncUnsolicitedResponse)
	if !u.IIN.Has(app.IINBroadcast) || !u.Control.CON {
		t.Fatalf("unsolicited after the broadcast: %s", u)
	}
	m.send(confirm(u.Control.Seq, true))
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINBroadcast) {
		t.Fatalf("IIN1.0 after the unsolicited confirmation: %s", f)
	}

	m.sendBroadcastTo(req(3, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})), link.BroadcastNoConfirm)
	broadcastReceived(t, m)
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINBroadcast) {
		t.Fatalf("the response after a broadcast to 0xFFFD: %s", f)
	}
	m.send(req(5, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINBroadcast) {
		t.Fatalf("IIN1.0 reported twice after a broadcast to 0xFFFD: %s", f)
	}
}

// broadcastReceived waits until the outstation has processed a broadcast
// it has not reported yet.
func broadcastReceived(t *testing.T, m *master) {
	t.Helper()
	a := m.srv.association(1)
	deadline := time.Now().Add(2 * time.Second)
	for {
		seen := make(chan bool, 1)
		a.post(func() { seen <- a.broadcast })
		if <-seen {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("broadcast not processed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSpec4_6_ConfirmToBroadcastIgnored: a confirmation is sent to the
// outstation's own address; one sent to a broadcast address confirms
// nothing (4.3 Rule 19, p. 39: a broadcast is not answered, and a
// CONFIRM is the answer to one response), so the events stay unconfirmed.
func TestSpec4_6_ConfirmToBroadcastIgnored(t *testing.T) {
	m := newMaster(t)
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.AllObjects(app.G60V2)))
	f := m.recvFunc(app.FuncResponse)
	if !f.Control.CON {
		t.Fatalf("event response %s", f)
	}
	m.sendBroadcastTo(confirm(1, false), link.BroadcastOptionalConfirm)
	// The next request, processed after the broadcast, ends the wait for a
	// confirmation; unconfirmed, the events are reported again.
	m.send(req(2, app.FuncRead, app.AllObjects(app.G60V2)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 {
		t.Fatalf("events after a broadcast CONFIRM: %s", f)
	}
}

// TestSpec4_5_12_OverflowUntilEveryBufferHasRoom: 4.5.12 (p. 86): IIN2.3
// shall stay set while an event buffer that overflowed has no room; a
// confirmation that empties another buffer does not clear it.
func TestSpec4_5_12_OverflowUntilEveryBufferHasRoom(t *testing.T) {
	m := newMaster(t, WithEventLimits(map[PointType]int{BinaryInput: 1, AnalogInput: 1}))
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	_ = db.UpdateBinaryInput(1, app.Binary{Flags: app.FlagOnline})
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 6, Flags: app.FlagOnline})
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 7, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.AllObjects(app.G60V2)))
	f := m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("after two overflows: %s", f)
	}
	m.send(confirm(1, false))
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("IIN2.3 cleared while the analog buffer is full: %s", f)
	}
	m.send(req(3, app.FuncRead, app.AllObjects(app.G60V3)))
	m.recvFunc(app.FuncResponse)
	m.send(confirm(3, false))
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("IIN2.3 after both buffers have room: %s", f)
	}
}

// TestSpec4_5_5_MasterClearsNeedTime: 4.5.5 (p. 83): an outstation that
// sets IIN1.4 shall let the master clear it by writing 0 to g80v1 index 4;
// it is set again after the interval. A write of 1, or of index 4 by an
// outstation that does not ask for time, is IIN2.2.
func TestSpec4_5_5_MasterClearsNeedTime(t *testing.T) {
	m := newMaster(t, WithTimeSync(300*time.Millisecond))
	m.send(req(1, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("before the clear: %s", f)
	}
	m.send(req(2, app.FuncWrite, app.Ranged(app.G80V1, 4, app.Binary{Value: true})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) || !f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("write of 1: %s", f)
	}
	// Index 4 to 7 in one range: IIN1.4 and IIN1.7 cleared, 5 and 6 refused.
	m.send(req(3, app.FuncWrite, app.Ranged(app.G80V1, 4, app.Binary{}, app.Binary{}, app.Binary{}, app.Binary{})))
	f := m.recvFunc(app.FuncResponse)
	if f.IIN.Has(app.IINNeedTime) || f.IIN.Has(app.IINDeviceRestart) || !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("write of 4 to 7: %s", f)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
		if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINNeedTime) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("IIN1.4 not set again after the interval")
		}
		time.Sleep(50 * time.Millisecond)
	}

	n := newMaster(t)
	n.send(req(1, app.FuncWrite, app.Ranged(app.G80V1, 4, app.Binary{})))
	if f := n.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("index 4 without WithTimeSync: %s", f)
	}
}

// TestSpec4_5_11_WriteWithoutValues: 4.5.11 (p. 85): IIN2.2 for a request
// with a qualifier the outstation does not support. A WRITE header that
// carries no values (qualifier 0x06) writes nothing and is refused; an
// unknown object stays IIN2.1.
func TestSpec4_5_11_WriteWithoutValues(t *testing.T) {
	m := newMaster(t)
	m.send(req(1, app.FuncWrite, app.AllObjects(app.G80V1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) || !f.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("WRITE g80v1 0x06: %s", f)
	}
	m.sendRaw([]byte{0xC2, byte(app.FuncWrite), 200, 1, 0x06})
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("WRITE of an unknown object: %s", f)
	}
}

// specApp is an ApplicationHandler answering with iin.
type specApp struct {
	NopHandler
	iin app.IIN
}

func (h specApp) Application(context.Context, app.FunctionCode, []app.Header) app.IIN { return h.iin }

// TestSpec4_4_12_SaveConfigTimeDelay: 4.4.12 (p. 60): an outstation shall
// answer SAVE_CONFIG at once with a time delay object (g52v1 or g52v2).
// IIN2.4, already executing (4.5.13, p. 87), is the handler's to report.
func TestSpec4_4_12_SaveConfigTimeDelay(t *testing.T) {
	m := newMaster(t, WithHandler(specApp{}))
	m.send(req(1, app.FuncSaveConfiguration))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G52V2 || f.Headers[0].Qualifier != app.Qual1ByteCount {
		t.Fatalf("SAVE_CONFIG: %s", f)
	}
	busy := newMaster(t, WithHandler(specApp{iin: app.IINAlreadyExecuting | app.IINNeedTime}))
	busy.send(req(1, app.FuncInitializeApplication))
	if f := busy.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINAlreadyExecuting) || f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("IIN of the handler: %s", f)
	}
	refused := newMaster(t, WithHandler(specApp{iin: app.IINParameterError}))
	refused.send(req(1, app.FuncSaveConfiguration))
	if f := refused.recvFunc(app.FuncResponse); len(f.Headers) != 0 || !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("refused SAVE_CONFIG: %s", f)
	}
}

// TestSpecTable4_12_AssignClass: Table 4-12 (p. 63) lists g12v0 and g41v0
// for the classes of binary and analog command events (g13, g43); note a:
// an outstation shall answer an ASSIGN_CLASS that would put
// authentication objects or security statistics in class 0 with a null
// response and IIN2.0. An object the outstation does not know is IIN2.1
// (Table 4-14, p. 85).
func TestSpecTable4_12_AssignClass(t *testing.T) {
	m := newMaster(t, WithHandler(&countingHandler{}))
	db := m.srv.Database()
	_ = db.AddBinaryOutput(0, PointConfig{CommandEventClass: 1}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddAnalogOutput(0, PointConfig{CommandEventClass: 1}, app.Analog{Flags: app.FlagOnline})
	m.send(req(1, app.FuncAssignClass, app.AllObjects(app.G60V3), app.AllObjects(app.G12V0), app.IndexRange(app.G41V0, 0, 0)))
	if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 {
		t.Fatalf("ASSIGN_CLASS g12v0 g41v0: %s", f)
	}
	m.send(req(2, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})))
	m.recvFunc(app.FuncResponse)
	m.send(req(3, app.FuncDirectOperate, app.Indexed(app.G41V2, app.Object{Index: 0, Value: app.AnalogOutput{Value: 3}})))
	m.recvFunc(app.FuncResponse)
	m.send(req(4, app.FuncRead, app.AllObjects(app.G60V3)))
	f := m.recvFunc(app.FuncResponse)
	var groups []uint8
	for _, h := range f.Headers {
		groups = append(groups, h.GV.Group())
	}
	if len(groups) != 2 || groups[0] != 13 || groups[1] != 43 {
		t.Fatalf("class 2 events after the assignment: %s", f)
	}
	m.send(confirm(4, false))

	for i, h := range []app.Header{app.AllObjects(app.G121V0), app.AllObjects(app.GV(120, 0))} {
		m.send(req(uint8(5+i), app.FuncAssignClass, app.AllObjects(app.G60V1), h))
		if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != app.IINNoFuncCodeSupport {
			t.Fatalf("g%d to class 0: %s", h.GV.Group(), f)
		}
	}
	m.send(req(7, app.FuncAssignClass, app.AllObjects(app.G60V2), app.AllObjects(app.G80V1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("ASSIGN_CLASS of g80: %s", f)
	}
}

// TestSpec4_4_14_RestartRevertsClasses: 4.4.14 (p. 63): devices that do
// not keep class assignments in non-volatile memory shall revert to their
// default class assignments after a restart.
func TestSpec4_4_14_RestartRevertsClasses(t *testing.T) {
	m := newMaster(t)
	m.send(req(1, app.FuncAssignClass, app.AllObjects(app.G60V4), app.AllObjects(app.G1V0)))
	m.recvFunc(app.FuncResponse)
	m.srv.Restart()
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...)) // after the restart, in order
	m.recvFunc(app.FuncResponse)
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(3, app.FuncRead, app.AllObjects(app.G60V2)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || f.Headers[0].GV.Group() != 2 {
		t.Fatalf("class 1 event of the reverted point: %s", f)
	}
}

// TestSpecA_25_2_DelayMeasureCapped: DELAY_MEASURE is answered with g52v2
// (4.4.15.1, p. 65), whose delay is 16 bits of milliseconds (A.25.2,
// p. 659): a longer processing time is reported as 65535 ms.
func TestSpecA_25_2_DelayMeasureCapped(t *testing.T) {
	m := newMaster(t)
	a := m.srv.association(1)
	got := make(chan *response, 1)
	a.post(func() {
		got <- a.dispatch(req(1, app.FuncDelayMeasure), inbound{at: time.Now().Add(-70 * time.Second)}, false)
	})
	r := <-got
	d := r.plans[0].headers[0].Objects[0].Value.(app.TimeDelay).Delay
	if r.plans[0].headers[0].GV != app.G52V2 || d != 65535*time.Millisecond {
		t.Fatalf("delay %v", d)
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

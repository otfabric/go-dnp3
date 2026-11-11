// SPDX-License-Identifier: MIT

package e2e

import (
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// Spec tests of the outstation through the go-dnp3 master, for behaviour
// that crosses the roles. Each names the clause and page of IEEE
// 1815-2012 it checks.

// TestSpecOutstation4_5_5_MasterClearsNeedTime: 4.5.5 (p. 83): a master
// may clear IIN1.4 by writing 0 to g80v1 index 4; the outstation shall
// accept it. A write of 1 is refused (IIN2.2).
func TestSpecOutstation4_5_5_MasterClearsNeedTime(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithTimeSync(time.Hour)})
	c := ctx(t)
	res, err := p.c.Read(c, app.AllObjects(app.G80V1))
	if err != nil || !res.IIN.Has(app.IINNeedTime) {
		t.Fatalf("before: %v %v", res, err)
	}
	if res, err = p.c.Write(c, app.Ranged(app.G80V1, 4, app.Binary{})); err != nil || res.IIN.Has(app.IINNeedTime) {
		t.Fatalf("write of 0: IIN %v, %v", res, err)
	}
	_, err = p.c.Write(c, app.Ranged(app.G80V1, 4, app.Binary{Value: true}))
	if ie, ok := errors.AsType[*dnp3.IINError](err); !ok || !ie.IIN.Has(app.IINParameterError) {
		t.Fatalf("write of 1: %v", err)
	}
}

// TestSpecOutstationA_23_1_2_3_ReadTime: A.23.1.2.3 (p. 648): an
// outstation shall answer a READ of g50v1, qualifier 0x07, count 1, with
// its time, the time the master wrote.
func TestSpecOutstationA_23_1_2_3_ReadTime(t *testing.T) {
	p := newPair(t, fullDatabase, []server.Option{server.WithTimeSync(time.Hour)})
	c := ctx(t)
	at := time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC)
	if err := p.c.WriteTime(c, at); err != nil {
		t.Fatal(err)
	}
	res, err := p.c.Read(c, app.CountOf(app.G50V1, 1))
	if err != nil {
		t.Fatal(err)
	}
	f := res.Fragments[0]
	if len(f.Headers) != 1 || f.Headers[0].GV != app.G50V1 || f.Headers[0].Qualifier != app.Qual1ByteCount {
		t.Fatalf("response %s", f)
	}
	got := f.Headers[0].Objects[0].Value.(app.AbsoluteTime).Time.Time()
	if d := got.Sub(at); d < 0 || d > 5*time.Second {
		t.Fatalf("time %v after writing %v", got, at)
	}
	if res.IIN.Has(app.IINNeedTime) {
		t.Fatalf("IIN1.4 after the write of the time: %s", res.IIN)
	}
}

// TestSpecOutstation4_4_17_1_1_FileTimeoutEvent: 4.4.17.1.1 (p. 67) and
// 5.3.8 Rule 12 (p. 120): a file that no request names for the timeout is
// closed, and the outstation reports it with a g70v6 event, status
// HANDLE_EXPIRED, in its event class; the master reads and confirms it.
func TestSpecOutstation4_4_17_1_1_FileTimeoutEvent(t *testing.T) {
	fs := newMemFS()
	p := newPair(t, fullDatabase, []server.Option{server.WithFileServer(fs), server.WithFileTimeout(100*time.Millisecond, 1)})
	c := ctx(t)
	res, err := p.c.Request(c, app.FuncOpenFile, app.FreeFormat(app.G70V3,
		app.FileCommand{Name: "/x", Mode: app.FileModeWrite, Size: 10, RequestID: 1}))
	if err != nil {
		t.Fatal(err)
	}
	st := res.Fragments[0].Headers[0].Objects[0].Value.(app.FileCommandStatus)
	if st.Status != app.FileSuccess {
		t.Fatalf("open: %+v", st)
	}
	_, _ = p.c.EventPoll(c) // the events of the start
	var ts app.FileTransportStatus
	waitUntil(t, "HANDLE_EXPIRED", func() bool {
		res, err := p.c.Read(c, app.AllObjects(app.G70V6))
		if err != nil || len(res.Fragments[0].Headers) == 0 {
			return false
		}
		ts = res.Fragments[0].Headers[0].Objects[0].Value.(app.FileTransportStatus)
		return true
	})
	if ts.Handle != st.Handle || ts.Status != app.FileHandleExpired {
		t.Fatalf("event %+v, handle %d", ts, st.Handle)
	}
	// Confirmed by the master: not reported again.
	if res, err := p.c.EventPoll(c, 1); err != nil || len(res.Fragments[0].Headers) != 0 {
		t.Fatalf("class 1 after the confirmation: %v %v", res.Fragments[0], err)
	}
	res, err = p.c.Request(c, app.FuncCloseFile, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: st.Handle}))
	if err != nil || res.Fragments[0].Headers[0].Objects[0].Value.(app.FileCommandStatus).Status != app.FileInvalidHandle {
		t.Fatalf("close after the timeout: %v %v", res, err)
	}
}

// TestSpecOutstationTable4_12_AssignCommandEventClass: Table 4-12 (p. 63)
// lists g12v0 and g41v0 for ASSIGN_CLASS: they set the class of the binary
// and analog command events (g13, g43), which an event poll of that class
// then returns.
func TestSpecOutstationTable4_12_AssignCommandEventClass(t *testing.T) {
	p := newPair(t, func(db *server.Database) {
		_ = db.AddBinaryOutput(0, server.PointConfig{}, app.Binary{Flags: app.FlagOnline})
		_ = db.AddAnalogOutput(0, server.PointConfig{}, app.Analog{Flags: app.FlagOnline})
	}, []server.Option{server.WithHandler(&relay{})})
	c := ctx(t)
	if err := p.c.AssignClass(c, 2, app.AllObjects(app.G12V0), app.AllObjects(app.G41V0)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.c.Operate(c, client.DirectOperate, client.Command{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}},
		client.Command{Index: 0, Value: app.AnalogOutput{Value: 9}}); err != nil {
		t.Fatal(err)
	}
	res, err := p.c.EventPoll(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[uint8]int{}
	for _, f := range res.Fragments {
		for _, h := range f.Headers {
			groups[h.GV.Group()] += len(h.Objects)
		}
	}
	if groups[13] != 1 || groups[43] != 1 {
		t.Fatalf("class 2 events: %v", groups)
	}
}

// TestSpecOutstationTable4_11_FreezeAtTimeCancel: Table 4-11 (pp. 56-57):
// a periodic FREEZE_AT_TIME continues until a new one for its points; one
// with the time all ones cancels it.
func TestSpecOutstationTable4_11_FreezeAtTimeCancel(t *testing.T) {
	p := newPair(t, fullDatabase, nil)
	c := ctx(t)
	frozen := func() uint32 {
		v, _ := p.db.Get(server.FrozenCounter, 0)
		return v.(app.Counter).Value
	}
	if err := p.c.FreezeAtTime(c, time.Now().Add(-time.Minute), 30*time.Millisecond, app.AllObjects(app.G20V0)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "periodic freeze", func() bool { return frozen() == 100 })
	_ = p.db.UpdateCounter(0, app.Counter{Value: 101, Flags: app.FlagOnline})
	waitUntil(t, "next freeze", func() bool { return frozen() == 101 })

	cancel := time.UnixMilli(int64(app.MaxTimestamp))
	if err := p.c.FreezeAtTime(c, cancel, 0, app.AllObjects(app.G20V0)); err != nil {
		t.Fatal(err)
	}
	_ = p.db.UpdateCounter(0, app.Counter{Value: 102, Flags: app.FlagOnline})
	time.Sleep(200 * time.Millisecond) // more than six intervals
	if v := frozen(); v != 101 {
		t.Fatalf("frozen counter %d after the cancel", v)
	}
}

// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// master is a scripted master: it sends exact fragments and reads the
// outstation's answers, without the client's logic in between.
type master struct {
	t    *testing.T
	ch   *channel.Channel
	sess *channel.Session
	in   chan *app.Fragment
	srv  *Server
}

func newMaster(t *testing.T, opts ...Option) *master {
	t.Helper()
	srv, err := New(append([]Option{WithMasters(1), WithConfirmTimeout(300 * time.Millisecond)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	db := srv.Database()
	_ = db.AddBinaryInput(0, PointConfig{Class: 1}, app.Binary{Value: true, Flags: app.FlagOnline})
	_ = db.AddBinaryInput(1, PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddAnalogInput(0, PointConfig{Class: 2}, app.Analog{Value: 5, Flags: app.FlagOnline})
	_ = db.AddCounter(0, PointConfig{Class: 3}, app.Counter{Value: 1, Flags: app.FlagOnline})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m := &master{t: t, in: make(chan *app.Fragment, 32), srv: srv}
	m.ch = channel.New(conn, channel.Config{})
	m.sess = m.ch.AddSession(channel.SessionConfig{Local: 1, Remote: 10, Master: true,
		OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil {
				m.in <- f
			}
		}})
	m.ch.Start()
	t.Cleanup(func() {
		m.ch.Close(nil)
		<-m.ch.Done()
		_ = srv.Close()
	})
	return m
}

func (m *master) send(f *app.Fragment) {
	m.t.Helper()
	b, err := f.Encode()
	if err != nil {
		m.t.Fatal(err)
	}
	m.sendRaw(b)
}

func (m *master) sendRaw(b []byte) {
	m.t.Helper()
	if err := m.sess.Send(context.Background(), b); err != nil {
		m.t.Fatal(err)
	}
}

func (m *master) sendBroadcast(f *app.Fragment) {
	m.t.Helper()
	m.sendBroadcastTo(f, link.BroadcastNoConfirm)
}

func (m *master) sendBroadcastTo(f *app.Fragment, to link.Address) {
	m.t.Helper()
	b, _ := f.Encode()
	if err := m.sess.SendBroadcast(context.Background(), b, to); err != nil {
		m.t.Fatal(err)
	}
}

func (m *master) recv() *app.Fragment {
	m.t.Helper()
	select {
	case f := <-m.in:
		return f
	case <-time.After(3 * time.Second):
		m.t.Fatal("no fragment from the outstation")
		return nil
	}
}

// recvFunc skips fragments until one with function fc arrives.
func (m *master) recvFunc(fc app.FunctionCode) *app.Fragment {
	m.t.Helper()
	for {
		if f := m.recv(); f.Function == fc {
			return f
		}
	}
}

func (m *master) none(d time.Duration) {
	m.t.Helper()
	select {
	case f := <-m.in:
		m.t.Fatalf("unexpected fragment %s", f)
	case <-time.After(d):
	}
}

func req(seq uint8, fc app.FunctionCode, hs ...app.Header) *app.Fragment {
	return &app.Fragment{Control: app.SingleControl(seq), Function: fc, Headers: hs}
}

func confirm(seq uint8, uns bool) *app.Fragment {
	return &app.Fragment{Control: app.Control{FIR: true, FIN: true, UNS: uns, Seq: seq}, Function: app.FuncConfirm}
}

func TestMalformedRequests(t *testing.T) {
	m := newMaster(t)
	cases := []struct {
		name string
		raw  []byte
		want app.IIN
	}{
		{"unknown function", []byte{0xC1, 0x63}, app.IINNoFuncCodeSupport},
		{"unknown object", []byte{0xC2, 0x02, 200, 1, 0x06}, app.IINObjectUnknown},
		{"bad qualifier", []byte{0xC3, 0x01, 1, 2, 0x0C}, app.IINParameterError},
		{"truncated header", []byte{0xC4, 0x01, 1}, app.IINParameterError},
	}
	for _, c := range cases {
		m.sendRaw(c.raw)
		f := m.recvFunc(app.FuncResponse)
		if !f.IIN.Has(c.want) || f.Control.Seq != c.raw[0]&0x0F {
			t.Errorf("%s: IIN %s seq %d", c.name, f.IIN, f.Control.Seq)
		}
	}
	// A request with an unsupported function code the library knows.
	m.send(req(5, app.FuncInitializeData))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINNoFuncCodeSupport) {
		t.Errorf("INITIALIZE_DATA: %s", f.IIN)
	}
	// Multi-fragment requests and responses sent to an outstation are
	// ignored.
	m.send(&app.Fragment{Control: app.Control{FIR: true, Seq: 6}, Function: app.FuncRead, Headers: app.ClassHeaders(0)})
	m.send(&app.Fragment{Control: app.SingleControl(7), Function: app.FuncResponse})
	m.none(200 * time.Millisecond)
}

func TestRepeatedRequest(t *testing.T) {
	r := &countingHandler{}
	m := newMaster(t, WithHandler(r))
	op := req(3, app.FuncDirectOperate, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}}))
	m.send(op)
	first := m.recvFunc(app.FuncResponse)
	// The same request again (the response was lost): answered with the
	// same response, not executed twice.
	m.send(op)
	second := m.recvFunc(app.FuncResponse)
	if first.Control.Seq != second.Control.Seq || r.count() != 1 {
		t.Fatalf("repeat executed: %d operates", r.count())
	}
	// A READ is executed again.
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	m.recvFunc(app.FuncResponse)
	m.send(req(4, app.FuncRead, app.ClassHeaders(0)...))
	m.recvFunc(app.FuncResponse)
}

func TestBroadcast(t *testing.T) {
	r := &countingHandler{}
	m := newMaster(t, WithHandler(r))
	m.sendBroadcast(req(1, app.FuncDirectOperateNoAck, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})))
	m.none(200 * time.Millisecond)
	if r.count() != 1 {
		t.Fatal("broadcast control not executed")
	}
	// SELECT is never executed from a broadcast.
	m.sendBroadcast(req(2, app.FuncSelect, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})))
	m.none(100 * time.Millisecond)
	// After a broadcast to 0xFFFD the next response reports IIN1.0, without
	// asking for confirmation, and the one after it no longer does.
	m.send(req(3, app.FuncRead, app.AllObjects(app.G80V1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINBroadcast) || f.Control.CON {
		t.Fatalf("after 0xFFFD: %s, CON %v", f.IIN, f.Control.CON)
	}
	m.send(req(4, app.FuncRead, app.AllObjects(app.G80V1)))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINBroadcast) {
		t.Fatal("BROADCAST indication repeated")
	}
	// After one to 0xFFFE or 0xFFFF the response reporting IIN1.0 asks for
	// confirmation; until it is confirmed, IIN1.0 is reported again.
	for i, to := range []link.Address{link.BroadcastConfirm, link.BroadcastOptionalConfirm} {
		seq := uint8(5 + 3*i)
		m.sendBroadcastTo(req(seq, app.FuncDirectOperateNoAck, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})), to)
		m.none(100 * time.Millisecond)
		for s := seq; s <= seq+1; s++ {
			m.send(req(s, app.FuncRead, app.AllObjects(app.G80V1)))
			if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINBroadcast) || !f.Control.CON {
				t.Fatalf("after %v: %s, CON %v", to, f.IIN, f.Control.CON)
			}
		}
		m.send(confirm(seq+1, false))
		m.send(req(seq+2, app.FuncRead, app.AllObjects(app.G80V1)))
		if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINBroadcast) || f.Control.CON {
			t.Fatalf("after %v, confirmed: %s, CON %v", to, f.IIN, f.Control.CON)
		}
	}
}

func TestConfirmTimeoutKeepsEvents(t *testing.T) {
	m := newMaster(t)
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.ClassHeaders(1)...))
	f := m.recvFunc(app.FuncResponse)
	if !f.Control.CON || len(f.Headers) == 0 {
		t.Fatalf("event response %s", f)
	}
	// No confirmation: after the timeout the events are reported again.
	time.Sleep(500 * time.Millisecond)
	m.send(req(2, app.FuncRead, app.ClassHeaders(1)...))
	f = m.recvFunc(app.FuncResponse)
	if len(f.Headers) == 0 {
		t.Fatal("unconfirmed events lost")
	}
	m.send(confirm(2, false))
	m.send(req(3, app.FuncRead, app.ClassHeaders(1)...))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
		t.Fatal("confirmed events reported again")
	}
	// A confirmation with the wrong sequence number is ignored.
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Flags: app.FlagOnline})
	m.send(req(4, app.FuncRead, app.ClassHeaders(1)...))
	m.recvFunc(app.FuncResponse)
	m.send(confirm(9, false))
	m.send(confirm(1, true))
	m.send(req(5, app.FuncRead, app.ClassHeaders(1)...))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) == 0 {
		t.Fatal("events removed by a wrong confirmation")
	}
}

func TestUnsolicitedRetries(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1}, Retries: 2, RetryDelay: 300 * time.Millisecond}))
	// The null unsolicited response is repeated until confirmed.
	n1 := m.recvFunc(app.FuncUnsolicitedResponse)
	n2 := m.recvFunc(app.FuncUnsolicitedResponse)
	if len(n1.Headers) != 0 || n1.Control.Seq != n2.Control.Seq || !n1.Control.UNS || !n1.Control.CON {
		t.Fatalf("null unsolicited %s / %s", n1, n2)
	}
	m.send(confirm(n2.Control.Seq, true))
	// Events: retried twice with the same sequence number, then given up
	// for the retry delay, then sent again with the next one.
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	var seqs []uint8
	for range 3 {
		f := m.recvFunc(app.FuncUnsolicitedResponse)
		if len(f.Headers) == 0 {
			t.Fatal("event unsolicited without events")
		}
		seqs = append(seqs, f.Control.Seq)
	}
	if seqs[0] != seqs[1] || seqs[1] != seqs[2] {
		t.Fatalf("retries changed the sequence: %v", seqs)
	}
	again := m.recvFunc(app.FuncUnsolicitedResponse)
	if again.Control.Seq != app.NextSeq(seqs[0]) || len(again.Headers) == 0 {
		t.Fatalf("after the retry delay: %s", again)
	}
	m.send(confirm(again.Control.Seq, true))
	m.none(400 * time.Millisecond)
}

func TestUnsolicitedHold(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1, 2}, HoldTime: 300 * time.Millisecond, HoldCount: 3}))
	n := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(n.Control.Seq, true))
	db := m.srv.Database()
	start := time.Now()
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	f := m.recvFunc(app.FuncUnsolicitedResponse)
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("hold time not respected")
	}
	m.send(confirm(f.Control.Seq, true))
	// Reaching the count sends at once.
	start = time.Now()
	_ = db.Batch(func(b *Batch) error {
		_ = b.Update(BinaryInput, 0, app.Binary{Flags: app.FlagOnline}, EventOnChange)
		_ = b.Update(BinaryInput, 1, app.Binary{Flags: app.FlagOnline}, EventOnChange)
		return b.Update(AnalogInput, 0, app.Analog{Value: 9, Flags: app.FlagOnline}, EventOnChange)
	})
	m.recvFunc(app.FuncUnsolicitedResponse)
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("hold count did not send at once")
	}
}

// TestControlNotSupported: a control the handler does not support is echoed
// with NOT_SUPPORTED and IIN2.2 (PARAMETER_ERROR), the other controls of the
// request with their own status.
func TestControlNotSupported(t *testing.T) {
	h := HandlerFunc(func(_ context.Context, c Command, _ OperateType) app.CommandStatus {
		if c.Index != 0 {
			return app.StatusNotSupported
		}
		return app.StatusSuccess
	})
	m := newMaster(t, WithHandler(h))
	m.send(req(1, app.FuncDirectOperate, app.Indexed(app.G12V1,
		app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}},
		app.Object{Index: 65535, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})))
	f := m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("IIN %s, want PARAMETER_ERROR", f.IIN)
	}
	if len(f.Headers) != 1 || len(f.Headers[0].Objects) != 2 {
		t.Fatalf("echo %v", f.Headers)
	}
	for i, want := range []app.CommandStatus{app.StatusSuccess, app.StatusNotSupported} {
		if s := f.Headers[0].Objects[i].Value.(app.CROB).Status; s != want {
			t.Fatalf("control %d: status %s, want %s", i, s, want)
		}
	}
}

func TestSelectTimeoutAndMismatch(t *testing.T) {
	r := &countingHandler{}
	m := newMaster(t, WithHandler(r), WithSelectTimeout(150*time.Millisecond))
	crob := func(op app.OpType) app.Header {
		return app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: op, Count: 1}})
	}
	status := func(f *app.Fragment) app.CommandStatus { return f.Headers[0].Objects[0].Value.(app.CROB).Status }

	m.send(req(1, app.FuncSelect, crob(app.OpLatchOn)))
	m.recvFunc(app.FuncResponse)
	time.Sleep(250 * time.Millisecond)
	m.send(req(2, app.FuncOperate, crob(app.OpLatchOn)))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusTimeout {
		t.Fatalf("after select timeout: %s", s)
	}
	m.send(req(3, app.FuncSelect, crob(app.OpLatchOn)))
	m.recvFunc(app.FuncResponse)
	m.send(req(4, app.FuncOperate, crob(app.OpLatchOff)))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusNoSelect {
		t.Fatalf("operate differing from select: %s", s)
	}
	m.send(req(5, app.FuncSelect, crob(app.OpLatchOn)))
	m.recvFunc(app.FuncResponse)
	m.send(req(7, app.FuncOperate, crob(app.OpLatchOn)))
	if s := status(m.recvFunc(app.FuncResponse)); s != app.StatusNoSelect {
		t.Fatalf("operate with a sequence gap: %s", s)
	}
	if r.count() != 0 {
		t.Fatal("operated without a valid select")
	}
	// Unknown control object.
	m.send(req(8, app.FuncDirectOperate, app.Indexed(app.G41V2, app.Object{Index: 0, Value: app.AnalogOutput{Value: 1}}),
		app.Header{GV: app.G30V1, Qualifier: app.Qual1ByteStartStop, Objects: []app.Object{{Index: 0, Value: app.Analog{}}}}))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("unknown control object: %s", f.IIN)
	}
}

func TestPatternControl(t *testing.T) {
	r := &countingHandler{}
	m := newMaster(t, WithHandler(r))
	mask := app.Ranged(app.G12V3, 4, app.Binary{Value: true}, app.Binary{}, app.Binary{Value: true})
	pcb := app.Counted(app.G12V2, app.CROB{Op: app.OpPulseOn, Count: 1, OnTime: 10})
	m.send(req(1, app.FuncDirectOperate, pcb, mask))
	f := m.recvFunc(app.FuncResponse)
	if f.IIN&dnp3.IINErrorBits != 0 || f.Headers[0].Objects[0].Value.(app.CROB).Status != app.StatusSuccess {
		t.Fatalf("pattern control: %s %v", f.IIN, f.Headers)
	}
	idx := r.indexes()
	if len(idx) != 2 || idx[0] != 4 || idx[1] != 6 {
		t.Fatalf("pattern executed on %v, want [4 6]", idx)
	}
	// A pattern control block without its mask.
	m.send(req(2, app.FuncDirectOperate, pcb))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("pcb without mask: %s", f.IIN)
	}
}

func TestIndicationsAndWrites(t *testing.T) {
	m := newMaster(t)
	m.srv.SetIndications(app.IINDeviceTrouble|app.IINLocalControl|app.IINNeedTime, true)
	m.send(req(1, app.FuncRead, app.AllObjects(app.G80V1)))
	f := m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINDeviceTrouble|app.IINLocalControl) || f.IIN.Has(app.IINNeedTime) {
		t.Fatalf("indications %s", f.IIN)
	}
	// g80v1 read returns the bits as packed objects.
	got := map[uint32]bool{}
	for _, o := range f.Headers[0].Objects {
		got[o.Index] = o.Value.(app.Binary).Value
	}
	if !got[6] || !got[5] || !got[7] {
		t.Fatalf("g80v1 objects %v", got)
	}
	m.srv.SetIndications(app.IINDeviceTrouble, false)
	// Writing anything but a clear of DEVICE_RESTART to g80 is refused.
	m.send(req(2, app.FuncWrite, app.Ranged(app.G80V1, 6, app.Binary{Value: false})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("write of IIN bit 6: %s", f.IIN)
	}
	// Deadband write.
	m.send(req(3, app.FuncWrite, app.Indexed(app.G34V3, app.Object{Index: 0, Value: app.AnalogDeadband{Value: 2.5}}),
		app.Indexed(app.G34V1, app.Object{Index: 9, Value: app.AnalogDeadband{Value: 1}})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("deadband of missing point: %s", f.IIN)
	}
	m.srv.db.mu.RLock()
	db := m.srv.db.points[AnalogInput][0].cfg.Deadband
	m.srv.db.mu.RUnlock()
	if db != 2.5 {
		t.Fatalf("deadband %v", db)
	}
	// g50v3 without RECORD_CURRENT_TIME first.
	m.send(req(4, app.FuncWrite, app.Counted(app.G50V3, app.AbsoluteTime{Time: 1})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("g50v3 without recorded time: %s", f.IIN)
	}
	// Writing an object the outstation does not take.
	m.send(req(5, app.FuncWrite, app.Ranged(app.G1V2, 0, app.Binary{})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("write of g1v2: %s", f.IIN)
	}
	// ASSIGN_CLASS without a class header, and with a range of missing points.
	m.send(req(6, app.FuncAssignClass, app.AllObjects(app.G1V0)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("assign class without class: %s", f.IIN)
	}
	m.send(req(7, app.FuncAssignClass, app.AllObjects(app.G60V2), app.IndexRange(app.G1V0, 0, 9)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("assign class of missing points: %s", f.IIN)
	}
	// ENABLE_UNSOLICITED with a non-class header.
	n := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true}))
	n.recvFunc(app.FuncUnsolicitedResponse)
	n.send(req(1, app.FuncEnableUnsolicited, app.AllObjects(app.G1V0)))
	if f := n.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("enable unsolicited with g1: %s", f.IIN)
	}
}

func TestFSFileServer(t *testing.T) {
	fsys := fstest.MapFS{
		"logs/a.txt": {Data: []byte("alpha"), Mode: 0o644, ModTime: time.Unix(1_700_000_000, 0)},
		"logs/b.txt": {Data: []byte("bravo!"), Mode: 0o600},
	}
	s := FSFileServer{FS: fsys}
	ctx := context.Background()
	f, st := s.Open(ctx, FileRequest{Name: "/logs/a.txt", Mode: app.FileModeRead})
	if st != app.FileSuccess || f.Size() != 5 {
		t.Fatalf("open: %s", st)
	}
	buf := make([]byte, 10)
	n, _ := f.Read(buf)
	if string(buf[:n]) != "alpha" {
		t.Fatalf("read %q", buf[:n])
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("write to read-only file")
	}
	_ = f.Close(false)
	if _, st := s.Open(ctx, FileRequest{Name: "/logs/a.txt", Mode: app.FileModeWrite}); st != app.FilePermissionDenied {
		t.Fatalf("open for write: %s", st)
	}
	if _, st := s.Open(ctx, FileRequest{Name: "/nope", Mode: app.FileModeRead}); st != app.FileNotFound {
		t.Fatalf("missing: %s", st)
	}
	if _, st := s.Open(ctx, FileRequest{Name: "../../etc/passwd", Mode: app.FileModeRead}); st != app.FileNotFound {
		t.Fatalf("escape: %s", st)
	}
	d, st := s.Open(ctx, FileRequest{Name: "\\logs", Mode: app.FileModeRead})
	if st != app.FileSuccess {
		t.Fatalf("directory: %s", st)
	}
	listing := make([]byte, 512)
	n, _ = d.Read(listing)
	entries, err := app.DecodeFileDescriptors(listing[:n])
	if err != nil || len(entries) != 2 || entries[0].Name != "a.txt" || entries[1].Size != 6 {
		t.Fatalf("listing %+v %v", entries, err)
	}
	if _, err := d.Write(nil); err == nil || d.Close(false) != nil || d.Size() == 0 {
		t.Fatal("directory file")
	}
	info, st := s.Info(ctx, "/logs")
	if st != app.FileSuccess || info.Type != app.FileTypeDirectory {
		t.Fatalf("info: %+v %s", info, st)
	}
	if info, st := s.Info(ctx, "/logs/a.txt"); st != app.FileSuccess || info.Permissions != 0o644 || info.Size != 5 {
		t.Fatalf("file info %+v", info)
	}
	if _, st := s.Info(ctx, "/x"); st != app.FileNotFound {
		t.Fatal("info of missing file")
	}
	if s.Delete(ctx, "/logs/a.txt", 0) != app.FilePermissionDenied {
		t.Fatal("delete on read-only server")
	}
}

func TestDatabaseAPI(t *testing.T) {
	srv, _ := New()
	db := srv.Database()
	if err := db.Add(OctetString, 0, PointConfig{}, app.OctetString{}); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("empty octet string accepted")
	}
	if err := db.Add(AnalogInput, 0, PointConfig{Class: 4}, app.Analog{}); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("class 4 accepted")
	}
	if err := db.Add(AnalogInput, 0, PointConfig{StaticVariation: 99}, app.Analog{}); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("bad static variation accepted")
	}
	if err := db.Add(AnalogInput, 0, PointConfig{EventVariation: 99}, app.Analog{}); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("bad event variation accepted")
	}
	if err := db.Add(numPointTypes, 0, PointConfig{}, app.Analog{}); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("bad type accepted")
	}
	if err := db.Add(BinaryInput, 0, PointConfig{}, app.Analog{}); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("wrong value type accepted")
	}
	_ = db.AddDoubleBitInput(0, PointConfig{Class: 1}, app.DoubleBitBinary{})
	_ = db.AddBinaryOutput(0, PointConfig{Class: 1}, app.Binary{})
	_ = db.AddAnalogOutput(0, PointConfig{Class: 1}, app.Analog{})
	if db.Len(DoubleBitInput) != 1 || db.Len(numPointTypes) != 0 {
		t.Fatal("Len")
	}
	if db.UpdateDoubleBitInput(0, app.DoubleBitBinary{Value: app.DoubleBitOn}) != nil ||
		db.UpdateBinaryOutput(0, app.Binary{Value: true}) != nil || db.UpdateAnalogOutput(0, app.Analog{Value: 3}) != nil {
		t.Fatal("typed updates")
	}
	if err := db.Update(AnalogInput, 7, app.Analog{}, EventOnChange); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("update of missing point")
	}
	if err := db.Update(numPointTypes, 0, app.Analog{}, EventOnChange); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("update of bad type")
	}
	if v, ok := db.Get(BinaryOutput, 0); !ok || !v.(app.Binary).Value {
		t.Fatal("Get")
	}
	if _, ok := db.Get(numPointTypes, 0); ok {
		t.Fatal("Get bad type")
	}
	if !db.Remove(BinaryOutput, 0) || db.Remove(BinaryOutput, 0) || db.Remove(numPointTypes, 0) {
		t.Fatal("Remove")
	}
	for pt := range numPointTypes + 1 {
		if pt.String() == "" {
			t.Fatal("PointType.String")
		}
	}
	for _, o := range []OperateType{SelectBeforeOperate, DirectOperate, DirectOperateNoAck} {
		if o.String() == "" {
			t.Fatal("OperateType.String")
		}
	}
	if srv.Address() != 10 {
		t.Fatal("Address")
	}
	// Option validation.
	for _, opt := range []Option{WithAddress(0xFFF0), WithMasters(0xFFFF), WithHandler(nil), WithMaxConnections(0),
		WithMaxFragment(100, 2048), WithConfirmTimeout(0), WithSelectTimeout(-1), WithMaxControls(0),
		WithUnsolicited(Unsolicited{Classes: []Class{4}}), WithEventLimits(map[PointType]int{BinaryInput: -1}),
		WithTimeSync(-1), WithAttributes(map[uint8]app.Attribute{254: {}})} {
		if _, err := New(opt); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("option accepted: %v", err)
		}
	}
	if _, err := New(WithSecureAuthentication(SecureAuth{})); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("secure authentication without a key accepted")
	}
	// A closed server refuses to serve.
	_ = srv.Close()
	_ = srv.Close()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := srv.Serve(l); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("Serve after Close: %v", err)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if err := srv.ServeConn(a, nil); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("ServeConn after Close: %v", err)
	}
}

func TestNopAndFuncHandlers(t *testing.T) {
	ctx := context.Background()
	if (NopHandler{}).Select(ctx, Command{}) != app.StatusNotSupported || (NopHandler{}).Operate(ctx, Command{}, DirectOperate) != app.StatusNotSupported {
		t.Fatal("NopHandler")
	}
	called := false
	h := HandlerFunc(func(context.Context, Command, OperateType) app.CommandStatus { called = true; return app.StatusLocal })
	if h.Select(ctx, Command{}) != app.StatusSuccess || h.Operate(ctx, Command{}, DirectOperate) != app.StatusLocal || !called {
		t.Fatal("HandlerFunc")
	}
}

// countingHandler accepts every control and records the indexes.
type countingHandler struct {
	mu  sync.Mutex
	idx []uint32
}

func (h *countingHandler) Select(context.Context, Command) app.CommandStatus {
	return app.StatusSuccess
}

func (h *countingHandler) Operate(_ context.Context, c Command, _ OperateType) app.CommandStatus {
	h.mu.Lock()
	h.idx = append(h.idx, c.Index)
	h.mu.Unlock()
	return app.StatusSuccess
}

func (h *countingHandler) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.idx) }

func (h *countingHandler) indexes() []uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint32(nil), h.idx...)
}

// TestSessionKeyChangeForms: the key status message in the key change data
// is accepted with and without its MAC value, since implementations
// differ; anything else is refused and keeps the keys as they were.
func TestSessionKeyChangeForms(t *testing.T) {
	uk := []byte("0123456789abcdef")
	m := newMaster(t, WithHandler(&countingHandler{}), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: uk}}))
	seq := uint8(0)
	status := func() app.AuthSessionKeyStatus {
		t.Helper()
		m.send(req(seq, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
		seq = app.NextSeq(seq)
		return m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus)
	}
	change := func(st app.AuthSessionKeyStatus, withMAC bool, key []byte) (app.Value, []byte, []byte) {
		t.Helper()
		form := st
		if !withMAC {
			form.MACValue = nil
		}
		msg, _ := app.AppendObjectValue(nil, app.G120V5, form)
		ctrl, mon := bytes.Repeat([]byte{byte(seq)}, 16), bytes.Repeat([]byte{byte(seq) + 1}, 16)
		plain, _ := secauth.KeyChangeData(ctrl, mon, msg)
		wrapped, _ := secauth.KeyWrap(key, plain)
		f := req(seq, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: 1, WrappedKeys: wrapped}))
		seq = app.NextSeq(seq)
		raw, _ := f.Encode()
		m.sendRaw(raw)
		return m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value, raw, mon
	}

	st := status()
	if st.Status != app.KeyStatusNotInit || len(st.MACValue) != 0 || st.KeyWrap != app.KeyWrapAES128 || len(st.Challenge) != 32 {
		t.Fatalf("initial key status %+v", st)
	}
	// First change, the form without the MAC (there is none yet anyway).
	v, raw, mon := change(st, false, uk)
	done, ok := v.(app.AuthSessionKeyStatus)
	want, _ := secauth.MAC(done.MAC, mon, raw)
	if !ok || done.Status != app.KeyStatusOK || !secauth.Equal(done.MACValue, want) {
		t.Fatalf("after the first change: %+v", v)
	}
	// Second change, the form with the MAC: accepted too.
	st = status()
	if len(st.MACValue) == 0 {
		t.Fatal("key status of initialized keys without a MAC")
	}
	if v, _, _ := change(st, true, uk); v.(app.AuthSessionKeyStatus).Status != app.KeyStatusOK {
		t.Fatalf("form with MAC refused: %+v", v)
	}
	// Third, without the MAC although there is one: accepted as well.
	st = status()
	if v, _, _ := change(st, false, uk); v.(app.AuthSessionKeyStatus).Status != app.KeyStatusOK {
		t.Fatalf("form without MAC refused: %+v", v)
	}
	// A wrong update key, a stale KSQ, a change without a status request.
	st = status()
	if v, _, _ := change(st, true, []byte("fedcba9876543210")); v.(app.AuthError).Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("wrong update key: %+v", v)
	}
	st.KSQ++
	if v, _, _ := change(st, true, uk); v.(app.AuthError).Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("change without a status request: %+v", v)
	}
	// An unknown user.
	m.send(req(seq, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 9})))
	if v := m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthError); v.Code != app.AuthErrUnknownUser {
		t.Fatalf("unknown user: %+v", v)
	}
}

// TestChallengeReply drives the challenge of a critical request by hand,
// with a pre-shared session key and with session keys from a key change.
func TestChallengeReply(t *testing.T) {
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	answer := func(m *master, seq uint8, key []byte, alg app.MACAlgorithm) (*app.Fragment, error) {
		t.Helper()
		op := req(seq, app.FuncDirectOperate, crob)
		critical, _ := op.Encode()
		m.sendRaw(critical)
		chf := m.recvFunc(app.FuncAuthResponse)
		raw, _ := chf.Encode()
		ch := chf.Headers[0].Objects[0].Value.(app.AuthChallenge)
		mac, err := secauth.MAC(alg, key, secauth.AuthData(raw, critical))
		if err != nil {
			return nil, err
		}
		m.send(req(app.NextSeq(seq), app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: ch.CSQ, User: 1, MAC: mac})))
		return m.recv(), nil
	}

	// Pre-shared session key.
	key := []byte("pre-shared session key 32 octets")
	h := &countingHandler{}
	m := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: key}}))
	f, err := answer(m, 1, key, app.MACHMACSHA256Trunc16)
	if err != nil || f.Function != app.FuncResponse || f.Control.Seq != 2 || h.count() != 1 {
		t.Fatalf("pre-shared key: %v %v executed=%d", f, err, h.count())
	}
	// Its key status is always OK.
	m.send(req(3, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	if st := m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus); st.Status != app.KeyStatusOK {
		t.Fatalf("pre-shared key status %s", st.Status)
	}
	// A wrong key: an authentication error, nothing executed.
	f, _ = answer(m, 4, []byte("wrong"), app.MACHMACSHA256Trunc16)
	if f.Function != app.FuncAuthResponse || f.Headers[0].Objects[0].Value.(app.AuthError).Code != app.AuthErrAuthenticationFailed || h.count() != 1 {
		t.Fatalf("wrong key: %v", f)
	}
	// A reply nobody asked for, and a key change in pre-shared mode.
	m.send(req(6, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: 99, User: 1, MAC: []byte{1}})))
	if v := m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value; v.(app.AuthError).Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("unrequested reply: %v", v)
	}
	m.send(req(7, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: 1, User: 1, WrappedKeys: make([]byte, 24)})))
	if v := m.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value; v.(app.AuthError).Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("key change in pre-shared mode: %v", v)
	}
	// An authentication request with no authentication object.
	m.send(req(8, app.FuncAuthRequest, app.AllObjects(app.G1V0)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("empty authentication request: %s", f.IIN)
	}

	// Session keys from a key change: before it, no reply verifies.
	uk := []byte("0123456789abcdef")
	n := newMaster(t, WithHandler(h), WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: uk}}))
	if f, _ := answer(n, 1, uk, app.MACHMACSHA256Trunc16); f.Function != app.FuncAuthResponse || h.count() != 1 {
		t.Fatalf("reply before any key change: %v", f)
	}
	n.send(req(3, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	st := n.recvFunc(app.FuncAuthResponse).Headers[0].Objects[0].Value.(app.AuthSessionKeyStatus)
	ctrl := bytes.Repeat([]byte{0x11}, 16)
	msg, _ := app.AppendObjectValue(nil, app.G120V5, st)
	plain, _ := secauth.KeyChangeData(ctrl, bytes.Repeat([]byte{0x22}, 16), msg)
	wrapped, _ := secauth.KeyWrap(uk, plain)
	n.send(req(4, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: 1, WrappedKeys: wrapped})))
	n.recvFunc(app.FuncAuthResponse)
	if f, err := answer(n, 5, ctrl, app.MACHMACSHA256Trunc16); err != nil || f.Function != app.FuncResponse || h.count() != 2 {
		t.Fatalf("reply with the negotiated key: %v %v", f, err)
	}

	// An outstation without secure authentication.
	o := newMaster(t)
	o.send(req(1, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})))
	if f := o.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINNoFuncCodeSupport) {
		t.Fatalf("without secure authentication: %s", f.IIN)
	}
}

// TestRelativeTimeCTO: relative-time events carry an unsynchronized CTO
// (g51v2) until the first time synchronization, a synchronized one (g51v1)
// after it, also once the outstation asks for the time again, and an
// unsynchronized one again after a restart and once twice the interval has
// passed without a synchronization.
func TestRelativeTimeCTO(t *testing.T) {
	const interval = 300 * time.Millisecond
	m := newMaster(t, WithTimeSync(interval))
	ctoOf := func(f *app.Fragment) app.GroupVariation {
		t.Helper()
		if len(f.Headers) != 2 || f.Headers[1].GV != app.G2V3 {
			t.Fatalf("headers %v, want a CTO and g2v3", f.Headers)
		}
		return f.Headers[0].GV
	}
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.AllObjects(app.G2V3)))
	f := m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINNeedTime) || ctoOf(f) != app.G51V2 {
		t.Fatalf("unsynchronized: IIN %s, CTO %s", f.IIN, f.Headers[0].GV)
	}
	m.send(confirm(1, false))

	m.send(req(2, app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.Now()})))
	m.recvFunc(app.FuncResponse)
	_ = db.UpdateBinaryInput(0, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(3, app.FuncRead, app.AllObjects(app.G2V3)))
	f = m.recvFunc(app.FuncResponse)
	if f.IIN.Has(app.IINNeedTime) || ctoOf(f) != app.G51V1 {
		t.Fatalf("synchronized: IIN %s, CTO %s", f.IIN, f.Headers[0].GV)
	}
	m.send(confirm(3, false))

	// Due for synchronization: IIN1.4, but still synchronized.
	time.Sleep(interval + 50*time.Millisecond)
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	m.send(req(6, app.FuncRead, app.AllObjects(app.G2V3)))
	f = m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINNeedTime) || ctoOf(f) != app.G51V1 {
		t.Fatalf("due for synchronization: IIN %s, CTO %s", f.IIN, f.Headers[0].GV)
	}
	m.send(confirm(6, false))
	// Twice the interval without one: unsynchronized.
	time.Sleep(interval)
	_ = db.UpdateBinaryInput(0, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(7, app.FuncRead, app.AllObjects(app.G2V3)))
	f = m.recvFunc(app.FuncResponse)
	if ctoOf(f) != app.G51V2 {
		t.Fatalf("synchronization expired: CTO %s", f.Headers[0].GV)
	}
	m.send(confirm(7, false))
	m.send(req(8, app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.Now()})))
	m.recvFunc(app.FuncResponse)

	// After a restart the time is unsynchronized again.
	m.srv.Restart()
	m.send(req(9, app.FuncRead, app.AllObjects(app.G80V1))) // the restart has taken effect once answered
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("no restart: IIN %s", f.IIN)
	}
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	m.send(req(10, app.FuncRead, app.AllObjects(app.G2V3)))
	f = m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINNeedTime) || ctoOf(f) != app.G51V2 {
		t.Fatalf("after a restart: IIN %s, CTO %s", f.IIN, f.Headers[0].GV)
	}
}

// TestReadWithoutFlagsKeepsQuality: a read of a variation without flags
// reports the points whose flags are anything but ONLINE in the variation
// with flags, and the others as asked.
func TestReadWithoutFlagsKeepsQuality(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddCounter(1, PointConfig{}, app.Counter{Value: 2, Flags: app.FlagOnline})
	_ = db.AddAnalogInput(1, PointConfig{}, app.Analog{Value: 3, Flags: app.FlagOnline})
	_ = db.Update(Counter, 0, app.Counter{Value: 1, Flags: app.FlagCommLost}, EventSuppress)
	_ = db.Update(AnalogInput, 0, app.Analog{Value: 5}, EventSuppress)
	cases := []struct{ read, abnormal, normal app.GroupVariation }{
		{app.G20V5, app.G20V1, app.G20V5},
		{app.G20V6, app.G20V2, app.G20V6},
		{app.G30V3, app.G30V1, app.G30V3},
		{app.G30V4, app.G30V2, app.G30V4},
	}
	for i, c := range cases {
		seq := uint8(i + 1)
		m.send(req(seq, app.FuncRead, app.AllObjects(c.read)))
		f := m.recvFunc(app.FuncResponse)
		if len(f.Headers) != 2 || f.Headers[0].GV != c.abnormal || f.Headers[1].GV != c.normal ||
			f.Headers[0].Objects[0].Index != 0 || f.Headers[1].Objects[0].Index != 1 {
			t.Fatalf("read of %s: %v", c.read, f.Headers)
		}
	}
}

// TestReadOfAbsentType: a read of a type the outstation has no points of,
// static or events, is a null response with IIN2.1; a read of the events of
// a type it has, but has no events of, a null response without it.
func TestReadOfAbsentType(t *testing.T) {
	m := newMaster(t)
	for i, gv := range []app.GroupVariation{app.GV(3, 0), app.GV(4, 0), app.GV(21, 0), app.GV(40, 0)} {
		m.send(req(uint8(i+1), app.FuncRead, app.AllObjects(gv)))
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) || len(f.Headers) != 0 {
			t.Fatalf("read of %s: IIN %s, headers %v", gv, f.IIN, f.Headers)
		}
	}
	m.send(req(5, app.FuncRead, app.AllObjects(app.GV(2, 0))))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINObjectUnknown) || len(f.Headers) != 0 {
		t.Fatalf("read of g2v0 without events: IIN %s, headers %v", f.IIN, f.Headers)
	}
}

// TestObjectsWithoutValues: headers whose objects carry indices but no
// value (a qualifier that carries indices only) are answered with IIN2.2,
// not by taking the outstation down. The first is the input the fuzzer
// found: a READ of g70v5.
func TestObjectsWithoutValues(t *testing.T) {
	m := newMaster(t, WithFileServer(FSFileServer{FS: fstest.MapFS{"a.txt": {Data: []byte("hello")}}}))
	for _, raw := range [][]byte{
		[]byte("\xc9\x01F\x05'\x01\b\x00\x01\x00\x00\x00\x00;;\x00\x00\x00"),
		{0xC1, 0x01, 70, 5, 0x17, 1, 0}, // READ g70v5, one index
	} {
		m.sendRaw(raw)
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
			t.Fatalf("% x: IIN %s, want PARAMETER_ERROR", raw, f.IIN)
		}
	}
	// The outstation still answers.
	m.send(req(6, app.FuncRead, app.ClassHeaders(0)...))
	m.recvFunc(app.FuncResponse)
}

// TestHeadersWithoutValuesDispatched: the other requests whose objects
// need a value check it too, although the decoder gives values to every
// object but those of a READ: each header here, with an object without a
// value, is answered with IIN2.2.
func TestHeadersWithoutValuesDispatched(t *testing.T) {
	srv, err := New(WithHandler(&countingHandler{}),
		WithFileServer(FSFileServer{FS: fstest.MapFS{"a.txt": {Data: []byte("hello")}}}),
		WithAttributeSet(1, map[uint8]app.Attribute{10: app.StringAttribute("t")}, 10))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	_ = srv.Database().AddAnalogInput(0, PointConfig{}, app.Analog{Flags: app.FlagOnline})
	_ = srv.Database().Add(OctetString, 0, PointConfig{}, app.OctetString{Data: []byte{1}})
	a := srv.association(1)
	bare := func(gv app.GroupVariation) app.Header {
		return app.Header{GV: gv, Qualifier: app.Qual1ByteIndexCount, Count: 1, Objects: []app.Object{{Index: 0}}}
	}
	crob := app.Counted(app.G12V2, app.CROB{Op: app.OpLatchOn, Count: 1})
	attr := bare(app.GV(0, 10))
	attr.Qualifier, attr.Start, attr.Stop = app.Qual1ByteStartStop, 1, 1
	cases := []struct {
		name string
		fc   app.FunctionCode
		hs   []app.Header
	}{
		{"control", app.FuncDirectOperate, []app.Header{bare(app.G12V1)}},
		{"analog output", app.FuncDirectOperate, []app.Header{bare(app.G41V2)}},
		{"pattern mask", app.FuncDirectOperate, []app.Header{crob, bare(app.G12V3)}},
		{"absolute time", app.FuncWrite, []app.Header{bare(app.G50V1)}},
		{"LAN time", app.FuncWrite, []app.Header{bare(app.G50V3)}},
		{"IIN", app.FuncWrite, []app.Header{bare(app.G80V1)}},
		{"deadband", app.FuncWrite, []app.Header{bare(app.G34V1)}},
		{"octet string", app.FuncWrite, []app.Header{bare(app.GV(110, 1))}},
		{"attribute", app.FuncWrite, []app.Header{attr}},
		{"file block", app.FuncWrite, []app.Header{bare(app.G70V5)}},
		{"freeze at time", app.FuncFreezeAtTime, []app.Header{bare(app.G50V2), app.AllObjects(app.G20V0)}},
	}
	for _, c := range cases {
		done := make(chan *response, 1)
		a.post(func() { done <- a.dispatch(&app.Fragment{Function: c.fc, Headers: c.hs}, inbound{}, false) })
		if r := <-done; r.iin&app.IINParameterError == 0 {
			t.Errorf("%s: IIN %s, want PARAMETER_ERROR", c.name, r.iin)
		}
	}
}

// TestReadDeferredByUnsolicited: a READ that comes while an unsolicited
// response waits for its confirmation is answered once the confirm timeout
// expires, before the response is repeated; the repeat carries the
// indications as they are then (IIN1.7 cleared meanwhile). A READ during
// the repeat is answered as soon as it is confirmed.
func TestReadDeferredByUnsolicited(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Retries: 3}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	if !null.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("null unsolicited IIN %s", null.IIN)
	}
	// A WRITE is answered at once.
	m.send(req(1, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 1 {
		t.Fatalf("write answered with %s", f)
	}
	sent := time.Now()
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	f := m.recv()
	if f.Function != app.FuncResponse || f.Control.Seq != 2 {
		t.Fatalf("first after the deferred READ: %s", f)
	}
	if time.Since(sent) < 200*time.Millisecond {
		t.Fatal("READ answered before the unsolicited confirm timeout")
	}
	retry := m.recv()
	if retry.Function != app.FuncUnsolicitedResponse || retry.Control.Seq != null.Control.Seq {
		t.Fatalf("after the READ: %s", retry)
	}
	if retry.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("repeat still reports IIN1.7: %s", retry.IIN)
	}
	m.send(req(3, app.FuncRead, app.ClassHeaders(0)...))
	m.none(100 * time.Millisecond)
	m.send(confirm(retry.Control.Seq, true))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 {
		t.Fatalf("READ after the confirmation: %s", f)
	}
}

// TestDeferredReadTakesUnsolicitedEvents: a READ deferred by an unconfirmed
// unsolicited response with events reports those events once the confirm
// timeout expires, and the unsolicited response is not repeated.
func TestDeferredReadTakesUnsolicitedEvents(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{1}, Retries: 3}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	if u := m.recvFunc(app.FuncUnsolicitedResponse); len(u.Headers) == 0 {
		t.Fatalf("unsolicited without events: %s", u)
	}
	m.send(req(1, app.FuncRead, app.ClassHeaders(1, 2, 3)...))
	f := m.recv()
	if f.Function != app.FuncResponse || !f.Control.CON || len(f.Headers) != 1 || f.Headers[0].GV.Group() != 2 {
		t.Fatalf("deferred READ answered with %s", f)
	}
	m.send(confirm(f.Control.Seq, false))
	m.none(500 * time.Millisecond)
}

// TestUnsolicitedRepeatWaitsForResponse: the null unsolicited response is
// not repeated while the response to a deferred READ waits for its
// confirmation (300 ms here), and is repeated once it is confirmed.
func TestUnsolicitedRepeatWaitsForResponse(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Retries: 3}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	_ = m.srv.Database().UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.ClassHeaders(1)...))
	f := m.recv()
	if f.Function != app.FuncResponse || !f.Control.CON {
		t.Fatalf("deferred READ answered with %s", f)
	}
	m.none(150 * time.Millisecond)
	m.send(confirm(f.Control.Seq, false))
	if r := m.recv(); r.Function != app.FuncUnsolicitedResponse || r.Control.Seq != null.Control.Seq || len(r.Headers) != 0 {
		t.Fatalf("after the confirmation: %s", r)
	}
}

// TestDeferredReadSuperseded: a request that comes after a deferred READ is
// answered at once, and the READ is not answered at all.
func TestDeferredReadSuperseded(t *testing.T) {
	m := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Retries: 3}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(req(1, app.FuncRead, app.ClassHeaders(0)...))
	m.send(req(2, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})))
	if f := m.recv(); f.Function != app.FuncResponse || f.Control.Seq != 2 {
		t.Fatalf("after the WRITE: %s", f)
	}
	if f := m.recv(); f.Function != app.FuncUnsolicitedResponse || f.Control.Seq != null.Control.Seq {
		t.Fatalf("at the confirm timeout: %s", f)
	}
	m.send(confirm(null.Control.Seq, true))
	m.none(200 * time.Millisecond)
}

// TestUnsolicitedUnlimitedRetries: with a negative Retries an unconfirmed
// unsolicited response is repeated until it is confirmed.
func TestUnsolicitedUnlimitedRetries(t *testing.T) {
	m := newMaster(t, WithConfirmTimeout(50*time.Millisecond), WithUnsolicited(Unsolicited{Enabled: true, Retries: -1}))
	first := m.recvFunc(app.FuncUnsolicitedResponse)
	for range 8 {
		if f := m.recvFunc(app.FuncUnsolicitedResponse); f.Control.Seq != first.Control.Seq || len(f.Headers) != 0 {
			t.Fatalf("repeat %s", f)
		}
	}
	m.send(confirm(first.Control.Seq, true))
	time.Sleep(60 * time.Millisecond)
	for len(m.in) > 0 {
		<-m.in
	}
	m.none(200 * time.Millisecond)
}

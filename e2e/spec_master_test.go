// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// The master's procedures of IEEE 1815-2012 against the go-dnp3
// outstation. The client's own spec tests (client/spec_*_test.go) check
// the octets against scripted outstations.

// requestLog is a client metrics that records the function code of every
// request and the link function of every frame the client sends.
type requestLog struct {
	dnp3.NopMetrics
	mu     sync.Mutex
	fcs    []app.FunctionCode
	frames map[app.FunctionCode][]link.Function
}

func (r *requestLog) OnRequest(_ net.Addr, _ uint16, fc app.FunctionCode) {
	r.mu.Lock()
	r.fcs = append(r.fcs, fc)
	r.mu.Unlock()
}

func (*requestLog) OnRequestDone(net.Addr, uint16, app.FunctionCode, time.Duration, error) {}
func (*requestLog) OnRetry(net.Addr, uint16, app.FunctionCode, int, error)                 {}

func (r *requestLog) OnFrameSent(_ net.Addr, f *linkFrame, _ int) {
	// The transport header with FIR, the application control and the
	// function code.
	if len(f.Data) < 3 || f.Data[0]&0x40 == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frames == nil {
		r.frames = map[app.FunctionCode][]link.Function{}
	}
	fc := app.FunctionCode(f.Data[2])
	r.frames[fc] = append(r.frames[fc], f.Function)
}

func (r *requestLog) requests() []app.FunctionCode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.fcs)
}

// waitAfter waits until the requests from index n on start with want and
// returns them.
func (r *requestLog) waitAfter(t *testing.T, n int, want ...app.FunctionCode) []app.FunctionCode {
	t.Helper()
	var got []app.FunctionCode
	waitUntil(t, "requests "+fcList(want), func() bool {
		got = r.requests()[n:]
		return len(got) >= len(want)
	})
	if !slices.Equal(got[:len(want)], want) {
		t.Fatalf("requests %s, want %s", fcList(got), fcList(want))
	}
	return got
}

func fcList(fcs []app.FunctionCode) string {
	var b bytes.Buffer
	for i, fc := range fcs {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(fc.String())
	}
	return b.String()
}

// TestSpec5_1_1_1_2_Rule2_RestartReenablesUnsolicited: IEEE 1815-2012
// clause 5.1.1.1.2 Rule 2 (printed page 102): on IIN1.7 the master clears
// it, performs an integrity poll and, when it uses unsolicited reporting
// with the outstation, enables it again; Table 6-3 row 8 (p. 169) asks
// the same of an unsolicited response that reports a restart. The
// outstation disabled unsolicited reporting at its restart (clause
// 5.1.1.1.1 Rule 3, p. 101): after the procedure, its events are reported
// unsolicited again (MASTER-2).
func TestSpec5_1_1_1_2_Rule2_RestartReenablesUnsolicited(t *testing.T) {
	log := &requestLog{}
	p := newPair(t, fullDatabase, []server.Option{server.WithUnsolicited(server.Unsolicited{Enabled: true})},
		client.WithMetrics(log), client.WithAutoIntegrity(true),
		client.WithStartup(client.Startup{EnableUnsolicited: []int{1, 2, 3}}))
	log.waitAfter(t, 0, app.FuncDisableUnsolicited, app.FuncWrite, app.FuncRead, app.FuncEnableUnsolicited)
	_ = p.db.UpdateBinaryInput(4, app.Binary{Value: false, Flags: app.FlagOnline})
	p.rec.waitFor(t, "an unsolicited event", func(ms []client.Measurement) bool { return len(ms) >= 1 })

	n := len(log.requests())
	p.srv.Restart()
	log.waitAfter(t, n, app.FuncWrite, app.FuncRead, app.FuncEnableUnsolicited)
	before := len(p.rec.waitFor(t, "", func([]client.Measurement) bool { return true }))
	_ = p.db.UpdateBinaryInput(4, app.Binary{Value: true, Flags: app.FlagOnline})
	ms := p.rec.waitFor(t, "an unsolicited event after the restart", func(ms []client.Measurement) bool { return len(ms) > before })
	if m := ms[len(ms)-1]; m.GV.Group() != 2 || m.Index != 4 {
		t.Fatalf("unsolicited %s index %d", m.GV, m.Index)
	}
	res, err := p.c.Read(ctx(t), app.AllObjects(app.G80V1))
	if err != nil || res.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("restart not cleared: %v %v", res, err)
	}
}

// TestSpec5_1_1_1_2_Rule2_SessionKeysFirst: clause 5.1.1.1.2 Rule 2 step 1
// (p. 102): "If both the master and outstation support secure
// authentication and are configured to use it, the master shall set the
// session keys" before it clears IIN1.7 (MASTER-4). The key change, a
// session key status request (g120v4) and a session key change (g120v6),
// is one AUTH_REQUEST procedure.
func TestSpec5_1_1_1_2_Rule2_SessionKeysFirst(t *testing.T) {
	log := &requestLog{}
	sa := server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: updateKey}})
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithUnsolicited(server.Unsolicited{Enabled: true}), server.WithHandler(r), sa},
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey}),
		client.WithMetrics(log), client.WithAutoIntegrity(true))
	// The restart of the first response is answered first.
	waitUntil(t, "the startup procedures", func() bool {
		res, err := p.c.Read(ctx(t), app.AllObjects(app.G80V1))
		return err == nil && !res.IIN.Has(app.IINDeviceRestart)
	})
	n := len(log.requests())
	p.srv.Restart()
	log.waitAfter(t, n, app.FuncAuthRequest, app.FuncWrite, app.FuncRead)
	// Controls work with the new keys.
	if st, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0)); err != nil || st[0] != app.StatusSuccess {
		t.Fatalf("control after the restart: %v %v", st, err)
	}
}

// TestSpec5_1_1_2_Rule1_DefaultStartup: clause 5.1.1.2 Rule 1 (pp.
// 102-103): the master performs an integrity poll at startup; by default
// Connect returns after it (MASTER-6). Clause 4.5.5 (p. 83): "If the
// outstation sets this bit [NEED_TIME], the master shall promptly perform
// a write time sequence": by default the client does, over TCP with the
// LAN procedure (MASTER-5).
func TestSpec5_1_1_2_Rule1_DefaultStartup(t *testing.T) {
	r := &relay{}
	reads := &readCounter{}
	srv, err := server.New(server.WithMasters(1), server.WithHandler(r), server.WithMetrics(reads), server.WithTimeSync(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	rec := newRecorder()
	c, err := client.Dial(ctx(t), l.Addr().String(), client.WithHandler(rec))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	reads.mu.Lock()
	n := reads.reads
	reads.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d READ requests before Connect returned, want the integrity poll", n)
	}
	waitUntil(t, "the startup measurements", func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.ms) >= 15
	})
	waitUntil(t, "the automatic time synchronization", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.times) == 1
	})
	res, err := c.Read(ctx(t), app.AllObjects(app.G80V1))
	if err != nil || res.IIN.Has(app.IINNeedTime) || res.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("after the automatic tasks: %v %v", res, err)
	}
	if d := time.Since(srv.Now()).Abs(); d > time.Second {
		t.Fatalf("outstation clock off by %v", d)
	}
}

// TestSpec4_4_4_3_Rule8_OutstationEchoOperated: clause 4.4.4.3 Rule 8
// (p. 51): the master compares the select response with its request octet
// for octet. The go-dnp3 outstation's echo of every control object the
// client sends matches, and the controls are operated.
func TestSpec4_4_4_3_Rule8_OutstationEchoOperated(t *testing.T) {
	r := &relay{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r)})
	cmds := []client.Command{
		client.CROB(2, app.OpPulseOn, 250, 750),
		{Index: 0, Value: app.AnalogOutput{Value: 12}, GV: app.G41V1},
		{Index: 0, Value: app.AnalogOutput{Value: -7}, GV: app.G41V2},
		{Index: 0, Value: app.AnalogOutput{Value: 1.25}, GV: app.G41V3},
		{Index: 0, Value: app.AnalogOutput{Value: 3.5}, GV: app.G41V4},
	}
	for _, cmd := range cmds {
		if st, err := p.c.Operate(ctx(t), client.SelectBeforeOperate, cmd); err != nil || st[0] != app.StatusSuccess {
			t.Fatalf("%s: %v %v", cmd.GV, st, err)
		}
	}
	if sel, op, _ := r.snapshot(); len(sel) != len(cmds) || len(op) != len(cmds) {
		t.Fatalf("%d selects and %d operates, want %d", len(sel), len(op), len(cmds))
	}
}

// TestSpec10_3_4_1_LinkConfirmedTimeSync: clause 10.3.4.1 (p. 303): time
// synchronization messages go as UNCONFIRMED_USER_DATA, also between a
// master and an outstation that confirm user data otherwise (MASTER-9),
// and the outstation's clock is set. The automatic clearing of IIN1.7 is
// off: the only WRITEs are those of the time synchronization.
func TestSpec10_3_4_1_LinkConfirmedTimeSync(t *testing.T) {
	log := &requestLog{}
	p := newPair(t, fullDatabase, []server.Option{server.WithLink(server.Link{Confirmed: true}), server.WithTimeSync(time.Hour)},
		client.WithLink(client.Link{Confirmed: true}), client.WithMetrics(log), client.WithTimeSync(client.TimeSyncNone),
		client.WithAutoClearRestart(false))
	for _, proc := range []client.TimeSync{client.TimeSyncLAN, client.TimeSyncNonLAN} {
		if err := p.c.SyncTime(ctx(t), proc); err != nil {
			t.Fatalf("procedure %d: %v", proc, err)
		}
		if d := time.Since(p.srv.Now()).Abs(); d > 100*time.Millisecond {
			t.Fatalf("procedure %d: outstation clock off by %v", proc, d)
		}
	}
	if _, err := p.c.IntegrityPoll(ctx(t)); err != nil {
		t.Fatal(err)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, fc := range []app.FunctionCode{app.FuncRecordCurrentTime, app.FuncDelayMeasure, app.FuncWrite} {
		if got := log.frames[fc]; len(got) == 0 || slices.ContainsFunc(got, func(f link.Function) bool { return f != link.PrimaryUnconfirmedUserData }) {
			t.Errorf("%s sent as %v", fc, got)
		}
	}
	if got := log.frames[app.FuncRead]; len(got) == 0 || got[0] != link.PrimaryConfirmedUserData {
		t.Errorf("READ sent as %v", got)
	}
}

// TestSpec4_5_12_AutoIntegrityOnOverflow: after a response with IIN2.3
// (EVENT_BUFFER_OVERFLOW) the client runs an integrity poll with
// WithAutoIntegrity, as NOTE 2 of clause 4.5.12 (p. 86) suggests; the
// note is informative and this is the library's behaviour.
func TestSpec4_5_12_AutoIntegrityOnOverflow(t *testing.T) {
	log := &requestLog{}
	p := newPair(t, fullDatabase, []server.Option{server.WithEventLimits(map[server.PointType]int{server.BinaryInput: 3})},
		client.WithAutoIntegrity(true), client.WithAutoClearRestart(false), client.WithMetrics(log))
	for i := range 10 {
		_ = p.db.UpdateBinaryInput(0, app.Binary{Value: i%2 == 0, Flags: app.FlagOnline})
	}
	res, err := p.c.EventPoll(ctx(t))
	if err != nil || !res.IIN.Has(app.IINEventBufferOverflow) {
		t.Fatalf("event poll: %v %v", res, err)
	}
	n := len(log.requests())
	log.waitAfter(t, n, app.FuncRead)
	waitUntil(t, "the integrity poll's static data", func() bool {
		p.rec.mu.Lock()
		defer p.rec.mu.Unlock()
		statics := 0
		for _, m := range p.rec.ms {
			if !m.Event {
				statics++
			}
		}
		return statics >= 15
	})
}

// TestSpec4_4_17_2_1_WriteFileWithRequestLimit: clause 4.3 Rule 4 (p. 39):
// a master configured to send requests of at most 249 octets; clause
// 4.4.17.2.1 (p. 68): the file size is the total number of octets the
// write requests transfer. A file written in blocks that fit 249-octet
// requests arrives whole at the outstation, and a reader longer than the
// size given is cut at the size (OBJECTS2-29, APPSTRUCT-5).
func TestSpec4_4_17_2_1_WriteFileWithRequestLimit(t *testing.T) {
	fs := newMemFS()
	p := newPair(t, fullDatabase, []server.Option{server.WithFileServer(fs)}, client.WithMaxRequestFragment(249))
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64) // 1024 octets
	long := append(slices.Clone(payload), "beyond the size"...)
	n, err := p.c.WriteFile(ctx(t), "/up.bin", bytes.NewReader(long), uint32(len(payload)), client.FileOptions{MaxBlockSize: 1024})
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("WriteFile: %d %v", n, err)
	}
	fs.mu.Lock()
	got := fs.files["/up.bin"]
	fs.mu.Unlock()
	if !bytes.Equal(got, payload) {
		t.Fatalf("outstation has %d octets, want %d", len(got), len(payload))
	}
	var back bytes.Buffer
	if _, err := p.c.ReadFile(ctx(t), "/up.bin", &back, client.FileOptions{}); err != nil || !bytes.Equal(back.Bytes(), payload) {
		t.Fatalf("ReadFile: %d octets, %v", back.Len(), err)
	}
}

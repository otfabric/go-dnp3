// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// sboRecorder records the controls passed to Select and Operate. Select
// refuses index 1 with LOCAL, and Operate refuses anything but the OPERATE
// of a select-before-operate pair.
type sboRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *sboRecorder) Select(_ context.Context, c Command) app.CommandStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("select %d", c.Index))
	if c.Index == 1 {
		return app.StatusLocal
	}
	return app.StatusSuccess
}

func (r *sboRecorder) Operate(_ context.Context, c Command, op OperateType) app.CommandStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("operate %d", c.Index))
	if op != SelectBeforeOperate {
		return app.StatusNotAuthorized
	}
	return app.StatusSuccess
}

func (r *sboRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

func crobs(statuses ...app.CommandStatus) app.Header {
	objs := make([]app.Object, len(statuses))
	for i, s := range statuses {
		objs[i] = app.Object{Index: uint32(i), Value: app.CROB{Op: app.OpLatchOn, Count: 1, Status: s}}
	}
	return app.Indexed(app.G12V1, objs...)
}

func echoStatuses(t *testing.T, f *app.Fragment) []app.CommandStatus {
	t.Helper()
	if len(f.Headers) != 1 {
		t.Fatalf("echo %v", f)
	}
	var out []app.CommandStatus
	for _, o := range f.Headers[0].Objects {
		out = append(out, o.Value.(app.CROB).Status)
	}
	return out
}

// TestOperateOnlyWhatSelectSelected: a control the SELECT marked
// NON_PARTICIPATING (126) was not selected (IEEE 1815-2012 4.4.4, p. 48;
// Table 11-7 footnote a, p. 330): an OPERATE that carries it with status 0
// matches no SELECT, is answered NO_SELECT for every control, and reaches
// neither Select nor Operate. An OPERATE with the octets of its SELECT is
// carried out as before.
func TestOperateOnlyWhatSelectSelected(t *testing.T) {
	const (
		ok  = app.StatusSuccess
		np  = app.StatusNonParticipating
		nos = app.StatusNoSelect
	)
	for _, tc := range []struct {
		name              string
		sel, op           []app.CommandStatus
		selCalls, opCalls []string
		selEcho, opEcho   []app.CommandStatus
	}{
		{name: "single 126 then 0", sel: []app.CommandStatus{np}, op: []app.CommandStatus{ok},
			selEcho: []app.CommandStatus{np}, opEcho: []app.CommandStatus{nos}},
		{name: "multi 0,126 then 0,0", sel: []app.CommandStatus{ok, np}, op: []app.CommandStatus{ok, ok},
			selCalls: []string{"select 0"}, selEcho: []app.CommandStatus{ok, np}, opEcho: []app.CommandStatus{nos, nos}},
		{name: "single 126 then 126", sel: []app.CommandStatus{np}, op: []app.CommandStatus{np},
			selEcho: []app.CommandStatus{np}, opEcho: []app.CommandStatus{np}},
		{name: "multi 0,126 then 0,126", sel: []app.CommandStatus{ok, np}, op: []app.CommandStatus{ok, np},
			selCalls: []string{"select 0"}, opCalls: []string{"operate 0"},
			selEcho: []app.CommandStatus{ok, np}, opEcho: []app.CommandStatus{ok, np}},
		{name: "single 0 then 0", sel: []app.CommandStatus{ok}, op: []app.CommandStatus{ok},
			selCalls: []string{"select 0"}, opCalls: []string{"operate 0"},
			selEcho: []app.CommandStatus{ok}, opEcho: []app.CommandStatus{ok}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &sboRecorder{}
			m := newMaster(t, WithHandler(r))
			m.send(req(5, app.FuncSelect, crobs(tc.sel...)))
			if got := echoStatuses(t, m.recvFunc(app.FuncResponse)); !slices.Equal(got, tc.selEcho) {
				t.Fatalf("SELECT echo %v, want %v", got, tc.selEcho)
			}
			if got := r.take(); fmt.Sprint(got) != fmt.Sprint(tc.selCalls) {
				t.Fatalf("SELECT calls %v, want %v", got, tc.selCalls)
			}
			m.send(req(6, app.FuncOperate, crobs(tc.op...)))
			if got := echoStatuses(t, m.recvFunc(app.FuncResponse)); !slices.Equal(got, tc.opEcho) {
				t.Fatalf("OPERATE echo %v, want %v", got, tc.opEcho)
			}
			if got := r.take(); fmt.Sprint(got) != fmt.Sprint(tc.opCalls) {
				t.Fatalf("OPERATE calls %v, want %v", got, tc.opCalls)
			}
		})
	}
}

// TestFreezeLimitAcrossRequests: requests that come at once, as from
// several associations, together keep at most MaxScheduledFreezes
// schedules; exactly that many of them are accepted.
func TestFreezeLimitAcrossRequests(t *testing.T) {
	m := newMaster(t)
	s := m.srv
	later := app.TimestampOf(s.Now().Add(time.Hour))
	const n = 4 * MaxScheduledFreezes
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			iin := s.freezeAtTime([]app.Header{app.Counted(app.G50V2, app.AbsoluteTime{Time: later}),
				app.IndexRange(app.G20V0, uint32(i), uint32(i))})
			if iin == 0 {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := len(schedules(s)); got != MaxScheduledFreezes || accepted != MaxScheduledFreezes {
		t.Fatalf("%d schedules, %d accepted; want %d", got, accepted, MaxScheduledFreezes)
	}
}

// TestFreezeIntervalFloor: a periodic FREEZE_AT_TIME interval shorter than
// minFreezeInterval is served as minFreezeInterval; a longer one as it is.
func TestFreezeIntervalFloor(t *testing.T) {
	m := newMaster(t)
	s := m.srv
	interval := func() time.Duration {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, f := range s.freezes {
			return f.interval
		}
		return -1
	}
	later := app.TimestampOf(s.Now().Add(time.Hour))
	points := app.IndexRange(app.G20V0, 0, 0)
	for _, tc := range []struct {
		ms   uint32
		want time.Duration
	}{
		{1, minFreezeInterval},
		{uint32(minFreezeInterval/time.Millisecond) - 1, minFreezeInterval},
		{uint32(minFreezeInterval / time.Millisecond), minFreezeInterval},
		{60000, time.Minute},
	} {
		if iin := s.freezeAtTime([]app.Header{app.Counted(app.G50V2, app.AbsoluteTime{Time: later, Interval: tc.ms}), points}); iin != 0 {
			t.Fatalf("interval %d ms: IIN %s", tc.ms, iin)
		}
		if got := interval(); got != tc.want {
			t.Fatalf("interval %d ms served as %v, want %v", tc.ms, got, tc.want)
		}
	}
	// Time 0 with an interval: from the start of the hour, at the floor.
	if iin := s.freezeAtTime([]app.Header{app.Counted(app.G50V2, app.AbsoluteTime{Interval: 1}), points}); iin != 0 {
		t.Fatalf("time 0, interval 1 ms: IIN %s", iin)
	}
	if got := interval(); got != minFreezeInterval {
		t.Fatalf("time 0, interval 1 ms served as %v", got)
	}
}

// TestIndexedAttributeWriteSets: an index-prefixed WRITE of group 0 writes
// each object to the set its own index names (IEEE 1815-2012 5.5.6,
// pp. 151-152); an object of a set that does not exist sets IIN2.2 and the
// others are written.
func TestIndexedAttributeWriteSets(t *testing.T) {
	h := &attrRecorder{}
	m := newMaster(t, WithHandler(h),
		WithAttributeSet(1, map[uint8]app.Attribute{10: app.StringAttribute("one")}, 10),
		WithAttributeSet(2, map[uint8]app.Attribute{10: app.StringAttribute("two")}))
	m.send(req(1, app.FuncWrite, app.Indexed(app.GV(0, 10),
		app.Object{Index: 2, Value: app.StringAttribute("x")},
		app.Object{Index: 1, Value: app.StringAttribute("y")},
		app.Object{Index: 7, Value: app.StringAttribute("z")},
		app.Object{Index: 0x10000, Value: app.StringAttribute("w")})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("write to read-only and missing sets: %v", f)
	}
	value := func(set uint16) string {
		as := m.srv.opts.attributes[set]
		as.mu.Lock()
		defer as.mu.Unlock()
		return string(as.attrs[10].Data)
	}
	if v1, v2 := value(1), value(2); v1 != "y" || v2 != "two" {
		t.Fatalf("set 1 %q, set 2 %q: want y and two", v1, v2)
	}
	if fmt.Sprint(h.sets) != "[y]" {
		t.Fatalf("handler told of %v, want [y]", h.sets)
	}
}

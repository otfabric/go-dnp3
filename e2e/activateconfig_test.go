// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
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

// activator answers ACTIVATE_CONFIG with status 0 for every file
// specification, or with what status and iin say.
type activator struct {
	server.NopHandler
	mu     sync.Mutex
	names  []string
	status *app.ActivateConfigStatus
	iin    app.IIN
	apps   []app.FunctionCode
}

func (a *activator) ActivateConfig(_ context.Context, hs []app.Header) (app.ActivateConfigStatus, app.IIN) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := app.ActivateConfigStatus{Delay: 250 * time.Millisecond}
	for _, h := range hs {
		for _, o := range h.Objects {
			if fs, ok := o.Value.(app.FileSpecification); ok {
				a.names = append(a.names, fs.Name)
				st.Results = append(st.Results, app.ActivateConfigResult{Code: 0, Text: fs.Name})
			}
		}
	}
	if a.status != nil {
		st = *a.status
	}
	return st, a.iin
}

func (a *activator) Application(_ context.Context, fc app.FunctionCode, _ []app.Header) app.IIN {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apps = append(a.apps, fc)
	return 0
}

// applicationOnly has the ApplicationHandler of v1.5 only.
type applicationOnly struct{ server.NopHandler }

func (applicationOnly) Application(context.Context, app.FunctionCode, []app.Header) app.IIN { return 0 }

func specs(names ...string) app.Header {
	vs := make([]app.Value, len(names))
	for i, n := range names {
		vs[i] = app.FileSpecification{Name: n}
	}
	return app.FreeFormat(app.G70V8, vs...)
}

func TestActivateConfig(t *testing.T) {
	h := &activator{}
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(h)})
	got, err := p.c.ActivateConfig(ctx(t), specs("a.xml", "b.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []app.ActivateConfigStatus{{Delay: 250 * time.Millisecond,
		Results: []app.ActivateConfigResult{{Text: "a.xml"}, {Text: "b.xml"}}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(h.names, []string{"a.xml", "b.xml"}) {
		t.Fatalf("handler saw %v", h.names)
	}
	// The other application functions still go to ApplicationHandler.
	if _, err := p.c.Request(ctx(t), app.FuncSaveConfiguration); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.apps, []app.FunctionCode{app.FuncSaveConfiguration}) {
		t.Fatalf("ApplicationHandler saw %v", h.apps)
	}

	// An error bit refuses the request, without a status.
	h.mu.Lock()
	h.iin = app.IINParameterError | app.IINClass1Events // only the IIN2 errors are kept
	h.mu.Unlock()
	_, err = p.c.ActivateConfig(ctx(t), specs("c.xml"))
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINParameterError) {
		t.Fatalf("refused: %v", err)
	}

	// A status that does not encode or fit is answered with PARAMETER_ERROR.
	h.mu.Lock()
	h.iin = 0
	h.status = &app.ActivateConfigStatus{Delay: -time.Second}
	h.mu.Unlock()
	if _, err := p.c.ActivateConfig(ctx(t), specs("d.xml")); !errors.As(err, &ie) || !ie.IIN.Has(app.IINParameterError) {
		t.Fatalf("invalid status: %v", err)
	}
	big := app.ActivateConfigStatus{Results: make([]app.ActivateConfigResult, 20)}
	for i := range big.Results {
		big.Results[i].Text = strings.Repeat("x", 200)
	}
	h.mu.Lock()
	h.status = &big
	h.mu.Unlock()
	if _, err := p.c.ActivateConfig(ctx(t), specs("e.xml")); !errors.As(err, &ie) || !ie.IIN.Has(app.IINParameterError) {
		t.Fatalf("status larger than a fragment: %v", err)
	}

	if _, err := p.c.ActivateConfig(ctx(t)); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("without headers: %v", err)
	}
}

func TestActivateConfigWithoutStatus(t *testing.T) {
	// An ApplicationHandler alone answers with IIN bits only, as before.
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(applicationOnly{})})
	res, err := p.c.Request(ctx(t), app.FuncActivateConfig, specs("a.xml"))
	if err != nil || len(res.Headers()) != 0 {
		t.Fatalf("ApplicationHandler: %v, %d headers", err, len(res.Headers()))
	}
	if _, err := p.c.ActivateConfig(ctx(t), specs("a.xml")); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("response without g91v1: %v", err)
	}
	// Without either, the function is not supported.
	q := newPair(t, fullDatabase, nil)
	_, err = q.c.ActivateConfig(ctx(t), specs("a.xml"))
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINNoFuncCodeSupport) {
		t.Fatalf("unsupported: %v", err)
	}
}

// unsCounter counts the unsolicited fragments a client receives.
type unsCounter struct {
	dnp3.NopMetrics
	mu  sync.Mutex
	uns int
}

func (m *unsCounter) OnFragmentReceived(_ net.Addr, f *app.Fragment, _ int) {
	if f.Function == app.FuncUnsolicitedResponse {
		m.mu.Lock()
		m.uns++
		m.mu.Unlock()
	}
}

func (m *unsCounter) get() int { m.mu.Lock(); defer m.mu.Unlock(); return m.uns }

func TestWithoutSolicitedConfirm(t *testing.T) {
	m := &countingMetrics{}
	p := newPair(t, fullDatabase, []server.Option{server.WithConfirmTimeout(200 * time.Millisecond)},
		client.WithSolicitedConfirm(false), client.WithMetrics(m))
	if _, err := p.c.IntegrityPoll(ctx(t)); err != nil {
		t.Fatal(err)
	}
	_ = p.db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	// The event is not confirmed, so every poll gets it again.
	for i := range 3 {
		res, err := p.c.EventPoll(ctx(t), 1)
		if err != nil {
			t.Fatal(err)
		}
		if got := gvs(res.Measurements()); !reflect.DeepEqual(got, []string{"g2v2"}) {
			t.Fatalf("poll %d: events %v", i, got)
		}
	}
	// The client sent requests only, no confirmation.
	if sent, done := m.get(&m.fragsSent), m.get(&m.requestsDone); sent != done {
		t.Fatalf("%d fragments sent for %d requests", sent, done)
	}

	// A multi-fragment response stalls after its first fragment.
	q := newPair(t, func(db *server.Database) {
		for i := range uint32(300) {
			_ = db.AddCounter(i, server.PointConfig{}, app.Counter{Value: i, Flags: app.FlagOnline})
		}
	}, []server.Option{server.WithMaxFragment(249, 2048)}, client.WithSolicitedConfirm(false),
		client.WithResponseTimeout(300*time.Millisecond))
	res, err := q.c.Read(ctx(t), app.AllObjects(app.G20V1))
	if !errors.Is(err, dnp3.ErrTimeout) || len(res.Fragments) != 1 {
		t.Fatalf("multi-fragment: %v after %d fragments", err, len(res.Fragments))
	}
}

func TestWithoutUnsolicitedConfirm(t *testing.T) {
	sm := &countingMetrics{}
	cm := &unsCounter{}
	p := newPair(t, fullDatabase, []server.Option{
		server.WithUnsolicited(server.Unsolicited{Enabled: true, Classes: []server.Class{1, 2, 3}, Retries: 2, RetryDelay: time.Minute}),
		server.WithConfirmTimeout(100 * time.Millisecond), server.WithMetrics(sm),
	}, client.WithUnsolicitedConfirm(false), client.WithMetrics(cm))
	_ = p.db.UpdateBinaryInput(4, app.Binary{Value: false, Flags: app.FlagOnline})
	// Unconfirmed, the null unsolicited response of the connection is sent
	// three times (Retries 2) and given up; the event waits behind it.
	waitUntil(t, "unsolicited response given up", func() bool { return sm.get(&sm.unsolicited) >= 1 })
	if n := cm.get(); n != 3 {
		t.Fatalf("%d unsolicited fragments, want 3", n)
	}
	// Requests are still answered, and solicited responses confirmed.
	res, err := p.c.EventPoll(ctx(t))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("poll: %v, %d events", err, len(res.Measurements()))
	}
	if res, _ := p.c.EventPoll(ctx(t)); len(res.Measurements()) != 0 {
		t.Fatalf("events left after a confirmed poll: %v", gvs(res.Measurements()))
	}
	// The same outstation with a confirming client: the null response is
	// sent once.
	cm2 := &unsCounter{}
	q := newPair(t, fullDatabase, []server.Option{
		server.WithUnsolicited(server.Unsolicited{Enabled: true, Retries: 2, RetryDelay: time.Minute}),
		server.WithConfirmTimeout(100 * time.Millisecond),
	}, client.WithMetrics(cm2))
	if _, err := q.c.IntegrityPoll(ctx(t)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "null unsolicited response", func() bool { return cm2.get() >= 1 })
	time.Sleep(300 * time.Millisecond) // three confirm timeouts: no repeat
	if n := cm2.get(); n != 1 {
		t.Fatalf("confirming client: %d unsolicited fragments, want 1", n)
	}
}

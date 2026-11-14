// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// droppedMetrics records the calls of dnp3.ClientMetrics.
type droppedMetrics struct {
	dnp3.NopMetrics
	mu      sync.Mutex
	dropped []string
	late    []app.FunctionCode
	remotes []net.Addr
	changed chan struct{}
}

func newDroppedMetrics() *droppedMetrics { return &droppedMetrics{changed: make(chan struct{}, 1)} }

func (m *droppedMetrics) OnTaskDropped(name string) {
	m.mu.Lock()
	m.dropped = append(m.dropped, name)
	m.mu.Unlock()
}

func (m *droppedMetrics) OnLateResponse(remote net.Addr, fc app.FunctionCode) {
	m.mu.Lock()
	m.late = append(m.late, fc)
	m.remotes = append(m.remotes, remote)
	m.mu.Unlock()
	m.notify()
}

func (m *droppedMetrics) notify() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// waitLate waits until n late responses were reported and returns their
// function codes.
func (m *droppedMetrics) waitLate(t *testing.T, n int) []app.FunctionCode {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		m.mu.Lock()
		late := slices.Clone(m.late)
		m.mu.Unlock()
		if len(late) >= n {
			return late
		}
		select {
		case <-m.changed:
		case <-deadline:
			t.Fatalf("%d late responses reported, want %d", len(late), n)
		}
	}
}

// TestClientMetricsTaskDropped: an automatic task that finds the task
// queue full is reported to OnTaskDropped with its name; one already
// queued is not queued twice, and not reported.
func TestClientMetricsTaskDropped(t *testing.T) {
	m := newDroppedMetrics()
	c, _ := pipeClient(t, nil, WithMetrics(m))
	running, release := make(chan struct{}), make(chan struct{})
	c.enqueue(task{name: "blocker", run: func(context.Context) error {
		close(running)
		<-release
		return nil
	}})
	<-running // the task goroutine holds it: the queue is empty
	nop := func(context.Context) error { return nil }
	for i := range cap(c.tasks) {
		c.enqueue(task{name: fmt.Sprintf("queued-%d", i), run: nop})
	}
	c.enqueue(task{name: "queued-0", run: nop}) // queued already
	c.enqueue(task{name: "event-poll", run: nop})
	c.enqueue(task{name: "time-sync", run: nop})
	close(release)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Equal(m.dropped, []string{"event-poll", "time-sync"}) {
		t.Fatalf("OnTaskDropped(%v), want event-poll and time-sync", m.dropped)
	}
}

// callbackMetrics is a dnp3.ClientMetrics whose OnTaskDropped calls into
// the client, as an application's hook may: it queues a task. The call is
// made on another goroutine and waited for for at most 5 s, so that a hook
// called under the client's task lock is reported instead of blocking the
// test; returned tells whether the call returned.
type callbackMetrics struct {
	dnp3.NopMetrics
	c        atomic.Pointer[Client]
	returned chan bool
}

func (m *callbackMetrics) OnTaskDropped(string) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.c.Load().enqueue(task{name: "queued-0", run: func(context.Context) error { return nil }})
	}()
	select {
	case <-done:
		m.returned <- true
	case <-time.After(5 * time.Second):
		m.returned <- false
	}
}

func (*callbackMetrics) OnLateResponse(net.Addr, app.FunctionCode) {}

// TestClientMetricsTaskDroppedCallsBack: OnTaskDropped is called after the
// client released its task lock, so a hook that calls into the client, here
// to queue a task, returns.
func TestClientMetricsTaskDroppedCallsBack(t *testing.T) {
	m := &callbackMetrics{returned: make(chan bool, 8)}
	c, _ := pipeClient(t, nil, WithMetrics(m))
	m.c.Store(c)
	running, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	c.enqueue(task{name: "blocker", run: func(ctx context.Context) error {
		close(running)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}})
	<-running // the task goroutine holds it: the queue is empty
	nop := func(context.Context) error { return nil }
	for i := range cap(c.tasks) {
		c.enqueue(task{name: fmt.Sprintf("queued-%d", i), run: nop})
	}
	c.enqueue(task{name: "event-poll", run: nop}) // dropped: the hook runs
	select {
	case ok := <-m.returned:
		if !ok {
			t.Fatal("a call into the client from OnTaskDropped did not return: the hook ran under the task lock")
		}
	default:
		t.Fatal("OnTaskDropped was not called")
	}
}

// TestClientMetricsLateResponse: a response no request waits for (Table
// 6-2 row 1), the fragments a request discards while it awaits its
// response (rows 3 and 5) and those it was given but did not take before
// it ended are reported to OnLateResponse, with the channel's address; the
// response taken is not.
func TestClientMetricsLateResponse(t *testing.T) {
	t.Run("no request waits", func(t *testing.T) {
		m := newDroppedMetrics()
		timedOut := make(chan struct{})
		first := true
		o := newSpecOutstation(t, func(req specFrag) [][]byte {
			if first { // answered once the master gave up
				first = false
				select {
				case <-timedOut:
				case <-time.After(5 * time.Second):
				}
			}
			return [][]byte{frag(ctl(true, true, false, req.f.Control.Seq), app.FuncResponse, 0, event0)}
		})
		c := specDial(t, o, append(specQuiet, WithResponseTimeout(50*time.Millisecond), WithMetrics(m))...)
		if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); !errors.Is(err, dnp3.ErrTimeout) {
			t.Fatalf("unanswered read: %v", err)
		}
		close(timedOut)
		if late := m.waitLate(t, 1); late[0] != app.FuncResponse {
			t.Fatalf("OnLateResponse(%v)", late)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.remotes[0] == nil || m.remotes[0].String() != c.remoteAddr().String() {
			t.Errorf("late response reported from %v, want %v", m.remotes[0], c.remoteAddr())
		}
	})
	t.Run("awaiting the first fragment", func(t *testing.T) {
		m := newDroppedMetrics()
		o := newSpecOutstation(t, func(req specFrag) [][]byte {
			n := req.f.Control.Seq
			return [][]byte{
				frag(ctl(false, true, true, n), app.FuncResponse, 0, event1),   // row 3
				frag(ctl(true, true, true, n+3), app.FuncResponse, 0, event1),  // row 5
				frag(ctl(true, false, true, n-1), app.FuncResponse, 0, event1), // row 5
				frag(ctl(true, true, true, n), app.FuncResponse, 0, event0),    // taken
			}
		})
		c := specDial(t, o, append(specQuiet, WithMetrics(m))...)
		if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); err != nil {
			t.Fatal(err)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.late) != 3 {
			t.Fatalf("%d late responses reported, want the 3 discarded", len(m.late))
		}
	})
	t.Run("secure authentication", func(t *testing.T) {
		m := newDroppedMetrics()
		c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithMetrics(m))
		c.onStrayAuth(nil, &app.Fragment{Control: app.SingleControl(2), Function: app.FuncResponse}, nil)
		c.onStrayAuth(nil, authResponse(2), nil) // no objects: discarded
		c.onStrayAuth(nil, authResponse(2, authErrorHeader(app.AuthErrAuthenticationFailed)), nil)
		if late := m.waitLate(t, 2); !slices.Equal(late, []app.FunctionCode{app.FuncResponse, app.FuncAuthResponse}) {
			t.Fatalf("OnLateResponse(%v), want RESPONSE and AUTH_RESPONSE; an error message is not late", late)
		}
	})
	t.Run("given to a request that ended", func(t *testing.T) {
		// Fragments handed to a request that ended before it took them:
		// abandoned, timed out or canceled.
		m := newDroppedMetrics()
		c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithMetrics(m))
		tr := newTransaction()
		for range 2 {
			if !tr.accept(&app.Fragment{Control: app.SingleControl(3), Function: app.FuncResponse}, nil, time.Time{}) {
				t.Fatal("fragment not taken")
			}
		}
		c.discardUnread(tr)
		if late := m.waitLate(t, 2); len(late) != 2 {
			t.Fatalf("OnLateResponse(%v), want the 2 fragments the request did not take", late)
		}
	})
	t.Run("without ClientMetrics", func(t *testing.T) {
		c := authClient(t, secauth.User{Number: 1, Key: specKey}, WithMetrics(dnp3.NopMetrics{}))
		c.onStrayAuth(nil, authResponse(2), nil)
		if c.cm != nil {
			t.Fatal("metrics without ClientMetrics are taken as ClientMetrics")
		}
	})
}

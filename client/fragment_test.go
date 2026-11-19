// SPDX-License-Identifier: MIT

package client

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// fragRecorder is a Handler and a FragmentHandler: it records, in order, each
// fragment it is given whole ("F") and each call with measurements ("M").
type fragRecorder struct {
	mu     sync.Mutex
	calls  []string
	frags  []*app.Fragment
	infos  []ResponseInfo
	signal chan struct{}
}

func (r *fragRecorder) HandleFragment(info ResponseInfo, f *app.Fragment) {
	if !info.Unsolicited {
		return
	}
	r.mu.Lock()
	r.calls = append(r.calls, "F")
	r.frags = append(r.frags, f)
	r.infos = append(r.infos, info)
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

func (r *fragRecorder) HandleMeasurements(info ResponseInfo, _ []Measurement) {
	if !info.Unsolicited {
		return
	}
	r.mu.Lock()
	r.calls = append(r.calls, "M")
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// wait waits for n calls, of either method.
func (r *fragRecorder) wait(t *testing.T, n int) ([]string, []*app.Fragment, []ResponseInfo) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		r.mu.Lock()
		if len(r.calls) >= n {
			defer r.mu.Unlock()
			return slices.Clone(r.calls), slices.Clone(r.frags), slices.Clone(r.infos)
		}
		r.mu.Unlock()
		select {
		case <-r.signal:
		case <-deadline:
			t.Fatalf("timed out waiting for %d calls", n)
		}
	}
}

// TestFragmentHandler: a Handler that is also a FragmentHandler gets every
// fragment whole, before its measurements: also a null response, which
// carries only its internal indications, and a fragment of virtual
// terminal event data (g113), which has no measurement.
func TestFragmentHandler(t *testing.T) {
	o := newSpecOutstation(t, func(specFrag) [][]byte { return nil })
	rec := &fragRecorder{signal: make(chan struct{}, 1)}
	specDial(t, o, append(specQuiet, WithHandler(rec))...)
	vt := []byte{113, 2, 0x17, 1, 2, 'h', 'i'} // g113v2, one object at port 2: "hi"
	o.push(t, uns(true, true, true, 1, app.IINDeviceTrouble))
	o.push(t, uns(true, true, true, 2, 0, vt))
	o.push(t, uns(true, true, true, 3, 0, event0))
	calls, frags, infos := rec.wait(t, 4)
	if want := []string{"F", "F", "F", "M"}; !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	if !infos[0].IIN.Has(app.IINDeviceTrouble) || len(frags[0].Headers) != 0 {
		t.Fatalf("null response: %+v %v", infos[0], frags[0])
	}
	h := frags[1].Headers
	if len(h) != 1 || h[0].GV.Group() != 113 || len(h[0].Objects) != 1 || h[0].Objects[0].Index != 2 {
		t.Fatalf("virtual terminal fragment: %v", frags[1])
	}
	if s, ok := h[0].Objects[0].Value.(app.OctetString); !ok || string(s.Data) != "hi" {
		t.Fatalf("virtual terminal data: %+v", h[0].Objects[0].Value)
	}
	if infos[2].Seq != 3 || !infos[2].FIR || !infos[2].FIN {
		t.Fatalf("info of the third fragment: %+v", infos[2])
	}
}

// panicky is a FragmentHandler whose first HandleFragment panics.
type panicky struct {
	frags, measurements atomic.Int64
}

func (p *panicky) HandleFragment(ResponseInfo, *app.Fragment) {
	if p.frags.Add(1) == 1 {
		panic("fragment handler of the application")
	}
}

func (p *panicky) HandleMeasurements(ResponseInfo, []Measurement) { p.measurements.Add(1) }

// TestFragmentHandlerPanicRecovered: a panic in HandleFragment is recovered
// like one in HandleMeasurements: that fragment's measurements are lost, the
// next fragment is delivered whole and with its measurements.
func TestFragmentHandlerPanicRecovered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := &panicky{}
		c, o := pipeClient(t, nil, WithHandler(h))
		o.send(unsolicitedNo(0, 0))
		o.send(unsolicitedNo(1, 0))
		synctest.Wait()
		if f, m := h.frags.Load(), h.measurements.Load(); f != 2 || m != 1 {
			t.Errorf("%d fragments and %d measurement calls, want 2 and 1", f, m)
		}
		if _, err := c.Read(t.Context(), app.AllObjects(app.G1V0)); err != nil {
			t.Fatalf("READ after the panic: %v", err)
		}
	})
}

// measurementsOnly is a Handler without HandleFragment.
type measurementsOnly struct{ calls atomic.Int64 }

func (m *measurementsOnly) HandleMeasurements(ResponseInfo, []Measurement) { m.calls.Add(1) }

// TestHandlerWithoutFragmentHandler: a Handler that is not a
// FragmentHandler is called as before, only for fragments with
// measurements: not for a null response.
func TestHandlerWithoutFragmentHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := &measurementsOnly{}
		_, o := pipeClient(t, nil, WithHandler(h))
		null := unsolicitedNo(0, app.IINDeviceTrouble)
		null.Headers = nil
		o.send(null)
		o.send(unsolicitedNo(1, 0))
		synctest.Wait()
		if n := h.calls.Load(); n != 1 {
			t.Errorf("HandleMeasurements called %d times, want 1", n)
		}
	})
}

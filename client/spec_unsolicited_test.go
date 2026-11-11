// SPDX-License-Identifier: MIT

package client

import (
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// measRecorder is a Handler that keeps the measurements of unsolicited
// responses.
type measRecorder struct {
	mu     sync.Mutex
	ms     []Measurement
	signal chan struct{}
}

func newMeasRecorder() *measRecorder { return &measRecorder{signal: make(chan struct{}, 1)} }

func (r *measRecorder) HandleMeasurements(info ResponseInfo, ms []Measurement) {
	if !info.Unsolicited {
		return
	}
	r.mu.Lock()
	r.ms = append(r.ms, ms...)
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

func (r *measRecorder) got() []Measurement {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ms)
}

// wait waits for n unsolicited measurements.
func (r *measRecorder) wait(t *testing.T, n int) []Measurement {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if ms := r.got(); len(ms) >= n {
			return ms
		}
		select {
		case <-r.signal:
		case <-deadline:
			t.Fatalf("timed out waiting for %d unsolicited measurements; have %d", n, len(r.got()))
		}
	}
}

// uns encodes an unsolicited response.
func uns(fir, fin, con bool, seq uint8, iin app.IIN, objects ...[]byte) []byte {
	return frag(app.Control{FIR: fir, FIN: fin, CON: con, UNS: true, Seq: seq}, app.FuncUnsolicitedResponse, iin, objects...)
}

// TestSpec4_6_6_Rule6_ConfirmedDuringRequest: IEEE 1815-2012 clause 4.6.6
// Rule 6 (printed page 92): "A master shall return confirmations to
// unsolicited responses immediately upon receipt, regardless of where it
// is in its polling sequence, even if it is waiting for a response to a
// solicited request"; the confirmation carries the unsolicited
// response's SEQ and UNS bit (clause 4.3 Rule 18, p. 39), and the
// solicited exchange still completes.
func TestSpec4_6_6_Rule6_ConfirmedDuringRequest(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		return [][]byte{uns(true, true, true, 9, 0, event1), frag(ctl(true, true, false, req.f.Control.Seq), app.FuncResponse, 0, event0)}
	})
	rec := newMeasRecorder()
	c := specDial(t, o, append(quiet, WithHandler(rec))...)
	res, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
	if err != nil || len(res.Fragments) != 1 || res.Measurements()[0].Index != 0 {
		t.Fatalf("read with an unsolicited response in between: %v %v", res, err)
	}
	if cs := o.waitConfirms(t, 1); len(cs) != 1 || cs[0].Seq != 9 || !cs[0].UNS {
		t.Fatalf("confirmations %v", cs)
	}
	if ms := rec.wait(t, 1); ms[0].Index != 1 {
		t.Fatalf("unsolicited measurements %v", ms)
	}
}

// TestSpec4_6_6_Rule4_FIRFINIgnored: clause 4.6.6 Rule 4 (p. 91): "A master
// shall ignore the state of the FIR and FIN bits in the application
// control octet of a received unsolicited response".
func TestSpec4_6_6_Rule4_FIRFINIgnored(t *testing.T) {
	o := newSpecOutstation(t, func(specFrag) [][]byte { return nil })
	rec := newMeasRecorder()
	specDial(t, o, append(quiet, WithHandler(rec))...)
	o.push(t, uns(false, false, true, 3, 0, event0))
	o.push(t, uns(true, false, true, 4, 0, event1))
	if cs := o.waitConfirms(t, 2); cs[0].Seq != 3 || cs[1].Seq != 4 || !cs[0].UNS || !cs[1].UNS {
		t.Fatalf("confirmations %v", cs)
	}
	if ms := rec.wait(t, 2); ms[0].Index != 0 || ms[1].Index != 1 {
		t.Fatalf("measurements %v", ms)
	}
}

// TestSpec4_6_6_Rule2_StaticData: clause 4.6.6 Rule 2 (p. 91): "Masters
// shall parse static data in unsolicited responses." It reaches the
// Handler as static (Event false).
func TestSpec4_6_6_Rule2_StaticData(t *testing.T) {
	o := newSpecOutstation(t, func(specFrag) [][]byte { return nil })
	rec := newMeasRecorder()
	specDial(t, o, append(quiet, WithHandler(rec))...)
	o.push(t, uns(true, true, false, 0, 0, []byte{0x01, 0x02, 0x00, 0x05, 0x05, 0x81})) // g1v2 index 5
	ms := rec.wait(t, 1)
	if ms[0].GV != app.G1V2 || ms[0].Index != 5 || ms[0].Event {
		t.Fatalf("measurement %+v", ms[0])
	}
	if b, ok := ms[0].Value.(app.Binary); !ok || !b.Value || b.Flags != app.FlagOnline {
		t.Fatalf("value %+v", ms[0].Value)
	}
}

// TestSpec4_6_6_Rule7_Repeats: clause 4.6.6 Rule 7 (p. 92): "the master
// shall compare all of the octets following the IIN octets" of an
// unsolicited response with the SEQ of the previous one, and process it
// only when they differ; a repeat is confirmed again. Table 6-3 (p. 169)
// row 5: a fragment with the same SEQ and other octets is processed and
// followed by an integrity poll; row 8: one that reports a restart
// (IIN1.7) is always processed (MASTER-12).
func TestSpec4_6_6_Rule7_Repeats(t *testing.T) {
	for _, tc := range []struct {
		name      string
		second    []byte
		processed bool // the second one
		integrity bool
	}{
		{"identical repeat", uns(true, true, true, 5, 0, event0), false, false},
		{"other IIN, same objects", uns(true, true, true, 5, app.IINClass1Events|app.IINDeviceTrouble, event0), false, false},
		{"same SEQ, other objects", uns(true, true, true, 5, 0, event1), true, true},
		{"repeat with IIN1.7", uns(true, true, true, 5, app.IINDeviceRestart, event0), true, true},
		{"next SEQ", uns(true, true, true, 6, 0, event0), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
			rec := newMeasRecorder()
			specDial(t, o, WithHandler(rec), WithStartup(Startup{}), WithAutoEventPoll(false),
				WithTimeSync(TimeSyncNone), WithAutoClearRestart(false), WithAutoIntegrity(true))
			o.push(t, uns(true, true, true, 5, 0, event0))
			rec.wait(t, 1)
			o.push(t, tc.second)
			// Both are confirmed, with their SEQ.
			if cs := o.waitConfirms(t, 2); cs[1].Seq != tc.second[0]&0x0F || !cs[1].UNS {
				t.Fatalf("confirmations %v", cs)
			}
			if tc.integrity {
				o.waitLog(t, "an integrity poll", func([]specFrag) bool {
					return slices.Contains(o.requests(), app.FuncRead)
				})
			}
			// A third one, processed in every case, shows that the second
			// was handled.
			o.push(t, uns(true, true, true, 12, 0, event1))
			want := 2
			if tc.processed {
				want = 3
			}
			o.waitConfirms(t, 3)
			if ms := rec.wait(t, want); len(ms) != want {
				t.Fatalf("%d measurements processed, want %d", len(ms), want)
			}
			if !tc.integrity && slices.Contains(o.requests(), app.FuncRead) {
				t.Fatalf("requests %v", o.requests())
			}
		})
	}
}

// TestSpec4_2_2_4_4_UNSContradiction: clause 4.2.2.4.4 (p. 22): the UNS bit
// is set in unsolicited responses and their confirmations only; it selects
// the solicited or the unsolicited reception table (clauses 6.3 and 6.5,
// pp. 163 and 167), and a confirmation repeats it (clause 4.3 Rule 18,
// p. 39). A fragment whose UNS bit contradicts its function code is
// neither processed nor confirmed (MASTER-14).
func TestSpec4_2_2_4_4_UNSContradiction(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		n := req.f.Control.Seq
		return [][]byte{
			frag(app.Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: n}, app.FuncResponse, 0, event1),
			frag(ctl(true, true, true, n), app.FuncResponse, 0, event0),
		}
	})
	rec := newMeasRecorder()
	c := specDial(t, o, append(quiet, WithHandler(rec))...)
	// An unsolicited response with UNS 0.
	o.push(t, frag(ctl(true, true, true, 7), app.FuncUnsolicitedResponse, 0, event1))
	res, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
	if err != nil || len(res.Fragments) != 1 || res.Measurements()[0].Index != 0 {
		t.Fatalf("read: %v %v", res, err)
	}
	cs := o.waitConfirms(t, 1)
	if len(cs) != 1 || cs[0].UNS || cs[0].Seq != res.Fragments[0].Control.Seq {
		t.Fatalf("confirmations %v", cs)
	}
	if ms := rec.got(); len(ms) != 0 {
		t.Fatalf("unsolicited measurements %v", ms)
	}
}

// holdMetrics holds the client's handling of the first unsolicited
// response until release is closed, and reports when the application
// starts a READ.
type holdMetrics struct {
	dnp3.NopMetrics
	once, read sync.Once
	held       chan struct{}
	release    chan struct{}
	reading    chan struct{}
}

func (m *holdMetrics) OnFragmentReceived(_ net.Addr, f *app.Fragment, _ int) {
	if f.Function == app.FuncUnsolicitedResponse {
		m.once.Do(func() {
			close(m.held)
			<-m.release
		})
	}
}

func (m *holdMetrics) OnRequest(_ net.Addr, _ uint16, fc app.FunctionCode) {
	if fc == app.FuncRead {
		m.read.Do(func() { close(m.reading) })
	}
}

func (*holdMetrics) OnRequestDone(net.Addr, uint16, app.FunctionCode, time.Duration, error) {}
func (*holdMetrics) OnRetry(net.Addr, uint16, app.FunctionCode, int, error)                 {}

// TestSpec4_3_Rule13_UnsolicitedConfirmBeforeRequest: clause 4.3 Rule 13
// (p. 39): a master that receives a fragment with CON "shall respond with
// an Application Layer confirm message before sending any other request
// message to that outstation", and clause 4.6.6 Rule 6 (p. 92) asks for
// the confirmation of an unsolicited response at once. A request the
// application makes while the client handles an unsolicited response
// waits for its confirmation (MASTER-18).
func TestSpec4_3_Rule13_UnsolicitedConfirmBeforeRequest(t *testing.T) {
	m := &holdMetrics{held: make(chan struct{}), release: make(chan struct{}), reading: make(chan struct{})}
	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
	c := specDial(t, o, append(quiet, WithMetrics(m))...)
	o.push(t, uns(true, true, true, 2, 0, event0))
	<-m.held // the client has the unsolicited response, not yet confirmed
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
		done <- err
	}()
	<-m.reading
	close(m.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sent := o.waitLog(t, "the confirmation and the read", func(sent []specFrag) bool { return len(sent) >= 2 })
	if f := sent[0].f; f.Function != app.FuncConfirm || !f.Control.UNS || f.Control.Seq != 2 {
		t.Fatalf("first fragment from the master: %s, then %s", f, sent[1].f)
	}
	if sent[1].f.Function != app.FuncRead {
		t.Fatalf("second fragment from the master: %s", sent[1].f)
	}
}

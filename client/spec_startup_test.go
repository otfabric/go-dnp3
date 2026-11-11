// SPDX-License-Identifier: MIT

package client

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// station is the state of a scripted outstation: whether it reports a
// restart (IIN1.7) and NEED_TIME (IIN1.4), which it reports until the
// master clears them or synchronizes the time, and the requests it
// rejects (with the given IIN) or leaves unanswered.
type station struct {
	mu       sync.Mutex
	restart  bool
	needTime bool
	refuse   map[app.FunctionCode]app.IIN
	silent   map[string]bool // describe() of the requests left unanswered
}

func (s *station) iin() app.IIN {
	var iin app.IIN
	if s.restart {
		iin |= app.IINDeviceRestart
	}
	if s.needTime {
		iin |= app.IINNeedTime
	}
	return iin
}

func (s *station) answer(req specFrag) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.silent[describe(req.f)] {
		return nil
	}
	if bad, ok := s.refuse[req.f.Function]; ok {
		return [][]byte{empty(req, s.iin()|bad)}
	}
	if req.f.Function == app.FuncWrite {
		for _, h := range req.f.Headers {
			switch h.GV {
			case app.G80V1:
				for _, o := range h.Objects {
					switch o.Index {
					case 7:
						s.restart = false
					case 4:
						s.needTime = false
					}
				}
			case app.G50V1, app.G50V3:
				s.needTime = false
			default:
			}
		}
	}
	if req.f.Function == app.FuncDelayMeasure {
		return [][]byte{delayResponse(req.f.Control.Seq, s.iin(), 0)}
	}
	return [][]byte{empty(req, s.iin())}
}

// describe names a request: its function code and, for a WRITE, the
// object written.
func describe(f *app.Fragment) string {
	if f.Function == app.FuncWrite && len(f.Headers) > 0 {
		return "WRITE " + f.Headers[0].GV.String()
	}
	return f.Function.String()
}

// described returns the requests the master sent, described.
func described(sent []specFrag) []string {
	var out []string
	for _, f := range sent {
		if f.f.Function != app.FuncConfirm {
			out = append(out, describe(f.f))
		}
	}
	return out
}

// waitRequests waits until the master sent n requests and returns them,
// described.
func (o *specOutstation) waitRequests(t *testing.T, n int) []string {
	t.Helper()
	return described(o.waitLog(t, "requests", func(sent []specFrag) bool { return len(described(sent)) >= n }))
}

// TestSpec5_1_1_2_Rule1_DefaultIntegrityPoll: IEEE 1815-2012 clause 5.1.1.2
// Rule 1 (printed pages 102-103): "When the master restarts, the master
// shall perform the following actions for each outstation in the order
// indicated below: [...] 4) Perform an integrity poll to read all
// outstation data". By default the client does it before Connect returns
// (MASTER-6); a startup that gets no response fails Connect.
// WithStartup(Startup{}) runs nothing.
func TestSpec5_1_1_2_Rule1_DefaultIntegrityPoll(t *testing.T) {
	s := &station{}
	o := newSpecOutstation(t, s.answer)
	specDial(t, o)
	sent := o.sent() // Connect returned: the poll is done
	if len(sent) == 0 || sent[0].f.Function != app.FuncRead {
		t.Fatalf("requests %v", o.requests())
	}
	var gvs []app.GroupVariation
	for _, h := range sent[0].f.Headers {
		gvs = append(gvs, h.GV)
	}
	if !slices.Equal(gvs, []app.GroupVariation{app.G60V2, app.G60V3, app.G60V4, app.G60V1}) {
		t.Fatalf("integrity poll of %v", gvs)
	}

	p := newSpecOutstation(t, s.answer)
	specDial(t, p, WithStartup(Startup{}))
	p.none(t, 100*time.Millisecond)

	q := newSpecOutstation(t, func(specFrag) [][]byte { return nil })
	if _, err := Dial(testCtx(t), q.addr, WithResponseTimeout(100*time.Millisecond)); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("startup without a response: %v", err)
	}
}

// TestSpec5_1_1_2_Rule1_StartupOrder: clause 5.1.1.2 Rule 1 (pp. 102-103):
// "2) If the master is configured to use unsolicited reporting with the
// outstation, the master shall issue a request to disable unsolicited
// reporting [...] 3) [optional steps, among them] Perform time
// synchronization [...] 4) Perform an integrity poll [...] 5) [...] the
// master shall issue a request to enable unsolicited reporting". Configured
// classes to enable bring the earlier steps with them. A restart the
// outstation reports on the way (IIN1.7) is cleared before the other steps
// (clause 5.1.1.1.2 Rule 2, p. 102) and once only (MASTER-3).
func TestSpec5_1_1_2_Rule1_StartupOrder(t *testing.T) {
	s := &station{restart: true, needTime: true}
	o := newSpecOutstation(t, s.answer)
	specDial(t, o, WithStartup(Startup{EnableUnsolicited: []int{1, 2}}))
	want := []string{"DISABLE_UNSOLICITED", "WRITE g80v1", "RECORD_CURRENT_TIME", "WRITE g50v3", "READ", "ENABLE_UNSOLICITED"}
	if got := described(o.sent()); !slices.Equal(got, want) {
		t.Fatalf("startup %v, want %v", got, want)
	}
	sent := o.sent()
	enable := sent[len(sent)-1].f
	if len(enable.Headers) != 2 || enable.Headers[0].GV != app.G60V2 || enable.Headers[1].GV != app.G60V3 {
		t.Fatalf("ENABLE_UNSOLICITED of %v", enable.Headers)
	}
	disable := sent[0].f
	if len(disable.Headers) != 3 || disable.Headers[0].GV != app.G60V2 || disable.Headers[2].GV != app.G60V4 {
		t.Fatalf("DISABLE_UNSOLICITED of %v", disable.Headers)
	}
	// The restart procedure and the time synchronization queued on the
	// way find their steps done.
	o.none(t, 200*time.Millisecond)
}

// TestSpec5_1_1_1_2_Rule2_RestartProcedure: clause 5.1.1.1.2 Rule 2
// (p. 102): "Upon detection of the IIN1.7 [DEVICE_RESTART] bit in a
// response from an outstation, the master shall perform the following
// actions for that outstation in the order indicated below": the session
// keys, clearing IIN1.7, optional steps such as time synchronization, an
// integrity poll and, when the master uses unsolicited reporting, enabling
// it again. Table 6-3 rows 4 and 8 (p. 169) ask the same of an unsolicited
// response that reports a restart (MASTER-2). A step the outstation
// rejects does not end the procedure; a step without a response does.
func TestSpec5_1_1_1_2_Rule2_RestartProcedure(t *testing.T) {
	startup := []string{"DISABLE_UNSOLICITED", "READ", "ENABLE_UNSOLICITED"}
	for _, tc := range []struct {
		name     string
		needTime bool
		unsol    bool
		refuse   map[app.FunctionCode]app.IIN
		silent   string
		want     []string
	}{
		{"unsolicited response", false, true, nil, "",
			[]string{"WRITE g80v1", "READ", "ENABLE_UNSOLICITED"}},
		{"solicited response", false, false, nil, "",
			[]string{"WRITE g80v1", "READ", "ENABLE_UNSOLICITED"}},
		{"with NEED_TIME", true, true, nil, "",
			[]string{"WRITE g80v1", "RECORD_CURRENT_TIME", "WRITE g50v3", "READ", "ENABLE_UNSOLICITED"}},
		{"integrity poll rejected", false, true, map[app.FunctionCode]app.IIN{app.FuncRead: app.IINObjectUnknown}, "",
			[]string{"WRITE g80v1", "READ", "ENABLE_UNSOLICITED"}},
		{"clear restart unanswered", false, true, nil, "WRITE g80v1",
			[]string{"WRITE g80v1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &station{}
			o := newSpecOutstation(t, s.answer)
			c := specDial(t, o, WithStartup(Startup{EnableUnsolicited: []int{1, 2}}), WithResponseTimeout(200*time.Millisecond))
			if got := described(o.sent()); !slices.Equal(got, startup) {
				t.Fatalf("startup %v", got)
			}
			s.mu.Lock()
			s.restart, s.needTime, s.refuse = true, tc.needTime, tc.refuse
			s.silent = map[string]bool{tc.silent: true}
			s.mu.Unlock()
			n := len(startup)
			if tc.unsol {
				// The null unsolicited response of a restarted outstation
				// (clause 5.1.1.1.1 Rule 2, p. 101).
				o.push(t, uns(true, true, true, 0, s.iin()))
			} else {
				if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); err != nil && tc.refuse == nil {
					t.Fatal(err)
				}
				n++
			}
			got := o.waitRequests(t, n+len(tc.want))[n:]
			if !slices.Equal(got, tc.want) {
				t.Fatalf("after the restart %v, want %v", got, tc.want)
			}
			o.none(t, 300*time.Millisecond)
		})
	}
}

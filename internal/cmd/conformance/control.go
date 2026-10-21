// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// request is one call of the dnp3c integration plugin. Op is the name of
// the IntegrationPlugin method; the other fields are its arguments.
type request struct {
	Op       string  `json:"op"`
	Kind     string  `json:"kind,omitempty"`
	Class    int     `json:"class,omitempty"` // 1..3, 0 for all three
	N        int     `json:"n,omitempty"`
	Index    int     `json:"index,omitempty"`
	Indices  []int   `json:"indices,omitempty"`
	Value    float64 `json:"value,omitempty"`
	Flag     int     `json:"flag,omitempty"`
	Bool     bool    `json:"bool,omitempty"`
	Limit    *int    `json:"limit,omitempty"`
	Expect   string  `json:"expect,omitempty"`
	Points   []point `json:"points,omitempty"`
	Points2  []point `json:"points2,omitempty"`
	Attrs    []attr  `json:"attrs,omitempty"`
	Expected float64 `json:"expected,omitempty"`
	Actual   float64 `json:"actual,omitempty"`
	SentMs   int64   `json:"sentMs,omitempty"`
	EventMs  int64   `json:"eventMs,omitempty"`
	DelayMs  int64   `json:"delayMs,omitempty"`
}

// point is a point dnp3c parsed from a response.
type point struct {
	Kind     string   `json:"kind"`
	Index    int      `json:"i"`
	Value    float64  `json:"v"`
	Flags    *int     `json:"f,omitempty"`
	Time     *int64   `json:"t,omitempty"`
	Relative bool     `json:"rel,omitempty"`
	Event    bool     `json:"event,omitempty"`
	Extra    []string `json:"x,omitempty"`
}

func (p point) String() string {
	s := fmt.Sprintf("%s %d = %v", p.Kind, p.Index, p.Value)
	if p.Time != nil {
		s += fmt.Sprintf(" @%d", *p.Time)
	}
	return s
}

// attr is a device attribute of set 0 dnp3c read.
type attr struct {
	Variation int    `json:"v"`
	Type      string `json:"type"`
	Text      string `json:"s"`
}

type reply struct {
	Log   []string `json:"log,omitempty"`
	Error string   `json:"error,omitempty"`
	Index int      `json:"index,omitempty"`
	Flags *int     `json:"flags,omitempty"`
}

func (d *device) handle(r *request) (rep reply) {
	if r.Op == "startProcedure" {
		if err := d.reset(); err != nil {
			rep.Error = err.Error()
		}
		return rep
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	logf := func(format string, args ...any) { rep.Log = append(rep.Log, fmt.Sprintf(format, args...)) }
	if err := d.do(r, &rep, logf); err != nil {
		rep.Error = err.Error()
	}
	return rep
}

func (d *device) do(r *request, rep *reply, logf func(string, ...any)) error {
	switch r.Op {
	case "endProcedure":
		return nil
	case "cyclePower":
		logf("restarted the outstation")
		return d.restartLocked()

	case "setLinkLayerConfirm":
		d.pending.linkConfirm = r.Bool
	case "setSelfAddressSupport":
		d.pending.selfAddress = r.Bool
	case "enableUnsolicitedResponse":
		d.pending.unsolicited = r.Bool
	case "setUnsolicitedResponseTimeout":
		d.pending.confirm = time.Duration(r.N) * time.Millisecond
	case "setMaxUnsolicitedRetries":
		d.pending.unsolRetries = -1 // until confirmed
		if r.Limit != nil {
			d.pending.unsolRetries = *r.Limit
		}
	case "setMasterAddress":
		d.pending.master = link.Address(r.N)
	case "setMaxFragmentSize":
		d.pending.maxFragment = r.N
	case "setColdRestartSupport":
		d.pending.coldRestart = r.Bool
		d.cfg.coldRestart = r.Bool

	case "checkOperate":
		i := slices.Index(d.ops, operation{r.Kind, r.Index})
		if i < 0 {
			return fmt.Errorf("%s %d did not operate (operations: %v)", r.Kind, r.Index, d.ops)
		}
		d.ops = slices.Delete(d.ops, i, i+1)
		logf("%s %d operated", r.Kind, r.Index)
	case "checkNotOperate":
		for _, o := range d.ops {
			if o.kind == r.Kind {
				return fmt.Errorf("%s %d operated", o.kind, o.index)
			}
		}
		logf("no %s operated", r.Kind)

	case "generateInputChanges":
		n := points
		if r.Kind != kindCounter {
			n = 3
		}
		return d.generate(logf, d.changes(r.Kind, n))
	case "generateExactInputEvents":
		return d.generate(logf, d.changes(r.Kind, r.N))
	case "generateClassEvents":
		return d.generate(logf, d.classChanges(r.Class, 3))
	case "generateExactClassEvents":
		return d.generate(logf, d.classChanges(r.Class, r.N))
	case "generatePattern":
		var cs []event
		for i := range points {
			var x float64
			switch r.Kind {
			case kindBinary:
				x = float64(i % 2)
			case kindDoubleBit:
				x = float64(1 + i%2)
			default:
				x = float64(10 * (i + 1))
			}
			cs = append(cs, event{kind: r.Kind, index: i, value: x})
		}
		return d.generate(logf, cs)
	case "generateUnsolicitedEvents":
		return d.generate(logf, d.changes(kindBinary, 1))
	case "generateTimeEvent":
		cs := d.changes(kindBinary, 1)
		if err := d.generate(logf, cs); err != nil {
			return err
		}
		ev := d.batches[len(d.batches)-1][0]
		d.timeEv = &ev
	case "generateMultiFragmentResponse":
		var cs []event
		for _, k := range kinds {
			if classes[k] != 0 {
				cs = append(cs, d.changes(k, 60)...)
			}
		}
		return d.generate(logf, cs)
	case "generateExactFrozenCounterEvents":
		return d.generate(logf, d.changes(kindFrozenCounter, r.N))
	case "generateExactSmallAnalogInputEvents":
		return d.generate(logf, d.changes(kindAnalog, r.N))
	case "generateEventOn":
		return d.generate(logf, []event{{kind: r.Kind, index: r.Index, value: d.next(r.Kind, r.Index)}})
	case "setAnalogInput":
		return d.generate(logf, []event{{kind: kindAnalog, index: r.Index, value: r.Value}})
	case "changeBinaryOutputState":
		return d.generate(logf, []event{{kind: kindBinaryOutput, index: r.Index, value: d.next(kindBinaryOutput, r.Index)}})
	case "setAnalogOutputValue":
		return d.generate(logf, []event{{kind: kindAnalogOutput, index: r.Index, value: r.Value}})
	case "changeOutputFlag":
		_, f := valueFlags(d.values[r.Kind][r.Index])
		return d.setFlags(r.Kind, r.Index, f^app.Flags(1<<r.Flag))
	case "setFlagsNormal":
		for i := range count(r.Kind) {
			if err := d.setFlags(r.Kind, i, app.FlagOnline); err != nil {
				return err
			}
		}
	case "setFlagAbnormal":
		if len(r.Indices) == 0 {
			return fmt.Errorf("no %s to set a flag abnormal on", r.Kind)
		}
		i := r.Indices[0]
		if err := d.setFlags(r.Kind, i, 0); err != nil {
			return err
		}
		rep.Index = i
		zero := 0
		rep.Flags = &zero
		logf("cleared ONLINE of %s %d", r.Kind, i)
	case "recordCurrentCounterValues":
		d.recorded = map[string]map[int]float64{}
		for _, k := range []string{kindCounter, kindFrozenCounter} {
			d.recorded[k] = map[int]float64{}
			for i := range count(k) {
				if v, ok := d.current(k, i); ok {
					d.recorded[k][i], _ = valueFlags(v)
				}
			}
		}

	case "uninstall":
		d.removed[r.Kind] = true
		for i := range count(r.Kind) {
			d.srv.Database().Remove(pointTypes[r.Kind], uint32(i))
		}
		logf("removed every %s", r.Kind)
	case "reinstallPoints":
		for k := range d.removed {
			for i := range count(k) {
				_ = d.srv.Database().Add(pointTypes[k], uint32(i), pointConfig(k, i), d.values[k][i])
			}
		}
		d.removed = map[string]bool{}

	case "enableRemoteSupervisoryControl":
		d.global = true
		d.local = map[int]bool{}
		return d.syncLocal()
	case "setGlobalRemoteSupervisoryControl":
		d.global = false
		return d.syncLocal()
	case "setIndividualRemoteSupervisoryControl":
		d.local[r.Index] = true
		return d.syncLocal()

	case "verifyAllStaticCurrentValues", "verifyInputCurrentValues":
		return d.verifyCurrent(r.Points, nil, logf)
	case "verifyRecordedCounterValues":
		if d.recorded == nil {
			return errors.New("no counter values were recorded")
		}
		return d.verifyCurrent(r.Points, d.recorded, logf)
	case "verifyInputEvents":
		return d.verifyEvents(func(e event) bool { return e.kind == r.Kind }, r.Expect, r.Points, logf)
	case "verifyClassEvents":
		return d.verifyEvents(func(e event) bool { return r.Class == 0 || int(classes[e.kind]) == r.Class }, r.Expect, r.Points, logf)
	case "verifyFirstInputEvent":
		return d.verifyFirst(func(e event) bool { return e.kind == r.Kind }, r.Points, logf)
	case "verifyFirstClassEvent":
		return d.verifyFirst(func(e event) bool { return r.Class == 0 || int(classes[e.kind]) == r.Class }, r.Points, logf)
	case "verifyFrozenCounterEvents":
		return d.verifyEvents(func(e event) bool { return e.kind == kindFrozenCounter }, "LatestBatch", r.Points, logf)
	case "checkAnalogOutputTolerance":
		if math.Abs(r.Expected-r.Actual) > 0.001 {
			return fmt.Errorf("analog output reports %v, sent %v", r.Actual, r.Expected)
		}
	case "verifyPolledDataDoNotRepeatUnsolicitedData":
		for _, p := range r.Points2 {
			for _, u := range r.Points {
				if same(p, u) {
					return fmt.Errorf("polled response repeats %v", p)
				}
			}
		}
	case "verifyResponseRetainsEvents":
		for _, p := range r.Points {
			if !slices.ContainsFunc(r.Points2, func(c point) bool { return same(p, c) }) {
				return fmt.Errorf("event %v missing from the later response", p)
			}
		}
	case "verifyDelayMeasurementAccuracy":
		if r.DelayMs < 0 || r.DelayMs > 100 {
			return fmt.Errorf("delay %d ms is out of the profile's 0..100 ms", r.DelayMs)
		}
	case "verifyTimestamp":
		if d.timeEv == nil {
			return errors.New("no time event was generated")
		}
		want := d.timeEv.wall.UnixMilli()
		for _, p := range r.Points {
			if p.Kind == d.timeEv.kind && p.Index == d.timeEv.index && p.Time != nil {
				if diff := *p.Time - want; diff < -100 || diff > 100 {
					return fmt.Errorf("event time %d is %d ms from when it was generated (%d)", *p.Time, diff, want)
				}
				logf("event time within %d ms", *p.Time-want)
				return nil
			}
		}
		return fmt.Errorf("time event %s %d not in the response", d.timeEv.kind, d.timeEv.index)
	case "verifyCommandEventTime":
		if diff := r.EventMs - r.SentMs; diff < -1000 || diff > 1000 {
			return fmt.Errorf("command event time is %d ms from the command", diff)
		}
	case "verifyDeviceAttributes":
		return d.verifyAttributes(r.Attrs, logf)
	default:
		return fmt.Errorf("the conformance outstation does not implement %s", r.Op)
	}
	return nil
}

func (d *device) generate(logf func(string, ...any), cs []event) error {
	if err := d.update(cs); err != nil {
		return err
	}
	var s []string
	for _, c := range cs {
		s = append(s, fmt.Sprintf("%s %d = %v", c.kind, c.index, c.value))
	}
	logf("changed %s", strings.Join(s, ", "))
	return nil
}

// classChanges makes n changes of the points in a class, or n in each
// class for 0.
func (d *device) classChanges(class, n int) []event {
	if class == 0 {
		var cs []event
		for c := 1; c <= 3; c++ {
			cs = append(cs, d.classChanges(c, n)...)
		}
		return cs
	}
	var ks []string
	for _, k := range kinds {
		if c := int(classes[k]); c != 0 && (class == 0 || c == class) {
			ks = append(ks, k)
		}
	}
	var cs []event
	for i := range n {
		k := ks[i%len(ks)]
		cs = append(cs, d.changes(k, 1+i/len(ks))[i/len(ks)])
	}
	return cs
}

// syncLocal clears ONLINE of the binary outputs under local control, and
// reports IIN1.5 (LOCAL_CONTROL) while there are any.
func (d *device) syncLocal() error {
	anyLocal := false
	for i := range points {
		f := app.FlagOnline
		if !d.global || d.local[i] {
			f = 0
			anyLocal = true
		}
		if err := d.setFlags(kindBinaryOutput, i, f); err != nil {
			return err
		}
	}
	d.srv.SetIndications(app.IINLocalControl, anyLocal)
	return nil
}

func near(a, b float64) bool { return math.Abs(a-b) <= 0.001*math.Max(1, math.Abs(b)) }

func same(a, b point) bool {
	return a.Kind == b.Kind && a.Index == b.Index && near(a.Value, b.Value) &&
		(a.Time == nil) == (b.Time == nil) && (a.Time == nil || *a.Time == *b.Time)
}

func counterMatch(kind string, got, want float64) bool {
	if near(got, want) {
		return true
	}
	// a 16-bit variation carries the low 16 bits
	return (kind == kindCounter || kind == kindFrozenCounter) && uint32(got) == uint32(want)&0xFFFF
}

func (d *device) verifyCurrent(ps []point, recorded map[string]map[int]float64, logf func(string, ...any)) error {
	if len(ps) == 0 {
		return errors.New("no points to check")
	}
	for _, p := range ps {
		var want float64
		if recorded != nil {
			w, ok := recorded[p.Kind][p.Index]
			if !ok {
				return fmt.Errorf("no recorded value for %s %d", p.Kind, p.Index)
			}
			want = w
		} else {
			v, ok := d.current(p.Kind, p.Index)
			if !ok {
				return fmt.Errorf("%s %d does not exist", p.Kind, p.Index)
			}
			want, _ = valueFlags(v)
		}
		if !counterMatch(p.Kind, p.Value, want) {
			return fmt.Errorf("%s %d reported %v, the outstation holds %v", p.Kind, p.Index, p.Value, want)
		}
	}
	logf("%d points match the outstation's values", len(ps))
	return nil
}

func filter(evs []event, keep func(event) bool) []event {
	var out []event
	for _, e := range evs {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

func (d *device) verifyFirst(keep func(event) bool, ps []point, logf func(string, ...any)) error {
	if len(d.batches) == 0 {
		return errors.New("no events were generated")
	}
	want := filter(d.batches[len(d.batches)-1], keep)
	if len(want) == 0 || len(ps) != 1 {
		return fmt.Errorf("expected one event of %d generated, got %v", len(want), ps)
	}
	if err := match(ps[0], want[0]); err != nil {
		return err
	}
	d.checked = 1
	logf("first event matches")
	return nil
}

func match(p point, e event) error {
	if p.Kind != e.kind || p.Index != e.index || !counterMatch(p.Kind, p.Value, e.value) {
		return fmt.Errorf("reported %v, generated %s %d = %v", p, e.kind, e.index, e.value)
	}
	return nil
}

// verifyEvents compares the events of a response with those generated.
func (d *device) verifyEvents(keep func(event) bool, expect string, ps []point, logf func(string, ...any)) error {
	if len(d.batches) == 0 {
		if expect == "ReturnedEventsOnly" && len(ps) == 0 {
			logf("no events generated, none reported")
			return nil
		}
		return errors.New("no events were generated")
	}
	latest := filter(d.batches[len(d.batches)-1], keep)
	switch expect {
	case "LatestBatch":
		return matchAll(ps, latest, logf)
	case "RemainingLatestBatch":
		return matchAll(ps, latest[min(d.checked, len(latest)):], logf)
	case "AllGeneratedBatches":
		// every batch whose events are not confirmed yet: the latest k
		var all []event
		for k := len(d.batches) - 1; k >= 0; k-- {
			all = append(filter(d.batches[k], keep), all...)
			if len(all) == len(ps) {
				return matchAll(ps, all, logf)
			}
		}
		return matchAll(ps, all, logf)
	case "CurrentValuesWithOptionalEarlier":
		for _, e := range latest {
			var last *point
			for i := range ps {
				if ps[i].Kind == e.kind && ps[i].Index == e.index {
					last = &ps[i]
				}
			}
			if last == nil {
				return fmt.Errorf("no event for %s %d", e.kind, e.index)
			}
			x, _ := valueFlags(d.values[e.kind][e.index])
			if !counterMatch(e.kind, last.Value, x) {
				return fmt.Errorf("%s %d: last event %v, current value %v", e.kind, e.index, last.Value, x)
			}
		}
		logf("each changed point's last event has its current value")
		return nil
	case "ReturnedEventsOnly":
		for _, p := range ps {
			found := false
			for _, b := range d.batches {
				for _, e := range b {
					if match(p, e) == nil {
						found = true
					}
				}
			}
			if !found {
				return fmt.Errorf("event %v was never generated", p)
			}
		}
		logf("%d events were generated", len(ps))
		return nil
	}
	return fmt.Errorf("unknown expectation %q", expect)
}

// matchAll checks that the response holds exactly the events, in the order
// they occurred within each type for binary and double-bit inputs and for
// each point otherwise, with the gaps between their times.
func matchAll(ps []point, want []event, logf func(string, ...any)) error {
	if len(ps) != len(want) {
		return fmt.Errorf("%d events reported, %d generated: reported %v", len(ps), len(want), ps)
	}
	used := make([]bool, len(want))
	var first *point
	var firstEv event
	for _, p := range ps {
		found := -1
		for j, e := range want {
			if used[j] {
				continue
			}
			if e.kind == p.Kind && (e.index == p.Index || p.Kind == kindBinary || p.Kind == kindDoubleBit) {
				found = j
				break
			}
		}
		if found < 0 {
			return fmt.Errorf("event %v not generated", p)
		}
		if err := match(p, want[found]); err != nil {
			return fmt.Errorf("out of order or wrong value: %w", err)
		}
		used[found] = true
		if p.Time != nil {
			if first == nil {
				first, firstEv = &p, want[found]
			} else {
				got := *p.Time - *first.Time
				exp := int64(want[found].time) - int64(firstEv.time)
				if got-exp > 1 || exp-got > 1 {
					return fmt.Errorf("event %v is %d ms after the first, generated %d ms after", p, got, exp)
				}
			}
		}
	}
	logf("%d events match those generated", len(ps))
	return nil
}

func (d *device) verifyAttributes(as []attr, logf func(string, ...any)) error {
	want := attributes()
	for _, a := range as {
		w, ok := want[uint8(a.Variation)]
		if !ok {
			continue
		}
		if a.Type == "string" && a.Text != string(w.Data) {
			return fmt.Errorf("g0v%d is %q, the outstation has %q", a.Variation, a.Text, w.Data)
		}
	}
	logf("%d attributes checked", len(as))
	return nil
}

// current is a point's value as the outstation holds it: frozen counters
// change when the master freezes them.
func (d *device) current(kind string, index int) (app.Value, bool) {
	if d.removed[kind] {
		return nil, false
	}
	return d.srv.Database().Get(pointTypes[kind], uint32(index))
}

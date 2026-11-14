// SPDX-License-Identifier: MIT

package client

import (
	"runtime/debug"
	"sync"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// Measurement is one point value or event of a response: indexed data of
// a point, sent with its index. Objects without an index that describe the
// device or a procedure, such as the time and date of time synchronization
// (g50v1..g50v3), are not measurements; OBJECTS.md marks the objects that
// are.
type Measurement struct {
	// GV is the object the value was sent as, for example app.G30V5.
	GV app.GroupVariation
	// Index is the point index.
	Index uint32
	// Value is one of the point value types of package app: app.Binary,
	// app.DoubleBitBinary, app.BinaryCommandEvent, app.Counter,
	// app.Analog, app.AnalogDeadband, app.AnalogCommandEvent,
	// app.AbsoluteTime (g50v4, a time and interval), app.BCD,
	// app.UnsignedInteger, app.OctetString or app.SecurityStatistic. A
	// value of a variation without flags reads as ONLINE; see
	// Measurements.
	Value app.Value
	// Event is set for objects of an event group.
	Event bool
}

// ResponseInfo describes the fragment measurements came in.
type ResponseInfo struct {
	// Unsolicited is set for unsolicited responses.
	Unsolicited bool
	// IIN are the internal indications of the fragment.
	IIN app.IIN
	// Seq is the application sequence number.
	Seq uint8
	// FIR and FIN mark the first and the final fragment of a response.
	FIR, FIN bool
}

// Handler receives measurements. It is called for every fragment of every
// response and unsolicited response, in the order they arrived, on a
// goroutine of the client's own: a slow handler does not delay the
// protocol, and a handler may issue requests. A handler that falls far
// behind (64 fragments) holds back what the outstation can push: while
// it does, unsolicited responses are neither processed nor confirmed, so
// that the outstation repeats them, and the client's automatic polls wait.
// A panic in the handler is recovered and logged; the client goes on.
//
// A handler must not call [Client.Close] itself: Close waits for the
// handler to return. Call it from another goroutine (go c.Close()).
type Handler interface {
	HandleMeasurements(info ResponseInfo, ms []Measurement)
}

// HandlerFunc adapts a function to a [Handler].
type HandlerFunc func(info ResponseInfo, ms []Measurement)

// HandleMeasurements calls f.
func (f HandlerFunc) HandleMeasurements(info ResponseInfo, ms []Measurement) { f(info, ms) }

// Measurements returns the measurements of a fragment, in the order of
// its headers.
//
// A value sent in a variation without flags (g1v1, g3v1, g10v1, g20v5 to
// v8, g21v9 to v12, g30v3, g30v4, g31v5 and g31v6) has the flags ONLINE
// and nothing else: IEEE 1815-2012 clause 11.6.5 and NOTE 2 of Table 11-5
// require the master to read such a value as online with no exception
// condition.
func Measurements(f *app.Fragment) []Measurement {
	var out []Measurement
	for _, h := range f.Headers {
		if !isMeasurement(h.GV) {
			continue
		}
		ev := h.GV.IsEvent()
		online := withoutFlags(h.GV)
		for _, o := range h.Objects {
			if o.Value == nil {
				continue
			}
			v := o.Value
			if online {
				v = withOnline(v)
			}
			out = append(out, Measurement{GV: h.GV, Index: o.Index, Value: v, Event: ev})
		}
	}
	return out
}

// withoutFlags reports whether gv is a variation without flags of a group
// that also has variations with flags (IEEE 1815-2012 clause 11.6.5):
// app/catalog.json marks these point variations as without flags.
func withoutFlags(gv app.GroupVariation) bool {
	switch gv {
	case app.G1V1, app.G3V1, app.G10V1,
		app.G20V5, app.G20V6, app.G20V7, app.G20V8,
		app.G21V9, app.G21V10, app.G21V11, app.G21V12,
		app.G30V3, app.G30V4, app.G31V5, app.G31V6:
		return true
	default:
		return false
	}
}

// withOnline returns v with the flags ONLINE (IEEE 1815-2012 Table 11-5
// NOTE 2).
func withOnline(v app.Value) app.Value {
	switch t := v.(type) {
	case app.Binary:
		t.Flags = app.FlagOnline
		return t
	case app.DoubleBitBinary:
		t.Flags = app.FlagOnline
		return t
	case app.Counter:
		t.Flags = app.FlagOnline
		return t
	case app.Analog:
		t.Flags = app.FlagOnline
		return t
	}
	return v
}

// maxNotices is how many notices the dispatcher holds before it is full:
// as many fragments as a session's receive queue holds (internal/channel,
// 64). While it is full, unsolicited responses are not taken (the
// outstation repeats them) and the automatic polls wait: what a peer can
// make the client hold for a slow handler is bounded. The responses to the
// application's own requests are always queued; their Result holds them
// too.
const maxNotices = 64

// dispatcher delivers responses to the Handler and state changes to the
// state handler, one at a time and in order, on its own goroutine.
type dispatcher struct {
	c      *Client
	mu     sync.Mutex
	queue  []notice
	signal chan struct{}
	// held counts the notices pushed and not delivered yet: those queued
	// and those of the batch being delivered.
	held int
	// room is signalled when a notice has been delivered.
	room chan struct{}
}

type notice struct {
	frag        *app.Fragment
	unsolicited bool
	state       dnp3.State
	err         error
	isState     bool
}

func newDispatcher(c *Client) *dispatcher {
	return &dispatcher{c: c, signal: make(chan struct{}, 1), room: make(chan struct{}, 1)}
}

// full reports whether the dispatcher holds maxNotices notices or more.
func (d *dispatcher) full() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.held >= maxNotices
}

func (d *dispatcher) push(n notice) {
	d.mu.Lock()
	d.queue = append(d.queue, n)
	d.held++
	d.mu.Unlock()
	select {
	case d.signal <- struct{}{}:
	default:
	}
}

func (d *dispatcher) response(f *app.Fragment, unsolicited bool) {
	if d.c.opts.handler != nil {
		d.push(notice{frag: f, unsolicited: unsolicited})
	}
}

func (d *dispatcher) state(s dnp3.State, err error) {
	d.push(notice{isState: true, state: s, err: err})
}

func (d *dispatcher) run() {
	defer d.c.wg.Done()
	for {
		d.mu.Lock()
		q := d.queue
		d.queue = nil
		d.mu.Unlock()
		for _, n := range q {
			d.deliver(n)
		}
		if len(q) > 0 {
			continue
		}
		select {
		case <-d.signal:
		case <-d.c.closeCh:
			d.mu.Lock()
			q := d.queue
			d.queue = nil
			d.mu.Unlock()
			for _, n := range q {
				d.deliver(n)
			}
			return
		}
	}
}

// deliver hands one notice to the application, recovering from a panic in
// its handler: the notice is lost, the dispatcher goes on.
func (d *dispatcher) deliver(n notice) {
	defer func() {
		if r := recover(); r != nil {
			d.c.log.Error("panic while delivering", "panic", r, "stack", string(debug.Stack()))
		}
		d.mu.Lock()
		d.held--
		d.mu.Unlock()
		select {
		case d.room <- struct{}{}:
		default:
		}
	}()
	o := d.c.opts
	if n.isState {
		if o.stateHandler != nil {
			o.stateHandler(n.state, n.err)
		}
		return
	}
	ms := Measurements(n.frag)
	if len(ms) == 0 {
		return
	}
	o.handler.HandleMeasurements(ResponseInfo{
		Unsolicited: n.unsolicited, IIN: n.frag.IIN, Seq: n.frag.Control.Seq,
		FIR: n.frag.Control.FIR, FIN: n.frag.Control.FIN,
	}, ms)
}

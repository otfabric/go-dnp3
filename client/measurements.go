// SPDX-License-Identifier: MIT

package client

import (
	"sync"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// Measurement is one point value or event of a response.
type Measurement struct {
	// GV is the object the value was sent as, for example app.G30V5.
	GV app.GroupVariation
	// Index is the point index.
	Index uint32
	// Value is one of the point value types of package app: app.Binary,
	// app.DoubleBitBinary, app.BinaryCommandEvent, app.Counter,
	// app.Analog, app.AnalogDeadband, app.AnalogCommandEvent,
	// app.AbsoluteTime (g50v4, a time and interval), app.BCD,
	// app.UnsignedInteger, app.OctetString or app.SecurityStatistic.
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
// protocol, and a handler may issue requests.
type Handler interface {
	HandleMeasurements(info ResponseInfo, ms []Measurement)
}

// HandlerFunc adapts a function to a [Handler].
type HandlerFunc func(info ResponseInfo, ms []Measurement)

// HandleMeasurements calls f.
func (f HandlerFunc) HandleMeasurements(info ResponseInfo, ms []Measurement) { f(info, ms) }

// isMeasurement reports whether objects of group g are point values: not
// commands, time, file, authentication or attribute objects.
func isMeasurement(gv app.GroupVariation) bool {
	switch gv.Group() {
	case 1, 2, 3, 4, 10, 11, 13, 20, 21, 22, 23, 30, 31, 32, 33, 34, 40, 42, 43, 101, 102, 110, 111, 121, 122:
		return true
	case 50:
		// The indexed time and interval is a point; the other variations
		// are the time of time synchronization and freezes.
		return gv == app.G50V4
	default:
		return false
	}
}

// Measurements returns the measurements of a fragment, in the order of
// its headers.
func Measurements(f *app.Fragment) []Measurement {
	var out []Measurement
	for _, h := range f.Headers {
		if !isMeasurement(h.GV) {
			continue
		}
		ev := h.GV.IsEvent()
		for _, o := range h.Objects {
			if o.Value == nil {
				continue
			}
			out = append(out, Measurement{GV: h.GV, Index: o.Index, Value: o.Value, Event: ev})
		}
	}
	return out
}

// dispatcher delivers responses to the Handler and state changes to the
// state handler, one at a time and in order, on its own goroutine.
type dispatcher struct {
	c      *Client
	mu     sync.Mutex
	queue  []notice
	signal chan struct{}
}

type notice struct {
	frag        *app.Fragment
	unsolicited bool
	state       dnp3.State
	err         error
	isState     bool
}

func newDispatcher(c *Client) *dispatcher {
	return &dispatcher{c: c, signal: make(chan struct{}, 1)}
}

func (d *dispatcher) push(n notice) {
	d.mu.Lock()
	d.queue = append(d.queue, n)
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

func (d *dispatcher) deliver(n notice) {
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

// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// selection is the state of a SELECT that waits for its OPERATE.
type selection struct {
	seq     uint8
	objects []byte // the encoded object headers of the SELECT
	at      time.Time
}

// control executes SELECT, OPERATE, DIRECT_OPERATE and
// DIRECT_OPERATE_NR. The response echoes the request's headers with the
// status of each control.
func (a *association) control(req *app.Fragment, broadcast bool) *response {
	objects := encodeHeaders(req.Headers)
	fc := req.Function
	if broadcast && fc != app.FuncDirectOperateNoAck && fc != app.FuncDirectOperate {
		// SELECT and OPERATE are never broadcast.
		return &response{none: true}
	}

	// An OPERATE that matches no SELECT is answered NO_SELECT; one that
	// matches a SELECT whose timer has run out, TIMEOUT (IEEE 1815-2012
	// Table 11-4).
	var noSelect, expired bool
	if fc == app.FuncOperate {
		s := a.selection
		a.selection = nil
		noSelect = s == nil || req.Control.Seq != app.NextSeq(s.seq) || !bytes.Equal(s.objects, objects)
		expired = !noSelect && time.Since(s.at) > a.srv.opts.selectTimeout
	}

	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	h := a.srv.opts.handler
	echo := make([]app.Header, len(req.Headers))
	r := &response{}
	allOK := true
	malformed := false
	count := 0
	for i, hdr := range req.Headers {
		echo[i] = hdr
		echo[i].Objects = append([]app.Object(nil), hdr.Objects...)
		switch hdr.GV {
		case app.G12V1, app.G41V1, app.G41V2, app.G41V3, app.G41V4:
		case app.G12V2:
			// A pattern control block applies to the points of the pattern
			// mask that follows it.
			if i+1 >= len(req.Headers) || req.Headers[i+1].GV != app.G12V3 || len(hdr.Objects) != 1 {
				r.iin |= app.IINParameterError
				allOK, malformed = false, true
				continue
			}
		case app.G12V3:
			continue // handled with its pattern control block
		default:
			r.iin |= app.IINObjectUnknown
			allOK, malformed = false, true
			continue
		}
		if !controlValues(hdr) || (hdr.GV == app.G12V2 && !binaryValues(req.Headers[i+1])) {
			// A header whose objects carry no control block, e.g. one
			// with a qualifier that carries indices only.
			r.iin |= app.IINParameterError
			allOK, malformed = false, true
			continue
		}
		for j := range echo[i].Objects {
			o := &echo[i].Objects[j]
			var status app.CommandStatus
			switch {
			case count >= a.srv.opts.maxControls:
				status = app.StatusTooManyObjects
			case noSelect:
				status = app.StatusNoSelect
			case expired:
				status = app.StatusTimeout
			case hdr.GV == app.G12V2:
				status = a.pattern(ctx, h, fc, o.Value.(app.CROB), req.Headers[i+1])
			default:
				status = a.execute(ctx, h, fc, Command{GV: hdr.GV, Index: o.Index, Value: o.Value, Master: a.master})
			}
			count++
			if status != app.StatusSuccess {
				allOK = false
			}
			// A control of a point the outstation does not have, or does
			// not support, also sets IIN2.2, as opendnp3 and stepfunc do
			// and the DNP3 IED certification procedure requires.
			if status == app.StatusNotSupported {
				r.iin |= app.IINParameterError
			}
			o.Value = withStatus(o.Value, status)
		}
	}
	if fc == app.FuncSelect && allOK && r.iin == 0 {
		a.selection = &selection{seq: req.Control.Seq, objects: objects, at: time.Now()}
	}
	if fc == app.FuncDirectOperateNoAck {
		return &response{none: true}
	}
	if !malformed {
		r.plans = []fragPlan{{headers: echo}}
	}
	return r
}

func (a *association) execute(ctx context.Context, h Handler, fc app.FunctionCode, c Command) app.CommandStatus {
	var status app.CommandStatus
	switch fc {
	case app.FuncSelect:
		return h.Select(ctx, c)
	case app.FuncOperate:
		status = h.Operate(ctx, c, SelectBeforeOperate)
	case app.FuncDirectOperate:
		status = h.Operate(ctx, c, DirectOperate)
	default:
		status = h.Operate(ctx, c, DirectOperateNoAck)
	}
	a.commandEvent(c, status)
	return status
}

// commandEvent reports an executed control as a command event when the
// output's configuration asks for it.
func (a *association) commandEvent(c Command, status app.CommandStatus) {
	db := a.srv.db
	t, et := BinaryOutput, BinaryOutputCommand
	if c.GV.Group() == 41 {
		t, et = AnalogOutput, AnalogOutputCommand
	}
	db.mu.RLock()
	p, ok := db.points[t][c.Index]
	var cfg PointConfig
	if ok {
		cfg = p.cfg
	}
	db.mu.RUnlock()
	if !ok || cfg.CommandEventClass == 0 {
		return
	}
	ts := a.srv.clock.now()
	// A control is a CROB (groups 12) or an analog output (group 41).
	var v app.Value
	if ao, isAnalog := c.Value.(app.AnalogOutput); isAnalog {
		v = app.AnalogCommandEvent{Value: ao.Value, Status: status, Time: ts}
	} else {
		crob, _ := c.Value.(app.CROB)
		v = app.BinaryCommandEvent{Value: crobState(crob), Status: status, Time: ts}
	}
	a.srv.publish([]event{{typ: et, index: c.Index, class: cfg.CommandEventClass, variation: cfg.CommandEventVariation, value: v}})
}

// crobState is the state a CROB commands: on for latch on, pulse on and
// close, off for latch off, pulse off and trip.
func crobState(c app.CROB) bool {
	switch c.TripClose {
	case app.TCCClose:
		return true
	case app.TCCTrip:
		return false
	default:
		return c.Op == app.OpLatchOn || c.Op == app.OpPulseOn
	}
}

// pattern executes a pattern control block for every set bit of the mask.
func (a *association) pattern(ctx context.Context, h Handler, fc app.FunctionCode, pcb app.CROB, mask app.Header) app.CommandStatus {
	status := app.StatusSuccess
	for _, o := range mask.Objects {
		if b, _ := o.Value.(app.Binary); !b.Value {
			continue
		}
		s := a.execute(ctx, h, fc, Command{GV: app.G12V2, Index: o.Index, Value: pcb, Master: a.master})
		if s != app.StatusSuccess && status == app.StatusSuccess {
			status = s
		}
	}
	return status
}

// controlValues reports whether every object of a control header carries
// the block of its variation: a CROB for g12, an analog output for g41.
func controlValues(h app.Header) bool {
	for _, o := range h.Objects {
		switch o.Value.(type) {
		case app.CROB:
			if h.GV.Group() != 12 {
				return false
			}
		case app.AnalogOutput:
			if h.GV.Group() != 41 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// binaryValues reports whether every object of h is a binary value, as the
// bits of a pattern mask (g12v3) are.
func binaryValues(h app.Header) bool {
	for _, o := range h.Objects {
		if _, ok := o.Value.(app.Binary); !ok {
			return false
		}
	}
	return true
}

func withStatus(v app.Value, s app.CommandStatus) app.Value {
	switch x := v.(type) {
	case app.CROB:
		x.Status = s
		return x
	case app.AnalogOutput:
		x.Status = s
		return x
	default:
		return v
	}
}

// encodeHeaders returns the encoding of the object headers with every
// status cleared, to compare an OPERATE with its SELECT.
func encodeHeaders(hs []app.Header) []byte {
	f := app.Fragment{Function: app.FuncSelect, Headers: make([]app.Header, len(hs))}
	for i, h := range hs {
		f.Headers[i] = h
		f.Headers[i].Objects = make([]app.Object, len(h.Objects))
		for j, o := range h.Objects {
			f.Headers[i].Objects[j] = app.Object{Index: o.Index, Value: withStatus(o.Value, app.StatusSuccess)}
		}
	}
	b, _ := f.Encode()
	return b
}

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

	// A SELECT replaces the selection, whether it succeeds or not, and an
	// OPERATE uses it up (IEEE 1815-2012 4.4.4.3 Rules 1 to 3, p. 50). An
	// OPERATE that matches no SELECT is answered NO_SELECT; one that
	// matches a SELECT whose timer has run out, TIMEOUT (Table 11-7, p. 329).
	s := a.selection
	a.selection = nil
	var noSelect, expired bool
	if fc == app.FuncOperate {
		noSelect = s == nil || req.Control.Seq != app.NextSeq(s.seq) || !bytes.Equal(s.objects, objects)
		expired = !noSelect && time.Since(s.at) > a.srv.opts.selectTimeout
	}

	// Every header is checked before any control is carried out: a
	// request with a header that is not a control is not executed at all
	// (4.4.4.1, pp. 48-49).
	r := &response{iin: controlHeadersValid(req.Headers)}
	if r.iin == 0 && fc != app.FuncDirectOperateNoAck {
		// The response echoes the request. When the echo does not fit a
		// fragment (4.3 Rule 1, p. 38), nothing is executed and the request
		// is refused as an option the outstation does not support (4.5.11,
		// p. 85): the standard does not say what to answer.
		if n := responseHeaderLen + headersLen(req.Headers); n > a.srv.opts.maxTxFragment {
			r.iin |= app.IINParameterError
		}
	}
	if r.iin != 0 {
		if fc == app.FuncDirectOperateNoAck {
			return &response{none: true}
		}
		return r
	}

	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	h := a.srv.opts.handler
	echo := make([]app.Header, len(req.Headers))
	allOK := true
	count := 0
	for i, hdr := range req.Headers {
		echo[i] = hdr
		echo[i].Objects = append([]app.Object(nil), hdr.Objects...)
		if hdr.GV == app.G12V3 {
			continue // handled with its pattern control block
		}
		for j := range echo[i].Objects {
			o := &echo[i].Objects[j]
			var status app.CommandStatus
			counted := false // pattern counts the controls it carries out
			switch rs := requestStatus(o.Value); {
			case count >= a.srv.opts.maxControls:
				status = app.StatusTooManyObjects
			case noSelect:
				status = app.StatusNoSelect
			case expired:
				status = app.StatusTimeout
			case rs == app.StatusNonParticipating:
				// A test or no-op: not carried out, and not refused either;
				// the echo keeps the status (Table 11-7 footnote a, p. 330).
				status = rs
			case rs != app.StatusSuccess:
				// A control whose request carries a status is not carried
				// out (TB2014-002; IEEE 1815-202x; 3.1r1 8.2.6).
				status = app.StatusFormatError
			case queued(o.Value):
				// The queue field is obsolete: NOT_SUPPORTED, not carried
				// out (A.8.1.2.2, p. 506).
				status = app.StatusNotSupported
			case hdr.GV == app.G12V2:
				status = a.pattern(ctx, h, fc, o.Value.(app.CROB), req.Headers[i+1], &count)
				counted = true
			default:
				status = a.execute(ctx, h, fc, Command{GV: hdr.GV, Index: o.Index, Value: o.Value, Master: a.master})
			}
			if !counted {
				count++
			}
			if status != app.StatusSuccess && status != app.StatusNonParticipating {
				allOK = false
			}
			// A control of a point the outstation does not have, or does
			// not support, also sets IIN2.2, as opendnp3 does and the
			// DNP3 IED certification procedure requires.
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
	r.plans = []fragPlan{{headers: echo}}
	return r
}

// controlHeadersValid checks the headers of a control request: control
// blocks (g12v1, g41v1 to g41v4) whose objects carry them, and a pattern
// control block (g12v2) followed by its pattern mask (g12v3). A control
// header must carry objects: one whose qualifier names none (0x06) has no
// control to carry out, and its echo would be a header a response cannot
// carry (IEEE 1815-2012 Table 4-8), so it is answered with IIN2.2.
func controlHeadersValid(hs []app.Header) app.IIN {
	var iin app.IIN
	for i, h := range hs {
		switch h.GV {
		case app.G12V1, app.G41V1, app.G41V2, app.G41V3, app.G41V4:
			if len(h.Objects) == 0 || !controlValues(h) {
				// A header whose objects carry no control block, e.g. one
				// with a qualifier that carries indices only.
				iin |= app.IINParameterError
			}
		case app.G12V2:
			if i+1 >= len(hs) || hs[i+1].GV != app.G12V3 || len(h.Objects) != 1 || !controlValues(h) || !binaryValues(hs[i+1]) {
				iin |= app.IINParameterError
			}
		case app.G12V3:
			if i == 0 || hs[i-1].GV != app.G12V2 || len(h.Objects) == 0 {
				iin |= app.IINParameterError // a pattern mask without its block, or without bits
			}
		default:
			iin |= app.IINObjectUnknown
		}
	}
	return iin
}

// headersLen is the encoded size of the object headers.
func headersLen(hs []app.Header) int {
	n := 0
	for _, h := range hs {
		l, _ := h.EncodedLen()
		n += l
	}
	return n
}

// queued reports whether a CROB has the obsolete queue bit set.
func queued(v app.Value) bool {
	c, ok := v.(app.CROB)
	return ok && c.Queue
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

// crobState is the commanded state of a binary command event (g13): 1 for
// latch on and close, 0 for latch off, trip and NUL, and 0 where the
// commanded state is unknown (IEEE 1815-2012 A.9.1.2.2, p. 515), as for a
// pulse, which leaves no state.
func crobState(c app.CROB) bool {
	switch c.TripClose {
	case app.TCCClose:
		return true
	case app.TCCTrip:
		return false
	default:
		return c.Op == app.OpLatchOn
	}
}

// pattern executes a pattern control block for every set bit of the mask.
// Each control it carries out counts against WithMaxControls in *count:
// once the limit is reached, the bits that remain are not carried out and
// the block is answered with TOO_MANY_OBJS.
func (a *association) pattern(ctx context.Context, h Handler, fc app.FunctionCode, pcb app.CROB, mask app.Header, count *int) app.CommandStatus {
	status := app.StatusSuccess
	for _, o := range mask.Objects {
		if b, _ := o.Value.(app.Binary); !b.Value {
			continue
		}
		if *count >= a.srv.opts.maxControls {
			return app.StatusTooManyObjects
		}
		s := a.execute(ctx, h, fc, Command{GV: app.G12V2, Index: o.Index, Value: pcb, Master: a.master})
		*count++
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

// requestStatus is the status field of a control block as the master sent
// it, which must be zero.
func requestStatus(v app.Value) app.CommandStatus {
	switch x := v.(type) {
	case app.CROB:
		return x.Status
	case app.AnalogOutput:
		return x.Status
	}
	return app.StatusSuccess
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

// encodeHeaders returns the encoding of the object headers as the master
// sent them, request statuses included, to compare an OPERATE with its
// SELECT. A conforming master sends the OPERATE with the octets of its
// SELECT (IEEE 1815-2012 4.4.4, p. 48); a control the SELECT marked
// NON_PARTICIPATING was not selected (Table 11-7 footnote a, p. 330), so an
// OPERATE that carries it with another status matches no SELECT.
func encodeHeaders(hs []app.Header) []byte {
	f := app.Fragment{Function: app.FuncSelect, Headers: hs}
	b, _ := f.Encode()
	return b
}

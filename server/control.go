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

	var noSelect bool
	if fc == app.FuncOperate {
		s := a.selection
		a.selection = nil
		noSelect = s == nil || req.Control.Seq != app.NextSeq(s.seq) || !bytes.Equal(s.objects, objects) ||
			time.Since(s.at) > a.srv.opts.selectTimeout
	}

	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	h := a.srv.opts.handler
	echo := make([]app.Header, len(req.Headers))
	r := &response{}
	allOK := true
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
				allOK = false
				continue
			}
		case app.G12V3:
			continue // handled with its pattern control block
		default:
			r.iin |= app.IINObjectUnknown
			allOK = false
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
			case hdr.GV == app.G12V2:
				status = a.pattern(ctx, h, fc, o.Value.(app.CROB), req.Headers[i+1])
			default:
				status = a.execute(ctx, h, fc, Command{GV: hdr.GV, Index: o.Index, Value: o.Value, Master: a.master})
			}
			count++
			if status != app.StatusSuccess {
				allOK = false
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
	if r.iin&(app.IINObjectUnknown|app.IINParameterError) == 0 {
		r.plans = []fragPlan{{headers: echo}}
	}
	return r
}

func (a *association) execute(ctx context.Context, h Handler, fc app.FunctionCode, c Command) app.CommandStatus {
	switch fc {
	case app.FuncSelect:
		return h.Select(ctx, c)
	case app.FuncOperate:
		return h.Operate(ctx, c, SelectBeforeOperate)
	case app.FuncDirectOperate:
		return h.Operate(ctx, c, DirectOperate)
	default:
		return h.Operate(ctx, c, DirectOperateNoAck)
	}
}

// pattern executes a pattern control block for every set bit of the mask.
func (a *association) pattern(ctx context.Context, h Handler, fc app.FunctionCode, pcb app.CROB, mask app.Header) app.CommandStatus {
	status := app.StatusSuccess
	for _, o := range mask.Objects {
		if !o.Value.(app.Binary).Value {
			continue
		}
		s := a.execute(ctx, h, fc, Command{GV: app.G12V2, Index: o.Index, Value: pcb, Master: a.master})
		if s != app.StatusSuccess && status == app.StatusSuccess {
			status = s
		}
	}
	return status
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

// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Read sends a READ with the given headers and returns the response, all
// fragments of it. The measurements also go to the Handler.
func (c *Client) Read(ctx context.Context, headers ...app.Header) (*Result, error) {
	if len(headers) == 0 {
		return nil, fmt.Errorf("%w: READ without headers", dnp3.ErrInvalidOption)
	}
	return c.request(ctx, app.FuncRead, true, headers...)
}

// IntegrityPoll reads the events of classes 1, 2 and 3 and then the
// static data of class 0.
func (c *Client) IntegrityPoll(ctx context.Context) (*Result, error) {
	res, err := c.Read(ctx, app.ClassHeaders(1, 2, 3, 0)...)
	if err == nil {
		c.mu.Lock()
		c.integrity = time.Now()
		c.mu.Unlock()
	}
	return res, err
}

// integritySince reports whether an integrity poll completed after t.
func (c *Client) integritySince(t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.integrity.After(t)
}

// EventPoll reads the events of the given classes (1..3); no classes
// means all three.
func (c *Client) EventPoll(ctx context.Context, classes ...int) (*Result, error) {
	if len(classes) == 0 {
		classes = []int{1, 2, 3}
	}
	for _, cl := range classes {
		if cl < 1 || cl > 3 {
			return nil, fmt.Errorf("%w: event class %d", dnp3.ErrInvalidOption, cl)
		}
	}
	return c.Read(ctx, app.ClassHeaders(classes...)...)
}

// Request sends any request and returns the response. It is repeated on
// failure (with WithRetry) only for READ.
func (c *Client) Request(ctx context.Context, fc app.FunctionCode, headers ...app.Header) (*Result, error) {
	return c.request(ctx, fc, fc == app.FuncRead, headers...)
}

// Broadcast sends a request to every outstation on the channel, at the
// broadcast address dest: link.BroadcastNoConfirm (0xFFFD),
// link.BroadcastConfirm (0xFFFE, confirmation mandatory) or
// link.BroadcastOptionalConfirm (0xFFFF, confirmation optional). Nobody answers;
// each outstation executes the request and sets IIN1.0 BROADCAST in its
// next response. Requests that need an answer (READ, SELECT, OPERATE, the
// file and authentication functions) cannot be broadcast.
func (c *Client) Broadcast(ctx context.Context, dest link.Address, fc app.FunctionCode, headers ...app.Header) error {
	if !dest.Broadcast() {
		return invalidOption("broadcast to %d: not a broadcast address", dest)
	}
	switch fc {
	case app.FuncConfirm, app.FuncRead, app.FuncSelect, app.FuncOperate, app.FuncOpenFile, app.FuncCloseFile,
		app.FuncDeleteFile, app.FuncGetFileInfo, app.FuncAuthenticateFile, app.FuncAbortFile,
		app.FuncAuthRequest, app.FuncAuthRequestNoAck:
		return invalidOption("%s cannot be broadcast", fc)
	default:
	}
	return c.do(ctx, fc, false, func(ctx context.Context) error {
		c.mu.Lock()
		sess := c.sess
		seq := c.seq
		c.mu.Unlock()
		if sess == nil {
			return dnp3.ErrNotConnected
		}
		req := &app.Fragment{Control: app.SingleControl(seq), Function: fc, Headers: headers}
		data, err := req.Encode()
		if err != nil {
			return err
		}
		if lim := c.opts.maxTxFragment; lim > 0 && len(data) > lim {
			return invalidOption("%s broadcast of %d octets exceeds the request fragment limit of %d (WithMaxRequestFragment)", fc, len(data), lim)
		}
		// The sequence number is taken only for a request that is sent
		// (IEEE 1815-2012 clause 4.3 Rule 14).
		c.mu.Lock()
		c.seq = app.NextSeq(seq)
		c.mu.Unlock()
		c.proc.sendMu.Lock()
		err = sess.SendBroadcast(ctx, data, dest)
		c.proc.sendMu.Unlock()
		if err != nil {
			return sendError(err)
		}
		if m := c.opts.metrics; m != nil {
			m.OnFragmentSent(c.remoteAddr(), req, len(data))
		}
		c.log.DebugContext(ctx, "broadcast sent", "fragment", req.String(), "dest", dest)
		return nil
	})
}

// Write sends a WRITE with the given headers.
func (c *Client) Write(ctx context.Context, headers ...app.Header) (*Result, error) {
	return c.request(ctx, app.FuncWrite, false, headers...)
}

// CommandMode selects how a control is executed.
type CommandMode uint8

// Command modes.
const (
	// SelectBeforeOperate sends SELECT and, when every control was
	// accepted, OPERATE.
	SelectBeforeOperate CommandMode = iota
	// DirectOperate sends DIRECT_OPERATE.
	DirectOperate
	// DirectOperateNoAck sends DIRECT_OPERATE_NR; there is no response
	// and so no status.
	DirectOperateNoAck
)

// Command is one control.
type Command struct {
	// Index is the index of the output.
	Index uint32
	// Value is an app.CROB (control relay output block) or an
	// app.AnalogOutput (set-point).
	Value app.Value
	// GV is the object to send it as. Zero picks app.G12V1 for a CROB and,
	// for a set-point, app.G41V1 when the value is an integer that fits 32
	// bits and app.G41V3 otherwise. Subset levels 1 and 2 define only
	// app.G41V2 for set-points (IEEE 1815-2012 Tables 14-2 and 14-3), and
	// app.G41V1 is of level 3, app.G41V3 of level 4: set GV for an
	// outstation of a lower level.
	//
	// A command is sent as given, except that IEEE 1815-2012 requires the
	// queue bit of a CROB to be 0 (Annex A.8.1.2.2) and the status of a
	// request to be 0 (Annex A.8.1.2.2 and A.20.1.2.2) or 126,
	// NON_PARTICIPATING (Table 11-7): Operate refuses other values with
	// dnp3.ErrInvalidOption.
	GV app.GroupVariation
}

// CROB returns a command for a control relay output block.
func CROB(index uint32, op app.OpType, onMillis, offMillis uint32) Command {
	return Command{Index: index, Value: app.CROB{Op: op, Count: 1, OnTime: onMillis, OffTime: offMillis}}
}

// SetPoint returns a command for an analog output.
func SetPoint(index uint32, value float64) Command {
	return Command{Index: index, Value: app.AnalogOutput{Value: value}}
}

func (cmd Command) gv() (app.GroupVariation, error) {
	if cmd.GV != 0 {
		return cmd.GV, nil
	}
	switch v := cmd.Value.(type) {
	case app.CROB:
		return app.G12V1, nil
	case app.AnalogOutput:
		if v.Value == math.Trunc(v.Value) && v.Value >= math.MinInt32 && v.Value <= math.MaxInt32 {
			return app.G41V1, nil
		}
		return app.G41V3, nil
	default:
		return 0, fmt.Errorf("%w: %T is not a command", dnp3.ErrInvalidOption, cmd.Value)
	}
}

// valid checks the fields IEEE 1815-2012 fixes in a request: the queue
// bit of a CROB is 0 (Annex A.8.1.2.2, printed page 506: "The master shall
// always set this bit to 0"), and the status is 0 in a request (A.8.1.2.2,
// p. 507, and A.20.1.2.2, p. 615) or NON_PARTICIPATING, which Table 11-7
// (p. 330) defines for requests.
func (cmd Command) valid() error {
	var st app.CommandStatus
	switch v := cmd.Value.(type) {
	case app.CROB:
		if v.Queue {
			return fmt.Errorf("%w: CROB for index %d with the obsolete queue bit set", dnp3.ErrInvalidOption, cmd.Index)
		}
		st = v.Status
	case app.AnalogOutput:
		st = v.Status
	}
	if st != app.StatusSuccess && st != app.StatusNonParticipating {
		return fmt.Errorf("%w: command for index %d with status %s in a request", dnp3.ErrInvalidOption, cmd.Index, st)
	}
	return nil
}

// commandHeaders groups consecutive commands of one object into
// index-prefixed headers.
func commandHeaders(cmds []Command) ([]app.Header, error) {
	if len(cmds) == 0 {
		return nil, fmt.Errorf("%w: no commands", dnp3.ErrInvalidOption)
	}
	var hs []app.Header
	var objs []app.Object
	var cur app.GroupVariation
	flush := func() {
		if len(objs) > 0 {
			hs = append(hs, app.Indexed(cur, objs...))
			objs = nil
		}
	}
	for _, cmd := range cmds {
		gv, err := cmd.gv()
		if err != nil {
			return nil, err
		}
		if err := cmd.valid(); err != nil {
			return nil, err
		}
		if gv != cur {
			flush()
			cur = gv
		}
		objs = append(objs, app.Object{Index: cmd.Index, Value: cmd.Value})
	}
	flush()
	return hs, nil
}

// Operate executes controls and returns the status the outstation
// reported for each, in order. With DirectOperateNoAck the statuses are
// all app.StatusSuccess: nothing is reported.
//
// A status other than success fails with a *dnp3.CommandError for the
// first such control; the statuses are returned as well. A truncated
// response, which holds the controls up to the first that failed (IEEE
// 1815-2012 clause 4.4.4.3 Rule 6), returns the statuses of those only.
// Controls are never repeated by WithRetry.
//
// With SelectBeforeOperate the OPERATE is sent only when the response to
// the SELECT repeats, octet for octet, everything that followed the
// function code in the request, with every status 0 and none of IIN2.0,
// 2.1, 2.2 and 2.4 set (clause 4.4.4.3 Rule 8); a response that differs
// otherwise than in its statuses fails with dnp3.ErrProtocol.
func (c *Client) Operate(ctx context.Context, mode CommandMode, cmds ...Command) ([]app.CommandStatus, error) {
	hs, err := commandHeaders(cmds)
	if err != nil {
		return nil, err
	}
	var fc app.FunctionCode
	switch mode {
	case SelectBeforeOperate:
		fc = app.FuncOperate
	case DirectOperate:
		fc = app.FuncDirectOperate
	default:
		fc = app.FuncDirectOperateNoAck
	}
	var statuses []app.CommandStatus
	err = c.do(ctx, fc, false, func(ctx context.Context) error {
		if mode == DirectOperateNoAck {
			_, err := c.exchange(ctx, fc, hs)
			statuses = make([]app.CommandStatus, len(cmds))
			return err
		}
		if mode == SelectBeforeOperate {
			// SELECT and OPERATE in one turn: the OPERATE must carry the
			// next sequence number.
			res, err := c.exchange(ctx, app.FuncSelect, hs)
			if statuses, err = controlResult(hs, res, err, true); err != nil {
				return err
			}
		}
		res, err := c.exchange(ctx, fc, hs)
		statuses, err = controlResult(hs, res, err, false)
		return err
	})
	return statuses, err
}

// controlResult returns the statuses of a control response and the error
// of the first control that failed. A response that sets an error IIN but
// echoes the request, as an outstation does for a control it does not
// support (NOT_SUPPORTED with IIN2.2), reports its statuses: a
// CommandError, rather than the IINError. With exact, the response to a
// SELECT, the echo must repeat the request octet for octet but for the
// statuses (IEEE 1815-2012 clause 4.4.4.3 Rule 8).
func controlResult(req []app.Header, res *Result, err error, exact bool) ([]app.CommandStatus, error) {
	var ie *dnp3.IINError
	if err != nil && (!errors.As(err, &ie) || res == nil || len(res.Fragments) == 0) {
		return nil, err
	}
	statuses, echoErr := echoStatuses(req, res, exact)
	if echoErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, echoErr
	}
	if failed := firstFailure(req, statuses); failed != nil {
		return statuses, failed
	}
	return statuses, err
}

// echoStatuses checks that the response echoes the request and returns
// the status of each control it holds. A response may end after the first
// control that failed: a truncated response (IEEE 1815-2012 clause 4.4.4.3
// Rule 6, item 3) holds the controls up to and including it, every one
// before it with status 0. With exact, the octets of the response after
// its IIN must be those of the request after its function code, with the
// statuses of the response (clause 4.4.4.3 Rule 8).
func echoStatuses(req []app.Header, res *Result, exact bool) ([]app.CommandStatus, error) {
	got := res.Headers()
	if len(got) == 0 || len(got) > len(req) {
		return nil, fmt.Errorf("%w: control echo has %d headers, the request %d", dnp3.ErrProtocol, len(got), len(req))
	}
	var out []app.CommandStatus
	echo := make([]app.Header, len(got)) // the request as the response should repeat it
	// The response echoes the first len(got) headers of the request.
	for i, h := range req[:len(got)] {
		e := got[i]
		lastHeader := i == len(got)-1
		if e.GV != h.GV || len(e.Objects) > len(h.Objects) || (!lastHeader && len(e.Objects) != len(h.Objects)) || len(e.Objects) == 0 {
			return nil, fmt.Errorf("%w: control echo header %d is %s n=%d, the request %s n=%d",
				dnp3.ErrProtocol, i, e.GV, len(e.Objects), h.GV, len(h.Objects))
		}
		echo[i] = h
		echo[i].Objects = make([]app.Object, len(e.Objects))
		for j, o := range e.Objects {
			r := h.Objects[j]
			if o.Index != r.Index {
				return nil, fmt.Errorf("%w: control echo index %d, the request %d", dnp3.ErrProtocol, o.Index, r.Index)
			}
			switch v := o.Value.(type) {
			case app.CROB:
				want, ok := r.Value.(app.CROB)
				want.Status = v.Status
				if !ok || want != v {
					return nil, fmt.Errorf("%w: control echo %s differs from the request", dnp3.ErrProtocol, v)
				}
				r.Value = want
				out = append(out, v.Status)
			case app.AnalogOutput:
				want, ok := r.Value.(app.AnalogOutput)
				if !ok {
					return nil, fmt.Errorf("%w: control echo %v differs from the request", dnp3.ErrProtocol, v)
				}
				want.Status = v.Status
				r.Value = want
				out = append(out, v.Status)
			default:
				return nil, fmt.Errorf("%w: control echo carries %T", dnp3.ErrProtocol, o.Value)
			}
			echo[i].Objects[j] = r
		}
	}
	if n := countObjects(req); len(out) < n {
		// A truncated response: only the last control it holds failed.
		for i, s := range out {
			if (s != app.StatusSuccess) != (i == len(out)-1) {
				return nil, fmt.Errorf("%w: control echo of %d of %d controls is not a truncated response (statuses %v)",
					dnp3.ErrProtocol, len(out), n, out)
			}
		}
	}
	if exact {
		want, err := (&app.Fragment{Headers: echo}).Encode()
		if err != nil {
			return nil, fmt.Errorf("%w: control echo: %w", dnp3.ErrProtocol, err)
		}
		var have []byte
		for _, raw := range res.raw {
			have = append(have, raw[4:]...)
		}
		if !bytes.Equal(have, want[2:]) {
			return nil, fmt.Errorf("%w: the SELECT response does not repeat the request octet for octet:\n response % x\n request  % x",
				dnp3.ErrProtocol, have, want[2:])
		}
	}
	return out, nil
}

func countObjects(hs []app.Header) int {
	n := 0
	for _, h := range hs {
		n += len(h.Objects)
	}
	return n
}

// firstFailure returns the CommandError of the first control whose status
// is not success; statuses may end early (a truncated response).
func firstFailure(hs []app.Header, statuses []app.CommandStatus) error {
	i := 0
	for _, h := range hs {
		for _, o := range h.Objects {
			if i < len(statuses) && statuses[i] != app.StatusSuccess {
				return &dnp3.CommandError{GV: h.GV, Index: o.Index, Status: statuses[i]}
			}
			i++
		}
	}
	return nil
}

// WriteTime writes the outstation's time (g50v1) without delay
// compensation.
func (c *Client) WriteTime(ctx context.Context, t time.Time) error {
	_, err := c.Write(ctx, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.TimestampOf(t)}))
	return err
}

// SyncTime synchronizes the outstation's time with the given procedure of
// IEEE 1815-2012 clause 10.3.3: TimeSyncLAN (RECORD_CURRENT_TIME, then a
// WRITE of g50v3 with the time the request was handed to the link layer)
// or TimeSyncNonLAN (DELAY_MEASURE, then a WRITE of g50v1 with the current
// time corrected by half the round trip minus the outstation's processing
// delay). TimeSyncClearNeedTime runs ClearNeedTime instead.
//
// The requests go as UNCONFIRMED_USER_DATA, never repeated by the link
// layer (clause 10.3.4.1). With WithRetry a failed procedure is run again
// from its first request, with new sequence numbers and fresh times, as
// that clause requires.
//
// The times are taken in the client, not at the line: the round trip of
// the non-LAN procedure ends when the response has been received whole,
// and so includes the transmission time of the response, which clause
// 10.3.3.1 d) excludes. Over a slow serial line the time written is late
// by about half that time.
func (c *Client) SyncTime(ctx context.Context, p TimeSync) error {
	if p == TimeSyncClearNeedTime {
		return c.ClearNeedTime(ctx)
	}
	return c.do(ctx, app.FuncWrite, true, func(ctx context.Context) error {
		switch p {
		case TimeSyncLAN:
			// [A] of clause 10.3.3.2: when the last octet of the request
			// left, here when the link layer had written it.
			res, err := c.exchange(ctx, app.FuncRecordCurrentTime, nil)
			if err != nil {
				return err
			}
			_, err = c.exchange(ctx, app.FuncWrite, []app.Header{
				app.Counted(app.G50V3, app.AbsoluteTime{Time: app.TimestampOf(res.sent)})})
			return err
		case TimeSyncNonLAN:
			res, err := c.exchange(ctx, app.FuncDelayMeasure, nil)
			if err != nil {
				return err
			}
			delay := max((res.arrived.Sub(res.sending)-processingDelay(res))/2, 0)
			_, err = c.exchange(ctx, app.FuncWrite, []app.Header{
				app.Counted(app.G50V1, app.AbsoluteTime{Time: app.TimestampOf(time.Now().Add(delay))})})
			return err
		default:
			return fmt.Errorf("%w: time sync procedure %d", dnp3.ErrInvalidOption, p)
		}
	})
}

// processingDelay returns the outstation's processing delay of a
// DELAY_MEASURE response: its fine time delay object (g52v2, IEEE
// 1815-2012 clause 4.4.15).
func processingDelay(res *Result) time.Duration {
	var processing time.Duration
	for _, h := range res.Headers() {
		if d, ok := timeDelay(h); ok && h.GV == app.G52V2 {
			processing = d
		}
	}
	return processing
}

// DelayMeasure sends DELAY_MEASURE and returns the outstation's
// processing delay and the round trip time: from the request to the
// arrival of its response (To and Ti of IEEE 1815-2012 clause 4.4.15).
// With WithRetry a DELAY_MEASURE that failed is sent again as a new
// request (clause 10.3.4.1), and the round trip is that of the request
// that was answered.
func (c *Client) DelayMeasure(ctx context.Context) (processing, roundTrip time.Duration, err error) {
	res, err := c.request(ctx, app.FuncDelayMeasure, true)
	if err != nil {
		return 0, 0, err
	}
	return processingDelay(res), res.arrived.Sub(res.sending), nil
}

// timeDelay returns the delay of a header with one time delay object (g52).
func timeDelay(h app.Header) (time.Duration, bool) {
	if len(h.Objects) != 1 {
		return 0, false
	}
	t, ok := h.Objects[0].Value.(app.TimeDelay)
	return t.Delay, ok
}

// ColdRestart asks the outstation for a cold restart and returns the time
// after which it can be polled again. The NOTE of IEEE 1815-2012 clause
// 4.4.9 says a master should send no request before that time has passed;
// the client does not hold requests back, so the application should wait.
func (c *Client) ColdRestart(ctx context.Context) (time.Duration, error) {
	return c.restart(ctx, app.FuncColdRestart)
}

// WarmRestart asks the outstation for a warm restart and returns the time
// after which it can be polled again; see ColdRestart.
func (c *Client) WarmRestart(ctx context.Context) (time.Duration, error) {
	return c.restart(ctx, app.FuncWarmRestart)
}

func (c *Client) restart(ctx context.Context, fc app.FunctionCode) (time.Duration, error) {
	res, err := c.request(ctx, fc, false)
	if err != nil {
		return 0, err
	}
	for _, h := range res.Headers() {
		if d, ok := timeDelay(h); ok && (h.GV == app.G52V1 || h.GV == app.G52V2) {
			return d, nil
		}
	}
	return 0, fmt.Errorf("%w: restart response without a time delay object", dnp3.ErrProtocol)
}

// ActivateConfig sends ACTIVATE_CONFIG (function code 31) with the given
// headers, which name the configurations to activate: file specifications
// (g70v8), for example
//
//	c.ActivateConfig(ctx, app.FreeFormat(app.G70V8, app.FileSpecification{Name: "config.xml"}))
//
// or octet strings (g110). It returns the status of requested operation
// of every g91v1 object of the response, usually one. A response without
// g91v1, or with one that is not a valid status, fails with
// dnp3.ErrProtocol; an outstation that refuses the request fails it with
// a *dnp3.IINError. The request is never repeated (WithRetry).
func (c *Client) ActivateConfig(ctx context.Context, headers ...app.Header) ([]app.ActivateConfigStatus, error) {
	if len(headers) == 0 {
		return nil, fmt.Errorf("%w: ACTIVATE_CONFIG without headers", dnp3.ErrInvalidOption)
	}
	res, err := c.request(ctx, app.FuncActivateConfig, false, headers...)
	if err != nil {
		return nil, err
	}
	var out []app.ActivateConfigStatus
	for _, h := range res.Headers() {
		if h.GV != app.G91V1 {
			continue
		}
		for _, o := range h.Objects {
			r, _ := o.Value.(app.Raw)
			s, err := app.ParseActivateConfigStatus(r.Data)
			if err != nil {
				return nil, fmt.Errorf("%w: activation status: %w", dnp3.ErrProtocol, err)
			}
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: ACTIVATE_CONFIG response without an activation status (g91v1)", dnp3.ErrProtocol)
	}
	return out, nil
}

// EnableUnsolicited enables unsolicited responses for the given classes
// (1..3); no classes means all three.
func (c *Client) EnableUnsolicited(ctx context.Context, classes ...int) error {
	return c.unsolicited(ctx, app.FuncEnableUnsolicited, classes)
}

// DisableUnsolicited disables unsolicited responses for the given classes
// (1..3); no classes means all three.
func (c *Client) DisableUnsolicited(ctx context.Context, classes ...int) error {
	return c.unsolicited(ctx, app.FuncDisableUnsolicited, classes)
}

func (c *Client) unsolicited(ctx context.Context, fc app.FunctionCode, classes []int) error {
	if len(classes) == 0 {
		classes = []int{1, 2, 3}
	}
	for _, cl := range classes {
		if cl < 1 || cl > 3 {
			return fmt.Errorf("%w: unsolicited class %d", dnp3.ErrInvalidOption, cl)
		}
	}
	_, err := c.request(ctx, fc, true, app.ClassHeaders(classes...)...)
	return err
}

// AssignClass assigns the points the headers name to class (0..3), for
// example AssignClass(ctx, 2, app.AllObjects(app.G30V0)). The NOTE of IEEE
// 1815-2012 clause 4.4.14 says a master should poll all three event
// classes in one request right after, EventPoll(ctx), so that events are
// reported in the order they were generated; AssignClass does not.
func (c *Client) AssignClass(ctx context.Context, class int, headers ...app.Header) error {
	if class < 0 || class > 3 || len(headers) == 0 {
		return fmt.Errorf("%w: assign class %d with %d headers", dnp3.ErrInvalidOption, class, len(headers))
	}
	hs := append([]app.Header{app.AllObjects(app.GV(60, uint8(class+1)))}, headers...)
	_, err := c.request(ctx, app.FuncAssignClass, true, hs...)
	return err
}

// Freeze freezes the counters or analog inputs the headers name (for
// example app.AllObjects(app.G20V0)); with clear, counters are reset
// after the freeze. noAck sends the no-acknowledgement variant.
func (c *Client) Freeze(ctx context.Context, clear, noAck bool, headers ...app.Header) error {
	fc := app.FuncImmediateFreeze
	switch {
	case clear && noAck:
		fc = app.FuncFreezeClearNoAck
	case clear:
		fc = app.FuncFreezeClear
	case noAck:
		fc = app.FuncImmediateFreezeNoAck
	}
	_, err := c.request(ctx, fc, false, headers...)
	return err
}

// FreezeAtTime asks for a freeze at the given time, repeated every
// interval (zero for once). The interval is sent in 32 bits of
// milliseconds (g50v2); a negative interval or one of 2^32 ms (about 49.7
// days) or more is an ErrInvalidOption.
func (c *Client) FreezeAtTime(ctx context.Context, at time.Time, interval time.Duration, headers ...app.Header) error {
	ms := interval.Milliseconds()
	if ms < 0 || ms > math.MaxUint32 {
		return fmt.Errorf("%w: freeze interval %v does not fit 32 bits of milliseconds", dnp3.ErrInvalidOption, interval)
	}
	hs := append([]app.Header{app.Counted(app.G50V2, app.AbsoluteTime{Time: app.TimestampOf(at), Interval: uint32(ms)})}, headers...)
	_, err := c.request(ctx, app.FuncFreezeAtTime, false, hs...)
	return err
}

// ClearRestart clears IIN1.7 (DEVICE_RESTART) by writing g80v1 index 7
// (IEEE 1815-2012 clauses 4.5.8 and 5.1.1.1.1 Rule 1).
func (c *Client) ClearRestart(ctx context.Context) error {
	return c.clearIIN(ctx, app.IINDeviceRestart)
}

// ClearNeedTime clears IIN1.4 (NEED_TIME) by writing g80v1 index 4, as
// IEEE 1815-2012 clause 4.5.5 recommends for a master that does not need
// the outstation's time. The outstation then assumes no time
// synchronization is coming.
func (c *Client) ClearNeedTime(ctx context.Context) error {
	return c.clearIIN(ctx, app.IINNeedTime)
}

// clearIIN writes 0 to one internal indication (g80v1, qualifier 0x00).
func (c *Client) clearIIN(ctx context.Context, bit app.IIN) error {
	_, err := c.Write(ctx, app.Header{GV: app.G80V1, Qualifier: app.Qual1ByteStartStop,
		Objects: []app.Object{{Index: app.IINBit(bit), Value: app.Binary{}}}})
	return err
}

// ReadAttributes reads device attributes of set 0: one variation (for
// example app.AttrManufacturerName), app.AttrAllAttributes or
// app.AttrListOfVariations. The result maps variations to values.
func (c *Client) ReadAttributes(ctx context.Context, variation uint8) (map[uint8]app.Attribute, error) {
	return c.ReadAttributeSet(ctx, 0, variation)
}

// ReadAttributeSet is ReadAttributes for another set of device attributes
// (IEEE 1815-2012 clause 11.9.1).
func (c *Client) ReadAttributeSet(ctx context.Context, set uint16, variation uint8) (map[uint8]app.Attribute, error) {
	res, err := c.Read(ctx, app.IndexRange(app.GV(0, variation), uint32(set), uint32(set)))
	if err != nil {
		return nil, err
	}
	out := make(map[uint8]app.Attribute)
	for _, h := range res.Headers() {
		if h.GV.Group() != 0 {
			continue
		}
		for _, o := range h.Objects {
			if a, ok := o.Value.(app.Attribute); ok {
				out[h.GV.Variation()] = a
			}
		}
	}
	return out, nil
}

// WriteAttribute writes a device attribute of set 0.
func (c *Client) WriteAttribute(ctx context.Context, variation uint8, a app.Attribute) error {
	return c.WriteAttributeSet(ctx, 0, variation, a)
}

// WriteAttributeSet writes a device attribute of another set.
func (c *Client) WriteAttributeSet(ctx context.Context, set uint16, variation uint8, a app.Attribute) error {
	_, err := c.Write(ctx, app.Ranged(app.GV(0, variation), uint32(set), a))
	return err
}

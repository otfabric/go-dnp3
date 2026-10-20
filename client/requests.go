// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"
	"math"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
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
	Index uint32
	// Value is an app.CROB (control relay output block) or an
	// app.AnalogOutput (set-point).
	Value app.Value
	// GV is the object to send it as. Zero picks app.G12V1 for a CROB and,
	// for a set-point, app.G41V1 when the value is an integer that fits 32
	// bits and app.G41V3 otherwise.
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
// first such control; the statuses are returned as well. Controls are
// never repeated by WithRetry.
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
			if err != nil {
				return err
			}
			statuses, err = echoStatuses(hs, res)
			if err != nil {
				return err
			}
			if err := firstFailure(hs, statuses); err != nil {
				return err
			}
		}
		res, err := c.exchange(ctx, fc, hs)
		if err != nil {
			return err
		}
		statuses, err = echoStatuses(hs, res)
		if err != nil {
			return err
		}
		return firstFailure(hs, statuses)
	})
	return statuses, err
}

// echoStatuses checks that the response echoes the request and returns
// the status of each control.
func echoStatuses(req []app.Header, res *Result) ([]app.CommandStatus, error) {
	got := res.Headers()
	if len(got) != len(req) {
		return nil, fmt.Errorf("%w: control echo has %d headers, the request %d", dnp3.ErrProtocol, len(got), len(req))
	}
	var out []app.CommandStatus
	for i, h := range req {
		e := got[i]
		if e.GV != h.GV || len(e.Objects) != len(h.Objects) {
			return nil, fmt.Errorf("%w: control echo header %d is %s n=%d, the request %s n=%d",
				dnp3.ErrProtocol, i, e.GV, len(e.Objects), h.GV, len(h.Objects))
		}
		for j, o := range e.Objects {
			if o.Index != h.Objects[j].Index {
				return nil, fmt.Errorf("%w: control echo index %d, the request %d", dnp3.ErrProtocol, o.Index, h.Objects[j].Index)
			}
			switch v := o.Value.(type) {
			case app.CROB:
				r := h.Objects[j].Value.(app.CROB)
				r.Status = v.Status
				if r != v {
					return nil, fmt.Errorf("%w: control echo %s differs from the request", dnp3.ErrProtocol, v)
				}
				out = append(out, v.Status)
			case app.AnalogOutput:
				out = append(out, v.Status)
			default:
				return nil, fmt.Errorf("%w: control echo carries %T", dnp3.ErrProtocol, o.Value)
			}
		}
	}
	return out, nil
}

func firstFailure(hs []app.Header, statuses []app.CommandStatus) error {
	i := 0
	for _, h := range hs {
		for _, o := range h.Objects {
			if statuses[i] != app.StatusSuccess {
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

// SyncTime synchronizes the outstation's time with the given procedure:
// TimeSyncLAN (RECORD_CURRENT_TIME and g50v3) or TimeSyncNonLAN
// (DELAY_MEASURE and g50v1 corrected by half the round trip minus the
// outstation's processing delay).
func (c *Client) SyncTime(ctx context.Context, p TimeSync) error {
	return c.do(ctx, app.FuncWrite, true, func(ctx context.Context) error {
		switch p {
		case TimeSyncLAN:
			sent := time.Now()
			if _, err := c.exchange(ctx, app.FuncRecordCurrentTime, nil); err != nil {
				return err
			}
			_, err := c.exchange(ctx, app.FuncWrite, []app.Header{
				app.Counted(app.G50V3, app.AbsoluteTime{Time: app.TimestampOf(sent)})})
			return err
		case TimeSyncNonLAN:
			sent := time.Now()
			res, err := c.exchange(ctx, app.FuncDelayMeasure, nil)
			if err != nil {
				return err
			}
			rtt := time.Since(sent)
			var processing time.Duration
			for _, h := range res.Headers() {
				if h.GV == app.G52V2 && len(h.Objects) == 1 {
					processing = h.Objects[0].Value.(app.TimeDelay).Delay
				}
			}
			delay := max((rtt-processing)/2, 0)
			_, err = c.exchange(ctx, app.FuncWrite, []app.Header{
				app.Counted(app.G50V1, app.AbsoluteTime{Time: app.TimestampOf(time.Now().Add(delay))})})
			return err
		default:
			return fmt.Errorf("%w: time sync procedure %d", dnp3.ErrInvalidOption, p)
		}
	})
}

// DelayMeasure sends DELAY_MEASURE and returns the outstation's
// processing delay and the round trip time.
func (c *Client) DelayMeasure(ctx context.Context) (processing, roundTrip time.Duration, err error) {
	start := time.Now()
	res, err := c.request(ctx, app.FuncDelayMeasure, true)
	if err != nil {
		return 0, 0, err
	}
	roundTrip = time.Since(start)
	for _, h := range res.Headers() {
		if h.GV == app.G52V2 && len(h.Objects) == 1 {
			processing = h.Objects[0].Value.(app.TimeDelay).Delay
		}
	}
	return processing, roundTrip, nil
}

// ColdRestart asks the outstation for a cold restart and returns the time
// after which it can be polled again.
func (c *Client) ColdRestart(ctx context.Context) (time.Duration, error) {
	return c.restart(ctx, app.FuncColdRestart)
}

// WarmRestart asks the outstation for a warm restart and returns the time
// after which it can be polled again.
func (c *Client) WarmRestart(ctx context.Context) (time.Duration, error) {
	return c.restart(ctx, app.FuncWarmRestart)
}

func (c *Client) restart(ctx context.Context, fc app.FunctionCode) (time.Duration, error) {
	res, err := c.request(ctx, fc, false)
	if err != nil {
		return 0, err
	}
	for _, h := range res.Headers() {
		if (h.GV == app.G52V1 || h.GV == app.G52V2) && len(h.Objects) == 1 {
			return h.Objects[0].Value.(app.TimeDelay).Delay, nil
		}
	}
	return 0, fmt.Errorf("%w: restart response without a time delay object", dnp3.ErrProtocol)
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
// example AssignClass(ctx, 2, app.AllObjects(app.G30V0)).
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
// interval (zero for once).
func (c *Client) FreezeAtTime(ctx context.Context, at time.Time, interval time.Duration, headers ...app.Header) error {
	hs := append([]app.Header{app.Counted(app.G50V2, app.AbsoluteTime{Time: app.TimestampOf(at), Interval: uint32(interval.Milliseconds())})}, headers...)
	_, err := c.request(ctx, app.FuncFreezeAtTime, false, hs...)
	return err
}

// ClearRestart clears IIN1.7 (DEVICE_RESTART) by writing g80v1 index 7.
func (c *Client) ClearRestart(ctx context.Context) error {
	_, err := c.Write(ctx, app.Header{GV: app.G80V1, Qualifier: app.Qual1ByteStartStop,
		Objects: []app.Object{{Index: app.IINBit(app.IINDeviceRestart), Value: app.Binary{}}}})
	return err
}

// ReadAttributes reads device attributes of set 0: one variation (for
// example app.AttrManufacturerName), app.AttrAllAttributes or
// app.AttrListOfVariations. The result maps variations to values.
func (c *Client) ReadAttributes(ctx context.Context, variation uint8) (map[uint8]app.Attribute, error) {
	res, err := c.Read(ctx, app.IndexRange(app.GV(0, variation), 0, 0))
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
	_, err := c.Write(ctx, app.Ranged(app.GV(0, variation), 0, a))
	return err
}

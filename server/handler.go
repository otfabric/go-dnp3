// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// OperateType says how a control reached the outstation.
type OperateType uint8

// Operate types.
const (
	// SelectBeforeOperate: the OPERATE of a select-before-operate pair.
	SelectBeforeOperate OperateType = iota
	// DirectOperate: DIRECT_OPERATE, answered with the status.
	DirectOperate
	// DirectOperateNoAck: DIRECT_OPERATE_NR, not answered.
	DirectOperateNoAck
)

// String returns "select-before-operate", "direct-operate" or
// "direct-operate-no-ack".
func (o OperateType) String() string {
	switch o {
	case SelectBeforeOperate:
		return "select-before-operate"
	case DirectOperate:
		return "direct-operate"
	default:
		return "direct-operate-no-ack"
	}
}

// Command is one control a master sent.
type Command struct {
	// GV is the object of the control: app.G12V1 (control relay output
	// block), app.G12V2 (pattern control block) or app.G41V1..app.G41V4
	// (analog output block).
	GV app.GroupVariation
	// Index is the point index.
	Index uint32
	// Value is an app.CROB or an app.AnalogOutput. Its Status field is
	// zero: a control whose request carries another status is answered
	// with FORMAT_ERROR without calling the Handler (TB2014-002).
	Value app.Value
	// Master is the link address of the master that sent the control.
	Master link.Address
}

// Handler executes controls. Its methods are called on the goroutine of
// the master's association, one request at a time per master; a slow
// handler delays that master's requests, not the others'.
//
// The returned status is echoed to the master. A handler that does not
// support a point returns app.StatusNotSupported; the response then also
// sets IIN2.2 (PARAMETER_ERROR).
type Handler interface {
	// Select checks whether the control could be executed now, without
	// executing it.
	Select(ctx context.Context, c Command) app.CommandStatus

	// Operate executes the control.
	Operate(ctx context.Context, c Command, op OperateType) app.CommandStatus
}

// NopHandler is a [Handler] that supports no control. Embed it in your
// own type to implement the optional handler interfaces only.
type NopHandler struct{}

// Select returns app.StatusNotSupported.
func (NopHandler) Select(context.Context, Command) app.CommandStatus { return app.StatusNotSupported }

// Operate returns app.StatusNotSupported.
func (NopHandler) Operate(context.Context, Command, OperateType) app.CommandStatus {
	return app.StatusNotSupported
}

// HandlerFunc adapts a function to a [Handler] that executes direct
// operates and select-before-operate pairs alike: Select returns success
// for every control the function would be called with, Operate calls it.
type HandlerFunc func(ctx context.Context, c Command, op OperateType) app.CommandStatus

// Select returns app.StatusSuccess.
func (HandlerFunc) Select(context.Context, Command) app.CommandStatus { return app.StatusSuccess }

// Operate calls f.
func (f HandlerFunc) Operate(ctx context.Context, c Command, op OperateType) app.CommandStatus {
	return f(ctx, c, op)
}

// RestartHandler is an optional interface of the [Handler]: without it,
// COLD_RESTART and WARM_RESTART are answered with IIN2.0
// (NO_FUNC_CODE_SUPPORT).
type RestartHandler interface {
	// Restart schedules a restart and returns the time after which the
	// master may poll again. The outstation answers before the restart
	// takes place; restarting the process (or calling Server.Restart) is
	// up to the handler. A non-nil error refuses the restart.
	Restart(ctx context.Context, cold bool) (time.Duration, error)
}

// TimeHandler is an optional interface of the [Handler]. The outstation
// keeps its own clock, set by time synchronization; a TimeHandler is told
// of every synchronization as well, for example to set the device clock.
type TimeHandler interface {
	SetTime(ctx context.Context, t time.Time)
}

// ApplicationHandler is an optional interface of the [Handler] for the
// function codes that act on the outstation's applications:
// INITIALIZE_DATA, INITIALIZE_APPL, START_APPL, STOP_APPL, SAVE_CONFIG and
// ACTIVATE_CONFIG. It returns the IIN2 error bits of the response; 0 is
// success. Without it these functions are answered with IIN2.0.
type ApplicationHandler interface {
	Application(ctx context.Context, fc app.FunctionCode, headers []app.Header) app.IIN
}

// AttributeSetWriteHandler is an optional interface of the [Handler]: it is
// told of a write of a writable device attribute of a set of
// WithAttributeSet before the outstation stores it, and refuses it with an
// error (answered with PARAMETER_ERROR).
type AttributeSetWriteHandler interface {
	WriteAttributeSet(ctx context.Context, set uint16, variation uint8, a app.Attribute) error
}

// WriteHandler is an optional interface of the [Handler] for WRITE
// requests on objects the outstation does not handle itself: device
// attributes (group 0) and octet strings (group 110). The outstation
// stores a written octet string in its database before it calls
// WriteOctetString. Errors are answered with IIN2.2 (PARAMETER_ERROR).
type WriteHandler interface {
	WriteAttribute(ctx context.Context, variation uint8, a app.Attribute) error
	WriteOctetString(ctx context.Context, index uint32, data []byte) error
}

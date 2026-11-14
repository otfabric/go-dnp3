// SPDX-License-Identifier: MIT

package logx

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

type contextKey struct{}

// NewContext returns ctx carrying l, for code the library calls with a
// context, such as a stream opener, to log through.
func NewContext(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, l)
}

// FromContext returns the logger of NewContext, or nil.
func FromContext(ctx context.Context) *Logger {
	l, _ := ctx.Value(contextKey{}).(*Logger)
	return l
}

// msgFailed is the message of the entry that reports a call of the
// application's code that did not return normally.
const msgFailed = "callback did not return normally"

// CallbackError is the error of a call of the application's code that did
// not return normally.
type CallbackError struct {
	// Callback names what was called, for example "Dialer.DialContext".
	Callback string
	// Value is the value the call ended with.
	Value any
}

// Error describes the call, for example
// "Dialer.DialContext did not return normally: no route".
func (e *CallbackError) Error() string {
	return fmt.Sprintf("%s did not return normally: %v", e.Callback, e.Value)
}

// Run calls f, the application's code that callback names, and returns
// nil. When f does not return normally, Run logs that at error level with
// the value and the stack, through l, and returns a *CallbackError.
func Run(l *Logger, callback string, f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = l.recovered(callback, r)
		}
	}()
	f()
	return nil
}

// Do is Run for a call that returns an error.
func Do(l *Logger, callback string, f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = l.recovered(callback, r)
		}
	}()
	return f()
}

// Call is Run for a call that returns a value and an error: one that does
// not return normally gives the zero value and the *CallbackError.
func Call[T any](l *Logger, callback string, f func() (T, error)) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			v, err = zero, l.recovered(callback, r)
		}
	}()
	return f()
}

// Failure is a call of the application's code that did not return
// normally, kept to be logged by Report once the caller released its locks.
type Failure struct {
	err   *CallbackError
	stack string
}

// Try is Do for a caller that holds a lock: it does not log. When f does
// not return normally, Try returns the Failure to give to Report after the
// lock is released, and its *CallbackError; else nil and f's error.
func Try(callback string, f func() error) (fail *Failure, err error) {
	defer func() {
		if r := recover(); r != nil {
			ce := &CallbackError{Callback: callback, Value: r}
			fail, err = &Failure{err: ce, stack: string(debug.Stack())}, ce
		}
	}()
	return nil, f()
}

// Report logs fail, as Do logs a call that did not return normally; a nil
// fail logs nothing.
func (l *Logger) Report(fail *Failure) {
	if fail != nil {
		l.Error(msgFailed, "callback", fail.err.Callback, "value", fail.err.Value, "stack", fail.stack)
	}
}

// recovered logs a call of callback that ended with r and returns its
// error.
func (l *Logger) recovered(callback string, r any) error {
	l.Error(msgFailed, "callback", callback, "value", r, "stack", string(debug.Stack()))
	return &CallbackError{Callback: callback, Value: r}
}

// rescueCall is deferred by the guarded metrics: a callback that does not
// return normally is logged, and the library goes on as if it had
// returned.
func (l *Logger) rescueCall(callback string) {
	if r := recover(); r != nil {
		_ = l.recovered(callback, r)
	}
}

// Metrics returns m with every callback guarded: one that does not return
// normally is logged through l with its stack, and the protocol goes on as
// if it had returned. A nil m stays nil.
func Metrics(m dnp3.Metrics, l *Logger) dnp3.Metrics {
	if m == nil {
		return nil
	}
	return metrics{m: m, l: l}
}

type metrics struct {
	m dnp3.Metrics
	l *Logger
}

func (g metrics) OnConnect(remote net.Addr) {
	defer g.l.rescueCall("Metrics.OnConnect")
	g.m.OnConnect(remote)
}

func (g metrics) OnDisconnect(remote net.Addr, err error) {
	defer g.l.rescueCall("Metrics.OnDisconnect")
	g.m.OnDisconnect(remote, err)
}

func (g metrics) OnFrameSent(remote net.Addr, f *link.Frame, size int) {
	defer g.l.rescueCall("Metrics.OnFrameSent")
	g.m.OnFrameSent(remote, f, size)
}

func (g metrics) OnFrameReceived(remote net.Addr, f *link.Frame, size int) {
	defer g.l.rescueCall("Metrics.OnFrameReceived")
	g.m.OnFrameReceived(remote, f, size)
}

func (g metrics) OnFramingError(remote net.Addr, err error) {
	defer g.l.rescueCall("Metrics.OnFramingError")
	g.m.OnFramingError(remote, err)
}

func (g metrics) OnFragmentSent(remote net.Addr, f *app.Fragment, size int) {
	defer g.l.rescueCall("Metrics.OnFragmentSent")
	g.m.OnFragmentSent(remote, f, size)
}

func (g metrics) OnFragmentReceived(remote net.Addr, f *app.Fragment, size int) {
	defer g.l.rescueCall("Metrics.OnFragmentReceived")
	g.m.OnFragmentReceived(remote, f, size)
}

func (g metrics) OnDecodeError(remote net.Addr, err error) {
	defer g.l.rescueCall("Metrics.OnDecodeError")
	g.m.OnDecodeError(remote, err)
}

// RequestMetrics is Metrics for a dnp3.RequestMetrics.
func RequestMetrics(m dnp3.RequestMetrics, l *Logger) dnp3.RequestMetrics {
	if m == nil {
		return nil
	}
	return requestMetrics{m: m, l: l}
}

type requestMetrics struct {
	m dnp3.RequestMetrics
	l *Logger
}

func (g requestMetrics) OnRequest(remote net.Addr, outstation uint16, fc app.FunctionCode) {
	defer g.l.rescueCall("RequestMetrics.OnRequest")
	g.m.OnRequest(remote, outstation, fc)
}

func (g requestMetrics) OnRequestDone(remote net.Addr, outstation uint16, fc app.FunctionCode, d time.Duration, err error) {
	defer g.l.rescueCall("RequestMetrics.OnRequestDone")
	g.m.OnRequestDone(remote, outstation, fc, d, err)
}

func (g requestMetrics) OnRetry(remote net.Addr, outstation uint16, fc app.FunctionCode, attempt int, err error) {
	defer g.l.rescueCall("RequestMetrics.OnRetry")
	g.m.OnRetry(remote, outstation, fc, attempt, err)
}

// ClientMetrics is Metrics for a dnp3.ClientMetrics.
func ClientMetrics(m dnp3.ClientMetrics, l *Logger) dnp3.ClientMetrics {
	if m == nil {
		return nil
	}
	return clientMetrics{m: m, l: l}
}

type clientMetrics struct {
	m dnp3.ClientMetrics
	l *Logger
}

func (g clientMetrics) OnTaskDropped(name string) {
	defer g.l.rescueCall("ClientMetrics.OnTaskDropped")
	g.m.OnTaskDropped(name)
}

func (g clientMetrics) OnLateResponse(remote net.Addr, fc app.FunctionCode) {
	defer g.l.rescueCall("ClientMetrics.OnLateResponse")
	g.m.OnLateResponse(remote, fc)
}

// ServerMetrics is Metrics for a dnp3.ServerMetrics.
func ServerMetrics(m dnp3.ServerMetrics, l *Logger) dnp3.ServerMetrics {
	if m == nil {
		return nil
	}
	return serverMetrics{m: m, l: l}
}

type serverMetrics struct {
	m dnp3.ServerMetrics
	l *Logger
}

func (g serverMetrics) OnHandled(remote net.Addr, fc app.FunctionCode, d time.Duration) {
	defer g.l.rescueCall("ServerMetrics.OnHandled")
	g.m.OnHandled(remote, fc, d)
}

func (g serverMetrics) OnEventsDiscarded(class int, n int) {
	defer g.l.rescueCall("ServerMetrics.OnEventsDiscarded")
	g.m.OnEventsDiscarded(class, n)
}

func (g serverMetrics) OnUnsolicited(remote net.Addr, events int, err error) {
	defer g.l.rescueCall("ServerMetrics.OnUnsolicited")
	g.m.OnUnsolicited(remote, events, err)
}

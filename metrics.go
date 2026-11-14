// SPDX-License-Identifier: MIT

package dnp3

import (
	"net"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Metrics is an optional callback interface for observing the channels and
// the traffic of a client or a server. A nil Metrics disables collection.
//
// The methods are called synchronously on the protocol path, possibly from
// several goroutines at once; implementations must be safe for concurrent
// use and must not block (increment a counter, send on a buffered
// channel). Frames and fragments passed to them must not be retained or
// modified. A method that does not return normally is logged with its
// stack, at error level, and the protocol goes on as if it had returned.
//
// Embed [NopMetrics] to implement only the callbacks you need and to stay
// compatible when methods are added.
type Metrics interface {
	// OnConnect is called when a transport connection is established or
	// a serial port opened.
	OnConnect(remote net.Addr)

	// OnDisconnect is called when a channel ends. err is nil when the
	// application closed it.
	OnDisconnect(remote net.Addr, err error)

	// OnFrameSent is called after a link frame was written. size is its
	// length on the wire in octets.
	OnFrameSent(remote net.Addr, f *link.Frame, size int)

	// OnFrameReceived is called for every link frame read from the peer.
	OnFrameReceived(remote net.Addr, f *link.Frame, size int)

	// OnFramingError is called when octets were skipped or a frame was
	// discarded: a bad start sequence, a CRC error, an invalid length.
	OnFramingError(remote net.Addr, err error)

	// OnFragmentSent is called after an application fragment was handed
	// to the transport function. size is its length in octets.
	OnFragmentSent(remote net.Addr, f *app.Fragment, size int)

	// OnFragmentReceived is called for every fragment that was
	// reassembled and decoded.
	OnFragmentReceived(remote net.Addr, f *app.Fragment, size int)

	// OnDecodeError is called when a reassembled fragment, or a segment,
	// could not be decoded and was dropped.
	OnDecodeError(remote net.Addr, err error)
}

// NopMetrics is a [Metrics] that does nothing. Embed it in your own type.
type NopMetrics struct{}

// OnConnect does nothing.
func (NopMetrics) OnConnect(net.Addr) {}

// OnDisconnect does nothing.
func (NopMetrics) OnDisconnect(net.Addr, error) {}

// OnFrameSent does nothing.
func (NopMetrics) OnFrameSent(net.Addr, *link.Frame, int) {}

// OnFrameReceived does nothing.
func (NopMetrics) OnFrameReceived(net.Addr, *link.Frame, int) {}

// OnFramingError does nothing.
func (NopMetrics) OnFramingError(net.Addr, error) {}

// OnFragmentSent does nothing.
func (NopMetrics) OnFragmentSent(net.Addr, *app.Fragment, int) {}

// OnFragmentReceived does nothing.
func (NopMetrics) OnFragmentReceived(net.Addr, *app.Fragment, int) {}

// OnDecodeError does nothing.
func (NopMetrics) OnDecodeError(net.Addr, error) {}

// RequestMetrics is an optional extension of [Metrics] for a client. When
// the value given to client.WithMetrics also implements it, the client
// reports every request: polls, commands, time synchronization, file
// operations.
//
// OnRequest fires once before the first attempt and OnRequestDone once
// with the final outcome, whose duration includes retries and their
// delays. OnRetry fires for each attempt that failed and will be repeated.
//
// remote is the address of the channel, or nil while the client has never
// been connected. outstation is the link address of the outstation.
type RequestMetrics interface {
	// OnRequest is called before a request is sent.
	OnRequest(remote net.Addr, outstation uint16, fc app.FunctionCode)

	// OnRequestDone is called with the final outcome. err is nil on
	// success; classify failures with errors.Is and errors.As
	// (*IINError, *CommandError, ErrTimeout, ...).
	OnRequestDone(remote net.Addr, outstation uint16, fc app.FunctionCode, duration time.Duration, err error)

	// OnRetry is called when attempt (1 for the first) failed with err and
	// the request is about to be tried again.
	OnRetry(remote net.Addr, outstation uint16, fc app.FunctionCode, attempt int, err error)
}

// ClientMetrics is an optional extension of [Metrics] for a client. When
// the value given to client.WithMetrics also implements it, the client
// reports the work it drops: automatic tasks that found the task queue
// full, and responses that came too late for their request. Both were
// logged at debug level only before.
type ClientMetrics interface {
	// OnTaskDropped is called when an automatic task was not queued
	// because the client's task queue (8 tasks) was full. name is the
	// task: "restart", "time-sync", "integrity", "event-poll",
	// "key-change", or "poll-<n>" for the n-th client.WithPoll, counted
	// from 0. It is called after the client released its task queue, so
	// it may call into the client.
	OnTaskDropped(name string)

	// OnLateResponse is called for each response fragment the client
	// discards because no request waits for it (IEEE 1815-2012 Table 6-2
	// row 1: its request timed out, was canceled or was abandoned), also
	// one that reached a request that ended before it took it, or because
	// it is not the first fragment of the response the request in
	// progress awaits: another sequence number, or no FIR (rows 3 and 5).
	// fc is the fragment's function code: app.FuncResponse, or
	// app.FuncAuthResponse with secure authentication.
	OnLateResponse(remote net.Addr, fc app.FunctionCode)
}

// ServerMetrics is an optional extension of [Metrics] for a server. When
// the value given to server.WithMetrics also implements it, the server
// reports every request it handled and every event it had to discard.
type ServerMetrics interface {
	// OnHandled is called after a request was handled, with the time
	// from its reception to the end of the handler calls.
	OnHandled(remote net.Addr, fc app.FunctionCode, duration time.Duration)

	// OnEventsDiscarded is called when an event buffer overflowed and n
	// events of the class (1..3) were discarded.
	OnEventsDiscarded(class int, n int)

	// OnUnsolicited is called after an unsolicited response was confirmed
	// (err == nil) or abandoned.
	OnUnsolicited(remote net.Addr, events int, err error)
}

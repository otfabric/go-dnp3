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
// modified.
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

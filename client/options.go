// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/transport"
)

// Option configures a [Client].
type Option func(*options) error

// Dialer opens TCP connections; *net.Dialer satisfies it.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// StreamOpener opens a byte stream that is not a TCP connection, for
// example a serial port. remote names the stream in logs and metrics and
// may be nil.
type StreamOpener func(ctx context.Context) (stream io.ReadWriteCloser, remote net.Addr, err error)

// Reconnect configures automatic reconnection with exponential backoff.
type Reconnect struct {
	// MinDelay is the delay before the first attempt; it doubles after
	// each failure. Zero means 1 second.
	MinDelay time.Duration
	// MaxDelay caps the delay. Zero means 1 minute.
	MaxDelay time.Duration
}

// Retry configures automatic retries of the requests that are safe to
// repeat: READ, the time and unsolicited functions, ASSIGN_CLASS and the
// file read functions. Controls, freezes, restarts and writes are never
// repeated.
type Retry struct {
	// Attempts is the total number of attempts, at least 1.
	Attempts int
	// Backoff is the pause after the first failed attempt; it doubles
	// after each further one. Zero means 500 ms.
	Backoff time.Duration
	// MaxBackoff caps the pause. Zero means 10 seconds.
	MaxBackoff time.Duration
}

// Link configures the data link layer.
type Link struct {
	// Confirmed sends user data as CONFIRMED_USER_DATA. The default,
	// unconfirmed, is what IEEE 1815-2012 recommends on TCP.
	Confirmed bool
	// Timeout is the wait for a link layer answer. Zero means 2 seconds.
	Timeout time.Duration
	// Retries is the number of repeats of an unanswered primary frame.
	Retries int
	// KeepAlive is the idle time after which REQUEST_LINK_STATUS is sent.
	// Zero means 60 seconds; a negative value disables it.
	KeepAlive time.Duration
}

// Startup configures what the client does each time the channel is
// established, before Connect returns. A step the outstation rejects (an
// IINError, such as IIN2.0 from an outstation without unsolicited
// responses) is logged and the sequence goes on; a step without a valid
// response fails it.
type Startup struct {
	// DisableUnsolicited sends DISABLE_UNSOLICITED for classes 1..3 first.
	DisableUnsolicited bool
	// Integrity runs an integrity poll. When the outstation has asked for
	// the time (NEED_TIME) and WithTimeSync is set, the time is
	// synchronized first, so that the poll's events carry synchronized time.
	Integrity bool
	// EnableUnsolicited sends ENABLE_UNSOLICITED for these classes last.
	EnableUnsolicited []int
}

// TimeSync selects the time synchronization procedure.
type TimeSync uint8

// Time synchronization procedures (IEEE 1815-2012 clause 5.2).
const (
	// TimeSyncNone disables automatic time synchronization.
	TimeSyncNone TimeSync = iota
	// TimeSyncLAN is the LAN procedure: RECORD_CURRENT_TIME, then a
	// WRITE of the time of that request (g50v3).
	TimeSyncLAN
	// TimeSyncNonLAN is the serial procedure: DELAY_MEASURE, then a WRITE
	// of the current time corrected by the measured delay (g50v1).
	TimeSyncNonLAN
)

// Poll is a request the client repeats on its own.
type Poll struct {
	// Interval between the end of one poll and the start of the next.
	Interval time.Duration
	// Headers are the headers of the READ, for example
	// app.ClassHeaders(1, 2, 3).
	Headers []app.Header
}

type options struct {
	local, remote    link.Address
	handler          Handler
	stateHandler     func(dnp3.State, error)
	logger           dnp3.Logger
	metrics          dnp3.Metrics
	dialer           Dialer
	opener           StreamOpener
	tls              *tls.Config
	reconnect        *Reconnect
	retry            *Retry
	responseTimeout  time.Duration
	maxRxFragment    int
	link             Link
	startup          Startup
	timeSync         TimeSync
	autoClearRestart bool
	autoEventPoll    bool
	autoIntegrity    bool
	polls            []Poll
	queueLimit       int
	auth             *secauth.User
	keyChange        time.Duration
	aggressive       []app.FunctionCode
}

func defaultOptions() options {
	return options{
		local:            1,
		remote:           10,
		dialer:           &net.Dialer{Timeout: dialTimeout},
		responseTimeout:  5 * time.Second,
		maxRxFragment:    transport.DefaultMaxFragment,
		autoClearRestart: true,
		autoIntegrity:    true,
		queueLimit:       64,
		keyChange:        15 * time.Minute,
	}
}

func invalidOption(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{dnp3.ErrInvalidOption}, args...)...)
}

// WithAddresses sets the link addresses of the master (local) and of the
// outstation (remote). The defaults are 1 and 10.
func WithAddresses(local, remote link.Address) Option {
	return func(o *options) error {
		if local > link.MaxStationAddress || remote > link.MaxStationAddress {
			return invalidOption("addresses %d/%d", local, remote)
		}
		o.local, o.remote = local, remote
		return nil
	}
}

// WithHandler sets the handler that receives the measurements of every
// response and unsolicited response.
func WithHandler(h Handler) Option {
	return func(o *options) error { o.handler = h; return nil }
}

// WithStateHandler sets a function called on every change of the channel
// state, with the error that caused it (nil when the application closed
// the client).
func WithStateHandler(f func(state dnp3.State, err error)) Option {
	return func(o *options) error { o.stateHandler = f; return nil }
}

// WithLogger sets the logger; logging is silent by default.
func WithLogger(l dnp3.Logger) Option {
	return func(o *options) error { o.logger = l; return nil }
}

// WithMetrics sets the metrics callbacks. A value that also implements
// dnp3.RequestMetrics receives the request-level callbacks.
func WithMetrics(m dnp3.Metrics) Option {
	return func(o *options) error { o.metrics = m; return nil }
}

// WithDialer sets the dialer of TCP connections.
func WithDialer(d Dialer) Option {
	return func(o *options) error {
		if d == nil {
			return invalidOption("nil dialer")
		}
		o.dialer = d
		return nil
	}
}

// WithStream makes the client run over the streams open returns, for
// example a serial port, instead of dialing TCP. The address given to New
// is then only a name.
func WithStream(open StreamOpener) Option {
	return func(o *options) error {
		if open == nil {
			return invalidOption("nil stream opener")
		}
		o.opener = open
		return nil
	}
}

// WithTLS connects with TLS (IEEE 1815-2012 Annex B / IEC 62351-3).
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) error { o.tls = cfg; return nil }
}

// WithReconnect makes the client re-establish a lost channel by itself.
func WithReconnect(r Reconnect) Option {
	return func(o *options) error {
		if r.MinDelay <= 0 {
			r.MinDelay = time.Second
		}
		if r.MaxDelay <= 0 {
			r.MaxDelay = time.Minute
		}
		if r.MaxDelay < r.MinDelay {
			return invalidOption("reconnect max delay %v below min delay %v", r.MaxDelay, r.MinDelay)
		}
		o.reconnect = &r
		return nil
	}
}

// WithRetry enables retries of the requests that are safe to repeat.
func WithRetry(r Retry) Option {
	return func(o *options) error {
		if r.Attempts < 1 {
			return invalidOption("retry attempts %d", r.Attempts)
		}
		if r.Backoff <= 0 {
			r.Backoff = 500 * time.Millisecond
		}
		if r.MaxBackoff <= 0 {
			r.MaxBackoff = 10 * time.Second
		}
		o.retry = &r
		return nil
	}
}

// WithResponseTimeout sets how long the client waits for each fragment of
// a response. The default is 5 seconds.
func WithResponseTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalidOption("response timeout %v", d)
		}
		o.responseTimeout = d
		return nil
	}
}

// WithMaxFragment sets the largest fragment the client reassembles. The
// default is 2048.
func WithMaxFragment(n int) Option {
	return func(o *options) error {
		if n < 249 {
			return invalidOption("max fragment %d below 249", n)
		}
		o.maxRxFragment = n
		return nil
	}
}

// WithLink configures the data link layer.
func WithLink(l Link) Option {
	return func(o *options) error { o.link = l; return nil }
}

// WithStartup sets what the client does each time the channel is
// established.
func WithStartup(s Startup) Option {
	return func(o *options) error {
		for _, c := range s.EnableUnsolicited {
			if c < 1 || c > 3 {
				return invalidOption("unsolicited class %d", c)
			}
		}
		o.startup = s
		return nil
	}
}

// WithTimeSync makes the client synchronize the outstation's time with
// the given procedure whenever the outstation reports IIN1.4 (NEED_TIME).
func WithTimeSync(p TimeSync) Option {
	return func(o *options) error { o.timeSync = p; return nil }
}

// WithAutoClearRestart controls whether the client clears IIN1.7
// (DEVICE_RESTART) when the outstation reports it. It is on by default.
func WithAutoClearRestart(enabled bool) Option {
	return func(o *options) error { o.autoClearRestart = enabled; return nil }
}

// WithAutoEventPoll makes the client poll the classes the outstation
// reports events for (IIN1.1..1.3).
func WithAutoEventPoll(enabled bool) Option {
	return func(o *options) error { o.autoEventPoll = enabled; return nil }
}

// WithAutoIntegrity controls whether the client runs an integrity poll
// when the outstation reports a restart or an event buffer overflow. It is
// on by default.
func WithAutoIntegrity(enabled bool) Option {
	return func(o *options) error { o.autoIntegrity = enabled; return nil }
}

// WithPoll adds a periodic READ.
func WithPoll(p Poll) Option {
	return func(o *options) error {
		if p.Interval <= 0 || len(p.Headers) == 0 {
			return invalidOption("poll every %v with %d headers", p.Interval, len(p.Headers))
		}
		o.polls = append(o.polls, p)
		return nil
	}
}

// WithQueueLimit sets how many requests may wait for their turn: DNP3
// allows one outstanding request per association. Further requests fail
// with dnp3.ErrBusy. The default is 64.
func WithQueueLimit(n int) Option {
	return func(o *options) error {
		if n < 1 {
			return invalidOption("queue limit %d", n)
		}
		o.queueLimit = n
		return nil
	}
}

// WithSecureAuthentication enables Secure Authentication version 5: the
// client answers the outstation's challenges of critical requests. With an
// update key in u it first runs the session key change on every
// connection, and again at the key change interval; with only a session
// key it uses that key directly. Without this option a challenge fails the
// request with dnp3.ErrAuthentication.
func WithSecureAuthentication(u secauth.User) Option {
	return func(o *options) error {
		if err := u.Validate(); err != nil {
			return invalidOption("%v", err)
		}
		o.auth = &u
		return nil
	}
}

// WithAggressiveMode sends the requests with the function codes fcs
// (secauth.DefaultCritical when none are given) in Secure Authentication
// aggressive mode (IEEE 1815-2012 clause 7.5.2.2.4): with a MAC in the
// request itself, so that the outstation executes it without a challenge.
// The MAC covers the last challenge received, so the first critical
// request of a connection is still challenged. Use it only with an
// outstation that supports aggressive mode: one that does not refuses the
// request with an authentication error. New refuses it without
// WithSecureAuthentication.
func WithAggressiveMode(fcs ...app.FunctionCode) Option {
	return func(o *options) error {
		if len(fcs) == 0 {
			fcs = secauth.DefaultCritical
		}
		o.aggressive = fcs
		return nil
	}
}

// WithKeyChangeInterval sets how often the session keys are changed while
// connected, with an update key. The default is 15 minutes.
func WithKeyChangeInterval(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalidOption("key change interval %v", d)
		}
		o.keyChange = d
		return nil
	}
}

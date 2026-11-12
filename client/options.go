// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/transport"
)

// Option configures a [Client].
type Option func(*options) error

// Dialer opens TCP connections; *net.Dialer satisfies it, as does a
// proxy's or a jump host's DialContext.
//
// Like net.Dialer, a Dialer returns a non-nil connection exactly when the
// error is nil: one that returns neither fails the dial, and a connection
// returned together with an error is closed. Its error reaches the caller
// wrapped in dnp3.ErrConnectFailed, so errors.Is finds the dialer's own
// sentinels. It must honour ctx: the context of Connect (or Dial), with
// the caller's deadline and cancel, and on a reconnect one that ends with
// the attempt or Close; ctx also carries the dial timeout of 10 seconds.
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
	// Jitter randomizes each delay, so that masters that lost their
	// channels together do not reconnect together: a fraction from 0 to 1,
	// each delay is drawn uniformly from [(1-Jitter)·d, d] of the delay d
	// that doubles. Zero, the default, waits d exactly.
	Jitter float64
}

// Retry configures automatic retries of the requests that are safe to
// repeat: READ, the time and unsolicited functions, ASSIGN_CLASS and the
// file read functions. Controls, freezes, restarts and writes are never
// repeated. Each repeat is a new request with the next sequence number
// (IEEE 1815-2012 clause 4.3 Rule 14), never an application layer retry of
// the same octets: a repeated time synchronization starts its procedure
// again with fresh times, as clause 10.3.4.1 requires.
type Retry struct {
	// Attempts is the total number of attempts, at least 1.
	Attempts int
	// Backoff is the pause after the first failed attempt; it doubles
	// after each further one. Zero means 500 ms.
	Backoff time.Duration
	// MaxBackoff caps the pause. Zero means 10 seconds.
	MaxBackoff time.Duration
	// Jitter randomizes each pause: a fraction from 0 to 1, each pause is
	// drawn uniformly from [(1-Jitter)·d, d] of the pause d that doubles.
	// Zero, the default, pauses d exactly.
	Jitter float64
}

// Link configures the data link layer.
type Link struct {
	// Confirmed sends user data as CONFIRMED_USER_DATA. Set it on serial
	// links only: IEEE 1815-2012 clause 13.2.1.1 forbids confirmed link
	// frames over TCP and UDP, and a channel on a network stream with it
	// logs a warning. The default is UNCONFIRMED_USER_DATA. Time
	// synchronization requests (DELAY_MEASURE, RECORD_CURRENT_TIME and a
	// WRITE of g50v1 or g50v3) always go as UNCONFIRMED_USER_DATA, without
	// link layer retries (IEEE 1815-2012 clause 10.3.4.1).
	Confirmed bool
	// Timeout is the wait for a link layer answer. Zero means 2 seconds.
	Timeout time.Duration
	// Retries is the number of repeats of an unanswered primary frame.
	Retries int
	// KeepAlive is the idle time after which REQUEST_LINK_STATUS is sent
	// (the keep-alive of IEEE 1815-2012 clause 13.2.3.3.1); a peer that
	// does not answer it ends the connection. Zero means 60 seconds; any
	// positive duration is taken. A negative value disables it, which the
	// clause allows for testing only: in service, set a long interval
	// instead.
	KeepAlive time.Duration
}

// Startup configures what the client does each time the channel is
// established, before Connect returns: the master startup of IEEE
// 1815-2012 clause 5.1.1.2. With secure authentication and an update key
// the session keys are changed first. A step the outstation rejects (an
// IINError, such as IIN2.0 from an outstation without unsolicited
// responses) is logged and the sequence goes on; a step without a valid
// response fails it.
//
// The default is Startup{Integrity: true}: clause 5.1.1.2 Rule 1 requires
// an integrity poll at master startup. WithStartup(Startup{}) runs nothing.
type Startup struct {
	// DisableUnsolicited sends DISABLE_UNSOLICITED for classes 1..3 first.
	DisableUnsolicited bool
	// Integrity runs an integrity poll. When the outstation has asked for
	// the time (NEED_TIME) and automatic time synchronization is on, the
	// time is synchronized first, so that the poll's events carry
	// synchronized time.
	Integrity bool
	// EnableUnsolicited sends ENABLE_UNSOLICITED for these classes last.
	// WithStartup then also sets DisableUnsolicited and Integrity, the
	// steps clause 5.1.1.2 Rule 1 requires before it. The classes are
	// enabled again whenever the outstation reports a restart (IIN1.7,
	// clause 5.1.1.1.2 Rule 2).
	EnableUnsolicited []int
}

// TimeSync selects the time synchronization procedure.
type TimeSync uint8

// Time synchronization procedures (IEEE 1815-2012 clause 10.3.3).
const (
	// TimeSyncNone disables automatic time synchronization.
	TimeSyncNone TimeSync = iota
	// TimeSyncLAN is the LAN procedure (clause 10.3.3.2):
	// RECORD_CURRENT_TIME, then a WRITE of the time of that request
	// (g50v3). Its function and object are of subset level 4 (IEEE
	// 1815-2012 Table 12-32); outstations of levels 1 to 3 need not
	// support them.
	TimeSyncLAN
	// TimeSyncNonLAN is the non-LAN procedure (clause 10.3.3.1):
	// DELAY_MEASURE, then a WRITE of the current time corrected by the
	// measured delay (g50v1). It is within subset level 1.
	TimeSyncNonLAN
	// TimeSyncClearNeedTime does not synchronize the time: it clears
	// IIN1.4 (NEED_TIME) with a WRITE of g80v1 index 4, as IEEE 1815-2012
	// clause 4.5.5 recommends where timekeeping is not required.
	TimeSyncClearNeedTime
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
	maxTxFragment    int // 0: unlimited
	timeSyncSet      bool
	link             Link
	startup          Startup
	timeSync         TimeSync
	autoClearRestart bool
	autoEventPoll    bool
	autoIntegrity    bool
	noSolConfirm     bool
	noUnsConfirm     bool
	polls            []Poll
	queueLimit       int
	auth             *secauth.User
	keyChange        time.Duration
	keyChangeCount   uint32
	aggressive       []app.FunctionCode
	challengeMACs    []app.MACAlgorithm
	dualListener     net.Listener
	dualAllow        func(net.Addr) bool
}

func defaultOptions() options {
	return options{
		local:            1,
		remote:           10,
		dialer:           &net.Dialer{Timeout: dialTimeout},
		responseTimeout:  5 * time.Second,
		maxRxFragment:    transport.DefaultMaxFragment,
		startup:          Startup{Integrity: true},
		autoClearRestart: true,
		autoIntegrity:    true,
		queueLimit:       64,
		keyChange:        15 * time.Minute,
		keyChangeCount:   DefaultKeyChangeCount,
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

// WithDialer sets the dialer of TCP connections: it is called with
// network "tcp" and the address given to New, for Connect, the
// reconnects of WithReconnect and the client's own connections of the
// dual end point (WithDualEndpoint); with WithTLS the TLS handshake runs
// over the connection it returns (tls.Client). Use it to bind a source
// address, dial through a proxy, or refuse addresses (see SECURITY.md: an
// allowlist belongs in the dialer, for example in net.Dialer.Control,
// which sees the resolved IP). A StreamOpener of WithStream opens its own
// stream and does not use it: UDP and UDPFrom dial with a net.Dialer,
// UDPWithDialer takes a dialer. The default is a net.Dialer with a 10
// second timeout; nil keeps it.
func WithDialer(d Dialer) Option {
	return func(o *options) error {
		if d == nil {
			d = &net.Dialer{Timeout: dialTimeout}
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
		if !validJitter(r.Jitter) {
			return invalidOption("reconnect jitter %v not within [0, 1]", r.Jitter)
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
		if !validJitter(r.Jitter) {
			return invalidOption("retry jitter %v not within [0, 1]", r.Jitter)
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
// default is 2048. IEEE 1815-2012 clause 4.3 Rule 3 requires a master to
// receive fragments of at least 2048 octets: values from 249 to 2047 are
// accepted, for testing and for peers known to send less, but are outside
// that rule. WithMaxRequestFragment limits the requests the client sends.
func WithMaxFragment(n int) Option {
	return func(o *options) error {
		if n < 249 {
			return invalidOption("max fragment %d below 249", n)
		}
		o.maxRxFragment = n
		return nil
	}
}

// WithMaxRequestFragment limits the request fragments the client sends to
// n octets, at least 249: IEEE 1815-2012 clause 4.3 Rule 4 requires a
// master to be configurable to restrict its requests to 249 octets, Rule
// 1 to 2048, and NOTE 2 of the clause asks for no request larger than the
// outstation can receive. A request that does not fit fails with
// dnp3.ErrInvalidOption before anything is sent; a critical request that
// fits only without the objects of aggressive mode is sent without them,
// to be challenged (clause 7.4.1.6). WriteFile sizes its blocks to fit. By
// default the size of requests is not limited.
func WithMaxRequestFragment(n int) Option {
	return func(o *options) error {
		if n < 249 {
			return invalidOption("max request fragment %d below 249", n)
		}
		o.maxTxFragment = n
		return nil
	}
}

// WithLink configures the data link layer.
func WithLink(l Link) Option {
	return func(o *options) error { o.link = l; return nil }
}

// WithStartup sets what the client does each time the channel is
// established; see Startup. The default is Startup{Integrity: true};
// WithStartup(Startup{}) runs no startup step. With EnableUnsolicited
// classes it also sets DisableUnsolicited and Integrity: IEEE 1815-2012
// clause 5.1.1.2 Rule 1 requires a master that uses unsolicited reporting
// to disable it and to run an integrity poll before it enables it.
func WithStartup(s Startup) Option {
	return func(o *options) error {
		for _, c := range s.EnableUnsolicited {
			if c < 1 || c > 3 {
				return invalidOption("unsolicited class %d", c)
			}
		}
		s.EnableUnsolicited = slices.Clone(s.EnableUnsolicited)
		if len(s.EnableUnsolicited) > 0 {
			s.DisableUnsolicited, s.Integrity = true, true
		}
		o.startup = s
		return nil
	}
}

// WithTimeSync sets what the client does whenever the outstation reports
// IIN1.4 (NEED_TIME); IEEE 1815-2012 clauses 4.5.5 and 10.3.3 require the
// master to send the time promptly. Without this option the client
// synchronizes the time on its own: with TimeSyncLAN when the stream is a
// net.Conn (TCP, TLS, UDP) and with TimeSyncNonLAN over other streams,
// such as a serial port; when an outstation refuses the LAN procedure as
// not supported (IIN2.0 or IIN2.1), the client uses the non-LAN procedure
// with it instead. TimeSyncNone turns this off, TimeSyncClearNeedTime
// clears the indication without synchronizing the time, and TimeSyncLAN
// or TimeSyncNonLAN always uses that procedure.
func WithTimeSync(p TimeSync) Option {
	return func(o *options) error {
		if p > TimeSyncClearNeedTime {
			return invalidOption("time sync procedure %d", p)
		}
		o.timeSync, o.timeSyncSet = p, true
		return nil
	}
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

// WithSolicitedConfirm controls whether the client confirms a solicited
// response that asks for confirmation (CON). It is on by default, as IEEE
// 1815-2012 requires. It is a test and diagnostic option, to see what an
// outstation does without the confirmation: it keeps the events it sent
// (the next poll gets them again) and sends no further fragment of a
// multi-fragment response, so such a response ends in dnp3.ErrTimeout.
// Unsolicited responses are still confirmed; see WithUnsolicitedConfirm.
func WithSolicitedConfirm(enabled bool) Option {
	return func(o *options) error { o.noSolConfirm = !enabled; return nil }
}

// WithUnsolicitedConfirm controls whether the client confirms an
// unsolicited response that asks for confirmation (CON). It is on by
// default, as IEEE 1815-2012 requires. It is a test and diagnostic option,
// to see the outstation repeat an unconfirmed unsolicited response: the
// client passes the events of a repeat to the Handler only once. An
// outstation may answer no request until its null unsolicited response at
// startup is confirmed.
func WithUnsolicitedConfirm(enabled bool) Option {
	return func(o *options) error { o.noUnsConfirm = !enabled; return nil }
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
// key it uses that key directly. A user number of 0, which IEEE 1815-2012
// reserves for an unknown user, is taken as 1, the default user. Without
// this option a challenge fails the request with dnp3.ErrAuthentication.
func WithSecureAuthentication(u secauth.User) Option {
	return func(o *options) error {
		// A copy per client: an Option may be used for several.
		user := u
		if err := user.Validate(); err != nil {
			return invalidOption("%v", err)
		}
		if user.Number == 0 {
			user.Number = 1 // 0 is reserved for an unknown user
		}
		o.auth = &user
		return nil
	}
}

// WithAggressiveMode sends the requests with the function codes fcs
// (secauth.DefaultCritical when none are given) in Secure Authentication
// aggressive mode (IEEE 1815-2012 clause 7.5.3.3, A.45.3 and A.45.9): with
// a MAC in the request itself, so that the outstation executes it without
// a challenge. The MAC covers the last challenge received and the whole
// request up to the MAC value (Table A-9). Aggressive mode is used only
// once a challenge was answered successfully since the last session key
// change, so the first critical request after each key change is still
// challenged; after a refused aggressive mode request the next one is
// sent normally, and an outstation that answers error 4 (aggressive mode
// not supported) is not sent aggressive mode again on that connection.
// New refuses it without WithSecureAuthentication.
func WithAggressiveMode(fcs ...app.FunctionCode) Option {
	return func(o *options) error {
		if len(fcs) == 0 {
			fcs = secauth.DefaultCritical
		}
		o.aggressive = fcs
		return nil
	}
}

// WithChallengeMACs limits the MAC algorithms an outstation's challenge
// may ask for. The challenge (g120v1, IEEE 1815-2012 A.45.1) names the
// algorithm of the reply and of aggressive mode requests; a challenge
// asking for another one fails the request with dnp3.ErrAuthentication.
// By default every algorithm package secauth computes is accepted except
// the obsolete HMAC-SHA-1 truncated to 4 octets and, over TCP/IP or
// UDP/IP (the built-in dialer, or a stream whose remote address is a TCP
// or UDP address), the truncations to 8 octets, which clauses 7.6.1.1.1
// and 7.6.1.1.2 allow on serial links only; this option can allow them. The
// algorithm of secauth.User is the one the session key change and the
// outstation's key status use; it need not be in the list.
func WithChallengeMACs(algs ...app.MACAlgorithm) Option {
	return func(o *options) error {
		if len(algs) == 0 {
			return invalidOption("no challenge MAC algorithm")
		}
		for _, a := range algs {
			if _, err := secauth.MAC(a, []byte{0}, nil); err != nil {
				return invalidOption("challenge MAC algorithm %s: %v", a, err)
			}
		}
		o.challengeMACs = slices.Clone(algs)
		return nil
	}
}

// WithKeyChangeInterval sets how often the session keys are changed while
// connected, with an update key (IEEE 1815-2012 clause 7.6.1.4.3). The
// default is 15 minutes. 0 disables the interval: the keys are then
// changed only after the key change count (WithKeyChangeCount), as the
// clause allows for devices that communicate infrequently. A negative
// interval is refused.
func WithKeyChangeInterval(d time.Duration) Option {
	return func(o *options) error {
		if d < 0 {
			return invalidOption("key change interval %v", d)
		}
		o.keyChange = d
		return nil
	}
}

// MaxKeyChangeCount is the largest session key change count: half the
// range of the key change sequence number (IEEE 1815-2012 clause
// 7.6.1.4.4).
const MaxKeyChangeCount = 1 << 31

// WithKeyChangeCount sets the session key change count (IEEE 1815-2012
// clause 7.6.1.4.4): with an update key, the session keys are also changed
// once n authentication messages were sent or received since the last
// change (challenges and errors received, replies and aggressive mode
// requests sent). The default is DefaultKeyChangeCount (1000); n ranges
// from 1 to MaxKeyChangeCount.
func WithKeyChangeCount(n uint32) Option {
	return func(o *options) error {
		if n < 1 || n > MaxKeyChangeCount {
			return invalidOption("key change count %d: 1 to %d", n, uint32(MaxKeyChangeCount))
		}
		o.keyChangeCount = n
		return nil
	}
}

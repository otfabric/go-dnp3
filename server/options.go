// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"fmt"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// Option configures a [Server].
type Option func(*options) error

// Unsolicited configures unsolicited responses.
type Unsolicited struct {
	// Enabled allows unsolicited responses. When set, the outstation sends
	// a null unsolicited response when a master connects and reports
	// events of the classes the master enables (or of Classes from the
	// start).
	Enabled bool
	// Classes are the classes (1..3) enabled before any ENABLE_UNSOLICITED,
	// IEEE 1815-2012's "unsolicited allowed at startup".
	Classes []Class
	// HoldTime is how long new events are collected before they are sent
	// unsolicited. Zero sends at once.
	HoldTime time.Duration
	// HoldCount sends at once when this many events are pending, before
	// HoldTime has passed. Zero means no count trigger.
	HoldCount int
	// Retries is how often an unconfirmed unsolicited response is
	// repeated before it is given up; its events are kept and reported
	// later. Zero means 3; a negative value repeats it until it is
	// confirmed.
	Retries int
	// RetryDelay is the pause after an unsolicited response was given up.
	// Zero means 5 seconds.
	RetryDelay time.Duration
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

type options struct {
	address        link.Address
	masters        []link.Address
	selfAddress    bool
	handler        Handler
	logger         dnp3.Logger
	metrics        dnp3.Metrics
	tls            *tls.Config
	maxConns       int
	maxTxFragment  int
	maxRxFragment  int
	confirmTimeout time.Duration
	selectTimeout  time.Duration
	maxControls    int
	unsolicited    Unsolicited
	link           Link
	eventLimits    map[PointType]int
	needTime       time.Duration
	attributes     map[uint16]*attributeSet
	files          FileServer
	auth           *SecureAuth
}

func defaultOptions() options {
	return options{
		address:        10,
		handler:        NopHandler{},
		maxConns:       16,
		maxTxFragment:  transport.DefaultMaxFragment,
		maxRxFragment:  transport.DefaultMaxFragment,
		confirmTimeout: 5 * time.Second,
		selectTimeout:  10 * time.Second,
		maxControls:    16,
	}
}

func invalidOption(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{dnp3.ErrInvalidOption}, args...)...)
}

// WithAddress sets the link address of the outstation. The default is 10.
func WithAddress(a link.Address) Option {
	return func(o *options) error {
		if a > link.MaxStationAddress {
			return invalidOption("outstation address %d", a)
		}
		o.address = a
		return nil
	}
}

// WithMasters restricts the masters the outstation answers to these link
// addresses. Their associations, and so their event buffers, exist from
// the start: events are kept while a master is not connected. Without it
// any master is answered and its association is created on first contact.
func WithMasters(addrs ...link.Address) Option {
	return func(o *options) error {
		for _, a := range addrs {
			if a > link.MaxStationAddress {
				return invalidOption("master address %d", a)
			}
		}
		o.masters = append([]link.Address(nil), addrs...)
		return nil
	}
}

// WithSelfAddress makes the outstation accept frames sent to the self
// address 0xFFFC as if they were sent to its own address.
func WithSelfAddress(enabled bool) Option {
	return func(o *options) error { o.selfAddress = enabled; return nil }
}

// WithHandler sets the handler for controls and, through its optional
// interfaces, for restarts, time synchronization, application functions
// and writes. The default supports no control.
func WithHandler(h Handler) Option {
	return func(o *options) error {
		if h == nil {
			return invalidOption("nil handler")
		}
		o.handler = h
		return nil
	}
}

// WithLogger sets the logger; logging is silent by default.
func WithLogger(l dnp3.Logger) Option {
	return func(o *options) error { o.logger = l; return nil }
}

// WithMetrics sets the metrics callbacks. A value that also implements
// dnp3.ServerMetrics receives the server-level callbacks.
func WithMetrics(m dnp3.Metrics) Option {
	return func(o *options) error { o.metrics = m; return nil }
}

// WithTLS serves TLS (IEEE 1815-2012 Annex B / IEC 62351-3) on the
// listeners of ListenAndServe, and is the TLS client configuration of
// DialAndServe. Serve and ServeConn take the connection as it is.
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) error { o.tls = cfg; return nil }
}

// WithMaxConnections limits concurrent connections; further ones are
// closed at once. The default is 16.
func WithMaxConnections(n int) Option {
	return func(o *options) error {
		if n < 1 {
			return invalidOption("max connections %d", n)
		}
		o.maxConns = n
		return nil
	}
}

// WithMaxFragment sets the largest response fragment the outstation sends
// (tx) and the largest request it reassembles (rx). The defaults are 2048;
// IEEE 1815-2012 requires at least 249.
func WithMaxFragment(tx, rx int) Option {
	return func(o *options) error {
		if tx < 249 || rx < 249 {
			return invalidOption("fragment sizes %d/%d below 249", tx, rx)
		}
		o.maxTxFragment, o.maxRxFragment = tx, rx
		return nil
	}
}

// WithConfirmTimeout sets how long the outstation waits for the
// application confirmation of a response or unsolicited response. The
// default is 5 seconds.
func WithConfirmTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalidOption("confirm timeout %v", d)
		}
		o.confirmTimeout = d
		return nil
	}
}

// WithSelectTimeout sets how long a SELECT stays valid for its OPERATE;
// an OPERATE after it is answered with TIMEOUT. The default is 10 seconds.
func WithSelectTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalidOption("select timeout %v", d)
		}
		o.selectTimeout = d
		return nil
	}
}

// WithMaxControls sets how many controls one request may carry; the
// controls beyond it are answered with TOO_MANY_OBJS. The default is 16.
func WithMaxControls(n int) Option {
	return func(o *options) error {
		if n < 1 {
			return invalidOption("max controls %d", n)
		}
		o.maxControls = n
		return nil
	}
}

// WithUnsolicited configures unsolicited responses; they are disabled by
// default.
func WithUnsolicited(u Unsolicited) Option {
	return func(o *options) error {
		for _, c := range u.Classes {
			if c < 1 || c > 3 {
				return invalidOption("unsolicited class %d", c)
			}
		}
		if u.Retries == 0 {
			u.Retries = 3
		}
		if u.RetryDelay <= 0 {
			u.RetryDelay = 5 * time.Second
		}
		o.unsolicited = u
		return nil
	}
}

// WithLink configures the data link layer.
func WithLink(l Link) Option {
	return func(o *options) error { o.link = l; return nil }
}

// WithEventLimits sets the number of events of each point type an
// association buffers; types not named keep [DefaultEventLimit]. When a
// buffer is full the oldest event of the type is discarded and the
// outstation reports IIN2.3 (EVENT_BUFFER_OVERFLOW).
func WithEventLimits(limits map[PointType]int) Option {
	return func(o *options) error {
		o.eventLimits = make(map[PointType]int, len(limits))
		for t, n := range limits {
			if n < 0 || t >= numPointTypes {
				return invalidOption("event limit %d for %s", n, t)
			}
			o.eventLimits[t] = n
		}
		return nil
	}
}

// WithTimeSync makes the outstation request time synchronization (IIN1.4
// NEED_TIME) at start and again when interval has passed since the last
// one. Zero, the default, never requests it.
//
// Its time counts as unsynchronized, which relative-time events report
// with a g51v2 CTO instead of g51v1, until the first synchronization after
// the start or a restart, and again once twice the interval has passed
// without one.
func WithTimeSync(interval time.Duration) Option {
	return func(o *options) error {
		if interval < 0 {
			return invalidOption("time sync interval %v", interval)
		}
		o.needTime = interval
		return nil
	}
}

// WithAttributes sets the device attributes of set 0 (group 0) the
// outstation reports, keyed by variation, for example
// app.AttrManufacturerName. The list of attribute variations (g0v255) is
// built from them; an attribute is writable when the [Handler] implements
// [WriteHandler].
func WithAttributes(attrs map[uint8]app.Attribute) Option {
	return func(o *options) error { return o.addAttributeSet(0, attrs, nil, true) }
}

// WithAttributeSet sets the device attributes of another set (group 0,
// the set is the index; IEEE 1815-2012 clause 11.9.1), keyed by
// variation. The variations in writable can be written by a master, with
// a value of the same type: the outstation stores it and, when the
// [Handler] implements [AttributeSetWriteHandler], tells it first. Other
// writes are refused.
func WithAttributeSet(set uint16, attrs map[uint8]app.Attribute, writable ...uint8) Option {
	return func(o *options) error {
		for _, v := range writable {
			if _, ok := attrs[v]; !ok {
				return invalidOption("writable attribute %d of set %d does not exist", v, set)
			}
		}
		return o.addAttributeSet(set, attrs, writable, false)
	}
}

func (o *options) addAttributeSet(set uint16, attrs map[uint8]app.Attribute, writable []uint8, legacy bool) error {
	as := &attributeSet{attrs: make(map[uint8]app.Attribute, len(attrs)), writable: map[uint8]bool{}, legacy: legacy}
	for v, a := range attrs {
		if v == app.AttrAllAttributes || v == app.AttrListOfVariations || v == 0 {
			return invalidOption("attribute variation %d", v)
		}
		as.attrs[v] = a
	}
	for _, v := range writable {
		as.writable[v] = true
	}
	if o.attributes == nil {
		o.attributes = map[uint16]*attributeSet{}
	}
	o.attributes[set] = as
	return nil
}

// WithFileServer serves file transfer (group 70) from fs.
func WithFileServer(fs FileServer) Option {
	return func(o *options) error { o.files = fs; return nil }
}

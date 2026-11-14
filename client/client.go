// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// DefaultPort is the registered DNP3 port (IEEE 1815-2012 clause
// 13.2.2.2), the default of an address without a port.
const DefaultPort = 20000

// DefaultTLSPort is the default port of DNP3 over TLS (IEEE 1815-2012
// clauses 7.8.8 and 13.2.2.2): the port of an address without one when
// WithTLS is set.
const DefaultTLSPort = 19999

// Client is a DNP3 master for one outstation. Create it with [New] or
// [Dial]. It is safe for concurrent use; requests are executed one at a
// time, in the order they are made, as DNP3 requires.
type Client struct {
	addr string
	opts options
	log  *logx.Logger
	rm   dnp3.RequestMetrics
	cm   dnp3.ClientMetrics

	mu      sync.Mutex
	ch      *channel.Channel
	sess    *channel.Session
	remote  net.Addr
	state   dnp3.State
	closed  bool
	dialing bool
	// held is the channel whose startup sequence a Connect runs: its loss
	// is that Connect's error, not a reason to reconnect. When its watch
	// sees it lost, it sets heldLost and heldErr for the Connect.
	held     *channel.Channel
	heldLost bool
	heldErr  error
	pending  *transaction
	// proc is the state of the master procedures of the current channel.
	proc procState
	// integrity is when the last integrity poll completed, so that an
	// automatic one queued before it is not run as well.
	integrity time.Time
	// started is closed when the startup sequence of the current channel
	// has ended: automatic tasks wait for it.
	started chan struct{}
	// auth is the secure authentication state of the current channel and
	// counters the security statistics.
	auth     authState
	counters authCounters
	// rekey asks the key change loop for a key change now.
	rekey chan struct{}

	// turn admits one transaction at a time; waiting counts the requests
	// queued for it.
	turn    chan struct{}
	waiting int
	seq     uint8

	events  *dispatcher
	tasks   chan task
	taskMu  sync.Mutex
	queued  map[string]bool
	closeCh chan struct{}
	wg      sync.WaitGroup

	// needTime is the NEED_TIME indication of the outstation's latest
	// response.
	needTime atomic.Bool
	// lastSync is when the last successful automatic time synchronization
	// ended (UnixNano), 0 before the first; syncTimer, guarded by taskMu,
	// queues a time synchronization put off until the response timeout
	// has passed since (enqueueTimeSync).
	lastSync  atomic.Int64
	syncTimer *time.Timer

	// dual is the dual end point of WithDualEndpoint, nil without.
	dual *dualEndpoint
}

// New returns a client for the outstation at addr ("host:port"; the port
// defaults to DefaultPort, 20000, and with WithTLS to DefaultTLSPort,
// 19999). The client is not connected until Connect.
func New(addr string, opts ...Option) (*Client, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if o.aggressive != nil && o.auth == nil {
		return nil, invalidOption("WithAggressiveMode needs WithSecureAuthentication")
	}
	if o.dualListener != nil && o.opener != nil {
		return nil, invalidOption("WithDualEndpoint and WithStream exclude each other")
	}
	if o.opener == nil {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			port := DefaultPort
			if o.tls != nil {
				port = DefaultTLSPort
			}
			addr = net.JoinHostPort(addr, strconv.Itoa(port))
		}
	}
	c := &Client{
		addr:    addr,
		opts:    o,
		log:     logx.New(o.logger, "client", "remote", addr, "outstation", o.remote),
		turn:    make(chan struct{}, 1),
		tasks:   make(chan task, 8),
		queued:  make(map[string]bool),
		closeCh: make(chan struct{}),
		rekey:   make(chan struct{}, 1),
	}
	c.counters = newAuthCounters()
	// The application's metrics are called guarded: a callback that does
	// not return normally is logged, and the client goes on.
	rm, _ := o.metrics.(dnp3.RequestMetrics)
	c.rm = logx.RequestMetrics(rm, c.log)
	cm, _ := o.metrics.(dnp3.ClientMetrics)
	c.cm = logx.ClientMetrics(cm, c.log)
	c.opts.metrics = logx.Metrics(o.metrics, c.log)
	if o.dualListener != nil {
		c.dual = &dualEndpoint{c: c, l: o.dualListener, allow: o.dualAllow, wake: make(chan struct{}, 1)}
	}
	c.events = newDispatcher(c)
	c.wg.Add(2)
	go c.events.run()
	go c.taskLoop()
	return c, nil
}

// Dial creates a client and connects it: [New] followed by
// [Client.Connect].
func Dial(ctx context.Context, addr string, opts ...Option) (*Client, error) {
	c, err := New(addr, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Addr returns the address the client connects to.
func (c *Client) Addr() string { return c.addr }

// Outstation returns the link address of the outstation.
func (c *Client) Outstation() link.Address { return c.opts.remote }

// State returns the current channel state.
func (c *Client) State() dnp3.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Connect establishes the channel and runs the startup sequence of
// WithStartup (with secure authentication and an update key, the session
// key change first), by default an integrity poll. When the sequence
// fails, for example because the outstation does not answer it, the
// channel is closed and the error returned. It fails with dnp3.ErrBusy when the client is
// connected or connecting. With WithReconnect it needs to succeed only
// once: a lost channel is re-established by the client, and kept when
// only the startup sequence of the new one failed.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return dnp3.ErrClosed
	case c.ch != nil || c.dialing:
		c.mu.Unlock()
		return fmt.Errorf("%w: already connected", dnp3.ErrBusy)
	}
	c.dialing = true
	c.mu.Unlock()
	return c.establish(ctx)
}

// establish connects a client that is dialing and not connected, and
// leaves it disconnected when that fails.
//
// The channel is held during its startup sequence: when it is lost then,
// its watch leaves the outcome here instead of reconnecting, so that a
// failed Connect leaves no reconnect behind it, which would dial next to
// the caller's next Connect.
func (c *Client) establish(ctx context.Context) error {
	c.setState(dnp3.StateConnecting, nil)
	ch, err := c.connect(ctx, true)
	c.mu.Lock()
	lost, lostErr := c.heldLost, c.heldErr
	c.held, c.heldLost, c.heldErr = nil, false, nil
	if err != nil {
		// A channel whose startup sequence failed is closed: Connect
		// either connects or leaves the client disconnected.
		c.dialing = false
		if ch != nil && c.ch == ch {
			c.ch, c.sess = nil, nil
		}
		started := c.started
		c.mu.Unlock()
		c.setState(dnp3.StateDisconnected, err)
		if ch != nil {
			ch.Close(nil)
			// connect left the startup sequence open (see there).
			close(started)
		}
		return err
	}
	if !lost {
		c.mu.Unlock()
		return nil
	}
	// The startup sequence succeeded and the channel was lost right
	// after it: what its watch would have done.
	reconnect := !c.closed && c.opts.reconnect != nil && lostErr != nil
	if reconnect {
		c.dialing = true
		c.wg.Add(1) // under c.mu, as in connect
	}
	c.mu.Unlock()
	if !reconnect {
		c.setState(dnp3.StateDisconnected, lostErr)
		return nil
	}
	c.setState(dnp3.StateConnecting, lostErr)
	go func() {
		defer c.wg.Done()
		c.reconnectLoop()
	}()
	return nil
}

// connect opens the stream and starts the channel, held for the startup
// sequence when hold is set (see establish). The caller has set dialing.
// It returns the channel it started, also when its startup sequence
// failed.
func (c *Client) connect(ctx context.Context, hold bool) (*channel.Channel, error) {
	stream, remote, err := c.open(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", dnp3.ErrConnectFailed, err)
	}
	ka := c.opts.link.KeepAlive
	if ka == 0 {
		ka = 60 * time.Second
	}
	ch := channel.New(stream, channel.Config{Remote: remote, Metrics: c.opts.metrics, Log: c.log})
	// No frame is read before Start, so the callback sees sess set.
	var sess *channel.Session
	sess = ch.AddSession(channel.SessionConfig{
		Local:           c.opts.local,
		Remote:          c.opts.remote,
		Master:          true,
		Confirmed:       c.opts.link.Confirmed,
		ResponseTimeout: c.opts.link.Timeout,
		Retries:         c.opts.link.Retries,
		KeepAlive:       max(ka, 0),
		MaxFragment:     c.opts.maxRxFragment,
		OnFragment:      func(frag []byte, _ link.Address) { c.safeReceive(sess, frag) },
	})
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		ch.Close(nil)
		return nil, dnp3.ErrClosed
	}
	if c.ch != nil {
		// Never two channels: one replaced without being closed would go on
		// answering the outstation's link status requests, and an
		// outstation keeps the connection of a connected master (IEEE
		// 1815-2012 clause 13.2.3.3).
		c.mu.Unlock()
		ch.Close(nil)
		return nil, fmt.Errorf("%w: already connected", dnp3.ErrBusy)
	}
	c.ch, c.sess, c.remote, c.dialing = ch, sess, remote, false
	if hold {
		c.held = ch
	}
	c.auth.reset()
	started := make(chan struct{})
	c.started = started
	c.proc.reset(c.autoTimeSync(stream))
	// The Add under c.mu, where closed was checked, comes before a Close's
	// Wait: an Add from zero after it is not allowed (sync.WaitGroup),
	// and watch would run after Close returned.
	c.wg.Add(1)
	c.mu.Unlock()
	ch.Start()
	go c.watch(ch)
	c.log.Info("connected", "remote_addr", addrString(remote))
	c.setState(dnp3.StateConnected, nil)

	err = c.changeSessionKeys(ctx)
	if err == nil {
		err = c.runStartup(ctx)
	} else if c.opts.auth != nil {
		c.rekeySoon()
	}
	if err != nil {
		c.log.Warn("startup sequence failed", "error", err)
		if hold {
			// establish closes the channel, and ends the startup sequence
			// only once the client is disconnected: a task queued during
			// it (taskLoop) must not run on that channel meanwhile.
			return ch, err
		}
	}
	close(started)
	return ch, err
}

// handshakeTimeout bounds the TLS handshake of a connection, so that an
// outstation that stalls it fails the attempt instead of holding it.
var handshakeTimeout = 10 * time.Second

// dialTimeout is the TCP connect timeout of the default dialer.
const dialTimeout = 10 * time.Second

func (c *Client) open(ctx context.Context) (s channel.Stream, remote net.Addr, err error) {
	if c.opts.opener != nil {
		// An opener that does not return normally fails the attempt. Accept
		// logs through the client's logger, which ctx carries.
		ctx = logx.NewContext(ctx, c.log)
		var rwc io.ReadWriteCloser
		err = logx.Do(c.log, "StreamOpener", func() (err error) {
			rwc, remote, err = c.opts.opener(ctx)
			return err
		})
		return rwc, remote, err
	}
	if c.dual != nil {
		return c.dual.open(ctx)
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.RemoteAddr(), nil
}

// dial opens a TCP connection to the outstation, with TLS when configured.
// The reconnects and the dual end point dial here as well.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	// A dialer that does not return normally fails the dial.
	conn, err := logx.Call(c.log, "Dialer.DialContext", func() (net.Conn, error) {
		return dialConn(ctx, c.opts.dialer, "tcp", c.addr)
	})
	if err != nil {
		return nil, err
	}
	if c.opts.tls != nil {
		cfg := c.opts.tls.Clone()
		if cfg.ServerName == "" {
			host, _, _ := net.SplitHostPort(c.addr)
			cfg.ServerName = host
		}
		tc := tls.Client(conn, cfg)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		// The handshake runs the callbacks of the application's tls.Config.
		err := logx.Do(c.log, "TLS handshake", func() error { return tc.HandshakeContext(hctx) })
		cancel()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tc
	}
	return conn, nil
}

// watch waits for a channel to end and reconnects when configured.
func (c *Client) watch(ch *channel.Channel) {
	defer c.wg.Done()
	<-ch.Done()
	err := ch.Err()
	c.mu.Lock()
	if c.ch == ch {
		c.ch, c.sess = nil, nil
	}
	p := c.pending
	closed := c.closed
	held := c.held == ch
	if held {
		c.held, c.heldLost, c.heldErr = nil, true, err
	}
	reconnect := !closed && !held && c.opts.reconnect != nil && err != nil
	if reconnect {
		c.dialing = true
	}
	c.mu.Unlock()
	if p != nil {
		p.fail(err)
	}
	if closed {
		return
	}
	c.log.Warn("connection lost", "error", err)
	if held {
		return // the Connect running its startup sequence decides
	}
	if !reconnect {
		c.setState(dnp3.StateDisconnected, err)
		return
	}
	c.setState(dnp3.StateConnecting, err)
	c.reconnectLoop()
}

func (c *Client) reconnectLoop() {
	delay := c.opts.reconnect.MinDelay
	timer := time.NewTimer(jittered(delay, c.opts.reconnect.Jitter))
	defer timer.Stop()
	for {
		select {
		case <-c.closeCh:
			c.mu.Lock()
			c.dialing = false
			c.mu.Unlock()
			return
		case <-timer.C:
		case <-c.dual.woken():
			// The outstation connected to the dual end point: the attempt
			// takes its connection now.
		}
		// Close ends an attempt in progress, not only the wait between
		// attempts, with dnp3.ErrClosed as the cause: an opener can tell
		// that no attempt follows.
		closed, cancelClosed := context.WithCancelCause(context.Background())
		ctx, cancel := context.WithTimeout(closed, max(delay, 10*time.Second))
		go func() {
			select {
			case <-c.closeCh:
				cancelClosed(dnp3.ErrClosed)
			case <-ctx.Done():
			}
		}()
		_, err := c.connect(ctx, false)
		cancel()
		cancelClosed(nil)
		if err == nil {
			return
		}
		if c.isClosed() {
			return
		}
		if !errors.Is(err, dnp3.ErrConnectFailed) {
			return // the dial succeeded, only the startup sequence failed: that channel's watch reconnects
		}
		c.mu.Lock()
		c.dialing = true
		c.mu.Unlock()
		c.setState(dnp3.StateConnecting, err)
		delay = min(delay*2, c.opts.reconnect.MaxDelay)
		wait := jittered(delay, c.opts.reconnect.Jitter)
		c.log.Warn("reconnect failed", "retry_in", wait.String(), "error", err)
		timer.Reset(wait)
	}
}

// startupDone returns the channel closed when the current startup
// sequence has ended, or nil without a channel.
func (c *Client) startupDone() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close closes the channel, stops reconnecting and the automatic tasks,
// and fails pending requests with dnp3.ErrClosed. It waits for the
// client's goroutines, the handler included, to finish, so it must not be
// called from the Handler or the state handler, which run on one of them:
// call go c.Close() there.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	ch := c.ch
	c.mu.Unlock()
	close(c.closeCh)
	if ch != nil {
		ch.Close(nil)
	}
	c.dual.close()
	c.wg.Wait()
	// The dispatcher has stopped: the last notification is delivered here,
	// after every earlier one.
	c.mu.Lock()
	changed := c.state != dnp3.StateDisconnected
	c.state = dnp3.StateDisconnected
	c.mu.Unlock()
	if changed && c.opts.stateHandler != nil {
		// On the caller's goroutine: one that does not return normally is
		// logged, as on the dispatcher's, and Close returns.
		_ = logx.Run(c.log, "state handler", func() { c.opts.stateHandler(dnp3.StateDisconnected, nil) })
	}
	return nil
}

// lateResponse reports a response fragment no request takes
// (dnp3.ClientMetrics).
func (c *Client) lateResponse(f *app.Fragment) {
	if c.cm != nil {
		c.cm.OnLateResponse(c.remoteAddr(), f.Function)
	}
}

func (c *Client) setState(s dnp3.State, err error) {
	c.mu.Lock()
	changed := c.state != s
	c.state = s
	c.mu.Unlock()
	if (changed || err != nil) && c.opts.stateHandler != nil {
		c.events.state(s, err)
	}
}

func (c *Client) remoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

// receive handles a fragment from the outstation on the session's
// safeReceive is receive, recovering from a panic in it (a bug reached by a
// response, or in the application's handler): the fragment is lost, as one
// lost on the line would be, instead of the panic stopping the process.
func (c *Client) safeReceive(sess *channel.Session, frag []byte) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("panic while receiving a fragment", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	c.receive(sess, frag)
}

// goroutine.
func (c *Client) receive(sess *channel.Session, data []byte) {
	at := time.Now()
	// No request goes out while a fragment is handled: the confirmation
	// it may ask for comes first (IEEE 1815-2012 clause 4.3 Rule 13).
	c.proc.sendMu.Lock()
	defer c.proc.sendMu.Unlock()
	f, err := app.Decode(data)
	if err != nil {
		c.log.Debug("undecodable fragment dropped", "error", err)
		if m := c.opts.metrics; m != nil {
			m.OnDecodeError(c.remoteAddr(), err)
		}
		return
	}
	c.count(secauth.StatTotalMessagesReceived)
	if m := c.opts.metrics; m != nil {
		m.OnFragmentReceived(c.remoteAddr(), f, len(data))
	}
	if c.log.DebugEnabled() {
		c.log.Debug("fragment received", "fragment", f.String())
	}
	if unsContradicts(f) {
		// The UNS bit selects the solicited or the unsolicited reception
		// state machine (IEEE 1815-2012 clauses 6.3 and 6.5), and a
		// confirmation carries the fragment's UNS bit (clause 4.3 Rule
		// 18): a fragment whose UNS bit contradicts its function code
		// (clause 4.2.2.4.4) is neither processed nor confirmed.
		c.log.Debug("fragment with a UNS bit contradicting its function discarded", "function", f.Function.String(), "uns", f.Control.UNS)
		return
	}
	switch f.Function {
	case app.FuncResponse, app.FuncAuthResponse:
		// Under c.mu, so that a request that ends finds every fragment
		// it was given (discardUnread).
		c.mu.Lock()
		p := c.pending
		taken := p != nil && p.accept(f, data, at)
		c.mu.Unlock()
		if !taken {
			// IEEE 1815-2012 Table 6-2 row 1: a response nobody waits for
			// is discarded, not confirmed. onStrayAuth logs it, or answers
			// a challenge of a confirmation sent before (clause 7.5.2.3.2
			// j).
			c.onStrayAuth(sess, f, data)
		}
	case app.FuncUnsolicitedResponse:
		c.receiveUnsolicited(sess, f, data)
	default:
		c.log.Debug("request function sent to a master ignored", "function", f.Function.String())
	}
}

// sendConfirm sends the application confirmation f (confirmResponse makes
// it), and keeps it: the outstation may challenge it.
func (c *Client) sendConfirm(sess *channel.Session, f *app.Fragment) {
	data, err := f.Encode()
	if err != nil {
		c.log.Debug("confirmation not sent", "error", err)
		return
	}
	c.mu.Lock()
	c.auth.lastConfirm = data
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.responseTimeout)
	defer cancel()
	if err := sess.Send(ctx, data); err != nil {
		c.log.Debug("confirmation not sent", "error", err)
		return
	}
	c.sent(f, len(data))
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

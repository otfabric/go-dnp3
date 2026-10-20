// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
)

// DefaultPort is the registered DNP3 port, also used for TLS.
const DefaultPort = 20000

// Client is a DNP3 master for one outstation. Create it with [New] or
// [Dial]. It is safe for concurrent use; requests are executed one at a
// time, in the order they are made, as DNP3 requires.
type Client struct {
	addr string
	opts options
	log  *logx.Logger
	rm   dnp3.RequestMetrics

	mu      sync.Mutex
	ch      *channel.Channel
	sess    *channel.Session
	remote  net.Addr
	state   dnp3.State
	closed  bool
	dialing bool
	pending *transaction
	lastUns []byte // the last unsolicited response, to recognise repeats
	// integrity is when the last integrity poll completed, so that an
	// automatic one queued before it is not run as well.
	integrity time.Time
	// started is closed when the startup sequence of the current channel
	// has ended: automatic tasks wait for it.
	started chan struct{}

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
}

// New returns a client for the outstation at addr ("host:port"; the port
// defaults to 20000). The client is not connected until Connect.
func New(addr string, opts ...Option) (*Client, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if o.opener == nil {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, strconv.Itoa(DefaultPort))
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
	}
	c.rm, _ = o.metrics.(dnp3.RequestMetrics)
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
// WithStartup. It fails with dnp3.ErrBusy when the client is connected or
// connecting. With WithReconnect it needs to succeed only once: a lost
// channel is re-established by the client.
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
	c.setState(dnp3.StateConnecting, nil)
	err := c.connect(ctx)
	if err != nil {
		c.mu.Lock()
		c.dialing = false
		c.mu.Unlock()
		c.setState(dnp3.StateDisconnected, err)
	}
	return err
}

// connect opens the stream and starts the channel. The caller has set
// dialing.
func (c *Client) connect(ctx context.Context) error {
	stream, remote, err := c.open(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", dnp3.ErrConnectFailed, err)
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
		OnFragment:      func(frag []byte, _ link.Address) { c.receive(sess, frag) },
	})
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		ch.Close(nil)
		return dnp3.ErrClosed
	}
	c.ch, c.sess, c.remote, c.dialing = ch, sess, remote, false
	started := make(chan struct{})
	c.started = started
	c.lastUns = nil
	c.mu.Unlock()
	ch.Start()
	c.wg.Add(1)
	go c.watch(ch)
	c.log.Info("connected", "remote_addr", addrString(remote))
	c.setState(dnp3.StateConnected, nil)

	err = c.runStartup(ctx)
	close(started)
	if err != nil {
		c.log.Warn("startup sequence failed", "error", err)
		return err
	}
	return nil
}

func (c *Client) open(ctx context.Context) (s channel.Stream, remote net.Addr, err error) {
	if c.opts.opener != nil {
		return c.opts.opener(ctx)
	}
	conn, err := c.opts.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, nil, err
	}
	if c.opts.tls != nil {
		cfg := c.opts.tls.Clone()
		if cfg.ServerName == "" {
			host, _, _ := net.SplitHostPort(c.addr)
			cfg.ServerName = host
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tc
	}
	return conn, conn.RemoteAddr(), nil
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
	reconnect := !closed && c.opts.reconnect != nil && err != nil
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
	if !reconnect {
		c.setState(dnp3.StateDisconnected, err)
		return
	}
	c.setState(dnp3.StateConnecting, err)
	c.reconnectLoop()
}

func (c *Client) reconnectLoop() {
	delay := c.opts.reconnect.MinDelay
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-c.closeCh:
			c.mu.Lock()
			c.dialing = false
			c.mu.Unlock()
			return
		case <-timer.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), max(delay, 10*time.Second))
		err := c.connect(ctx)
		cancel()
		if err == nil {
			return
		}
		if c.isClosed() {
			return
		}
		c.mu.Lock()
		connected := c.ch != nil
		if !connected {
			c.dialing = true
		}
		c.mu.Unlock()
		if connected {
			return // the channel is up; only the startup sequence failed
		}
		c.setState(dnp3.StateConnecting, err)
		c.log.Warn("reconnect failed", "retry_in", delay.String(), "error", err)
		delay = min(delay*2, c.opts.reconnect.MaxDelay)
		timer.Reset(delay)
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
// client's goroutines, the handler included, to finish.
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
	c.wg.Wait()
	// The dispatcher has stopped: the last notification is delivered here,
	// after every earlier one.
	c.mu.Lock()
	changed := c.state != dnp3.StateDisconnected
	c.state = dnp3.StateDisconnected
	c.mu.Unlock()
	if changed && c.opts.stateHandler != nil {
		c.opts.stateHandler(dnp3.StateDisconnected, nil)
	}
	return nil
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
// goroutine.
func (c *Client) receive(sess *channel.Session, data []byte) {
	f, err := app.Decode(data)
	if err != nil {
		c.log.Debug("undecodable fragment dropped", "error", err)
		if m := c.opts.metrics; m != nil {
			m.OnDecodeError(c.remoteAddr(), err)
		}
		return
	}
	if m := c.opts.metrics; m != nil {
		m.OnFragmentReceived(c.remoteAddr(), f, len(data))
	}
	if c.log.DebugEnabled() {
		c.log.Debug("fragment received", "fragment", f.String())
	}
	switch f.Function {
	case app.FuncResponse, app.FuncAuthResponse:
		c.mu.Lock()
		p := c.pending
		c.mu.Unlock()
		if p == nil || !p.accept(f, data) {
			c.log.Debug("response nobody waits for ignored", "seq", f.Control.Seq)
		}
	case app.FuncUnsolicitedResponse:
		if f.Control.CON {
			c.confirm(sess, f.Control.Seq, true)
		}
		c.mu.Lock()
		repeat := bytes.Equal(c.lastUns, data)
		c.lastUns = data
		c.mu.Unlock()
		if repeat {
			c.log.Debug("repeated unsolicited response ignored", "seq", f.Control.Seq)
			return
		}
		c.events.response(f, true)
		c.onIIN(f.IIN)
	default:
		c.log.Debug("request function sent to a master ignored", "function", f.Function.String())
	}
}

// confirm sends an application confirmation.
func (c *Client) confirm(sess *channel.Session, seq uint8, uns bool) {
	f := &app.Fragment{Control: app.Control{FIR: true, FIN: true, UNS: uns, Seq: seq}, Function: app.FuncConfirm}
	data, _ := f.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.responseTimeout)
	defer cancel()
	if err := sess.Send(ctx, data); err != nil {
		c.log.Debug("confirmation not sent", "error", err)
		return
	}
	if m := c.opts.metrics; m != nil {
		m.OnFragmentSent(c.remoteAddr(), f, len(data))
	}
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

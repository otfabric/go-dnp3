// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/internal/logx"
)

// WithDualEndpoint makes the client a TCP dual end point (IEEE 1815-2012
// clause 13.2.3.1.3, Figure 13-7): it dials the outstation at the address
// given to New, as without the option, and also takes the connections the
// outstation establishes on l, for example to report unsolicited
// responses. Only one connection is in place at a time:
//
//   - A connection the outstation establishes while the client has none
//     is used: at once when the client is idle or waits to reconnect, and
//     by a Connect in progress when its own dial fails.
//   - One that arrives while the client is connected is closed. So is one
//     that arrives while the client's own dial succeeds: the master has
//     priority on the creation of TCP connections.
//
// allow, when not nil, validates the outstation's address (clause
// 13.2.3.1.4 b): a connection from an address it refuses is closed. The
// end point listens from the first Connect; Close closes l. With WithTLS,
// give a listener of tls.NewListener: the client is the TLS server of the
// connections it takes. WithStream excludes the option.
//
//	l, _ := net.Listen("tcp", ":20000")
//	c, err := client.New("192.0.2.10:20000", client.WithDualEndpoint(l, nil))
func WithDualEndpoint(l net.Listener, allow func(net.Addr) bool) Option {
	return func(o *options) error {
		if l == nil {
			return invalidOption("WithDualEndpoint: nil listener")
		}
		o.dualListener, o.dualAllow = l, allow
		return nil
	}
}

// dualEndpoint holds the listening side of WithDualEndpoint.
type dualEndpoint struct {
	c     *Client
	l     net.Listener
	allow func(net.Addr) bool
	once  sync.Once
	// wake ends a reconnect wait when the outstation connects.
	wake chan struct{}

	mu sync.Mutex
	// inUse is set while a connection of the end point, dialed or taken,
	// is open.
	inUse bool
	// queued is a connection the outstation established while none was
	// in use, waiting to be taken.
	queued net.Conn
	closed bool
}

// woken returns the channel a reconnect wait selects on: never ready
// without a dual end point.
func (d *dualEndpoint) woken() <-chan struct{} {
	if d == nil {
		return nil
	}
	return d.wake
}

// open returns the connection of the next channel: a waiting connection
// of the outstation, else the client's own, else one the outstation
// established while the dial failed.
func (d *dualEndpoint) open(ctx context.Context) (channel.Stream, net.Addr, error) {
	d.once.Do(func() {
		// Under c.mu, as in connect: no accept after Close.
		d.c.mu.Lock()
		defer d.c.mu.Unlock()
		if d.c.closed {
			return
		}
		d.c.wg.Add(1)
		go d.accept()
	})
	if conn := d.take(); conn != nil {
		return d.use(ctx, conn)
	}
	conn, err := d.c.dial(ctx)
	if err == nil {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			_ = conn.Close()
			return nil, nil, dnp3.ErrClosed
		}
		d.inUse = true
		q := d.queued
		d.queued = nil
		d.mu.Unlock()
		if q != nil {
			d.c.log.Info("outstation connection dropped: the master's connection has priority", "remote_addr", q.RemoteAddr().String())
			_ = q.Close()
		}
		return &dualConn{Conn: conn, d: d}, conn.RemoteAddr(), nil
	}
	if conn := d.take(); conn != nil {
		return d.use(ctx, conn)
	}
	return nil, nil, err
}

// take returns the waiting connection of the outstation, marking it in
// use, or nil.
func (d *dualEndpoint) take() net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	conn := d.queued
	d.queued = nil
	if conn != nil {
		d.inUse = true
	}
	return conn
}

// use completes the TLS handshake of a connection the outstation
// established, when it has one, and returns it as the channel's stream.
func (d *dualEndpoint) use(ctx context.Context, conn net.Conn) (channel.Stream, net.Addr, error) {
	if hs, ok := conn.(interface {
		HandshakeContext(context.Context) error
	}); ok {
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		// The handshake runs the callbacks of the application's tls.Config.
		err := logx.Do(d.c.log, "TLS handshake", func() error { return hs.HandshakeContext(hctx) })
		cancel()
		if err != nil {
			_ = conn.Close()
			d.release()
			return nil, nil, fmt.Errorf("TLS handshake: %w", err)
		}
	}
	d.c.log.Info("outstation connected to the dual end point", "remote_addr", conn.RemoteAddr().String())
	return &dualConn{Conn: conn, d: d}, conn.RemoteAddr(), nil
}

// release marks the end point free: its connection has closed.
func (d *dualEndpoint) release() {
	d.mu.Lock()
	d.inUse = false
	d.mu.Unlock()
}

// accept takes the connections the outstation establishes, until l is
// closed.
func (d *dualEndpoint) accept() {
	defer d.c.wg.Done()
	var delay time.Duration
	for {
		// The listener and allow are the application's: an Accept that does
		// not return normally is an Accept error, an allow that does not
		// refuses the connection.
		conn, err := logx.Call(d.c.log, "net.Listener.Accept", d.l.Accept)
		if err != nil {
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			d.c.log.Warn("dual end point accept failed", "error", err)
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			select {
			case <-d.c.closeCh:
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		remote := conn.RemoteAddr()
		if d.allow != nil && !d.allowed(remote) {
			d.c.log.Warn("outstation connection refused: address not allowed", "remote_addr", remote.String())
			_ = conn.Close()
			continue
		}
		d.mu.Lock()
		switch {
		case d.closed:
			d.mu.Unlock()
			_ = conn.Close()
			continue
		case d.inUse:
			// Only one connection to the same device at a time (clause
			// 13.2.3.1.3; Figure 13-7, "reject S'IN").
			d.mu.Unlock()
			d.c.log.Warn("outstation connection refused: already connected", "remote_addr", remote.String())
			_ = conn.Close()
			continue
		}
		old := d.queued
		d.queued = conn
		d.mu.Unlock()
		if old != nil {
			_ = old.Close() // the newer connection replaces one not yet taken
		}
		d.c.takeIncoming()
	}
}

// allowed is allow, false when allow does not return normally.
func (d *dualEndpoint) allowed(remote net.Addr) bool {
	ok, _ := logx.Call(d.c.log, "WithDualEndpoint allow", func() (bool, error) { return d.allow(remote), nil })
	return ok
}

// close stops the end point: it closes l and a connection not yet taken.
func (d *dualEndpoint) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.closed = true
	q := d.queued
	d.queued = nil
	d.mu.Unlock()
	_ = logx.Do(d.c.log, "net.Listener.Close", d.l.Close)
	if q != nil {
		_ = q.Close()
	}
}

// dualConn is a connection of the dual end point; closing it frees the
// end point for the next one.
type dualConn struct {
	net.Conn
	d    *dualEndpoint
	once sync.Once
}

func (c *dualConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.d.release)
	return err
}

// takeIncoming connects the client over a connection the outstation
// established on the dual end point: at once when the client is idle,
// else by waking a reconnect wait. A Connect in progress takes it itself
// when its dial fails.
func (c *Client) takeIncoming() {
	c.mu.Lock()
	switch {
	case c.closed || c.ch != nil:
		c.mu.Unlock()
		return
	case c.dialing:
		c.mu.Unlock()
		select {
		case c.dual.wake <- struct{}{}:
		default:
		}
		return
	}
	c.dialing = true
	c.mu.Unlock()
	c.wg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		go func() {
			select {
			case <-c.closeCh:
				cancel()
			case <-ctx.Done():
			}
		}()
		if err := c.establish(ctx); err != nil {
			c.log.Warn("connection of the outstation failed", "error", err)
		}
	})
}

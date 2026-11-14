// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/logx"
)

// Redial configures how DialAndServe reconnects: with exponential backoff
// between failed attempts.
type Redial struct {
	// MinDelay is the delay after the first failure; it doubles after each
	// further one. Zero means 1 second.
	MinDelay time.Duration
	// MaxDelay caps the delay. Zero means 1 minute.
	MaxDelay time.Duration
	// Jitter randomizes each delay, so that outstations that lost their
	// connections together do not reconnect together: a fraction from 0
	// to 1, each delay is drawn uniformly from [(1-Jitter)·d, d] of the
	// delay d that doubles. Zero, the default, waits d exactly. It has the
	// semantics of client.Reconnect.Jitter.
	Jitter float64
}

// DialAndServe is the outstation's end of a TCP connection that the
// outstation establishes (the dual end point of IEEE 1815-2012 clause
// 13.2.3.1.3, for an outstation behind a firewall or on a dial-out link):
// it connects to the master at addr, with TLS when WithTLS was given (the
// outstation is then the TLS client: the configuration's RootCAs verify
// the master, its Certificates are presented, ServerName defaults to the
// host of addr), serves the connection like an accepted one, and connects
// again when it ends, with the delays of r. It returns when ctx is done
// (ctx.Err()) or the server is closed (nil).
//
// Only one connection to the master stands at a time, and the master's
// own has priority (clause 13.2.3.1.3): while a master is connected to
// the server's listener, DialAndServe does not connect, and checks again
// every r.MinDelay.
//
// The connection is opened by the dialer of WithDialer, by default a
// net.Dialer. A failed attempt is logged with an error that wraps
// dnp3.ErrConnectFailed and the dialer's error. DialAndServe fails with
// dnp3.ErrInvalidOption when r.Jitter is not within [0, 1].
func (s *Server) DialAndServe(ctx context.Context, addr string, r Redial) error {
	if !validJitter(r.Jitter) {
		return invalidOption("redial jitter %v not within [0, 1]", r.Jitter)
	}
	if r.MinDelay <= 0 {
		r.MinDelay = time.Second
	}
	if r.MaxDelay <= 0 {
		r.MaxDelay = time.Minute
	}
	if r.MaxDelay < r.MinDelay {
		r.MaxDelay = r.MinDelay
	}
	// Close and ctx both end a connection being served.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.closeCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	delay := r.MinDelay
	for {
		if s.isClosed() {
			return nil
		}
		if s.streamConnected() {
			select {
			case <-time.After(r.MinDelay):
				continue
			case <-ctx.Done():
				if s.isClosed() {
					return nil
				}
				return ctx.Err()
			}
		}
		conn, err := s.dial(ctx, addr)
		if err == nil {
			delay = r.MinDelay
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			var remote net.Addr
			remote, err = logx.Call(s.log, "net.Conn.RemoteAddr", func() (net.Addr, error) { return conn.RemoteAddr(), nil })
			if err == nil {
				err = s.ServeConn(conn, remote)
			} else {
				_ = logx.Do(s.log, "net.Conn.Close", conn.Close)
			}
			stop()
		}
		if s.isClosed() {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := jittered(delay, r.Jitter)
		s.log.Info("connection to the master lost, reconnecting", "address", addr, "error", err, "delay", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			if s.isClosed() {
				return nil
			}
			return ctx.Err()
		}
		delay = min(2*delay, r.MaxDelay)
	}
}

// errNoConn is the error of an attempt whose dialer returned neither a
// connection nor an error.
var errNoConn = errors.New("dialer returned neither a connection nor an error")

// dial opens a connection to the master, with TLS when configured. Its
// errors wrap dnp3.ErrConnectFailed and the cause.
func (s *Server) dial(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := dialConn(ctx, s.log, s.opts.dialer, addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", dnp3.ErrConnectFailed, err)
	}
	if s.opts.tls == nil {
		return conn, nil
	}
	cfg := s.opts.tls.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName, _, _ = net.SplitHostPort(addr)
	}
	tc := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	// The handshake runs the callbacks of the application's tls.Config.
	if err := logx.Do(s.log, "TLS handshake", func() error { return tc.HandshakeContext(hctx) }); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: TLS handshake: %w", dnp3.ErrConnectFailed, err)
	}
	return tc, nil
}

// dialConn opens a TCP connection with d, or with the default net.Dialer
// when d is nil, under the dial timeout, and holds d to the contract of
// net.Dialer: a connection exactly when the error is nil. A dialer that
// does not return normally fails the attempt; log reports it.
func dialConn(ctx context.Context, log *logx.Logger, d Dialer, addr string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{Timeout: handshakeTimeout}
	}
	dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := logx.Call(log, "Dialer.DialContext", func() (net.Conn, error) { return d.DialContext(dctx, "tcp", addr) })
	switch {
	case err != nil:
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	case conn == nil:
		return nil, errNoConn
	}
	return conn, nil
}

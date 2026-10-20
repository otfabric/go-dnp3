// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Redial configures how DialAndServe reconnects: with exponential backoff
// between failed attempts.
type Redial struct {
	// MinDelay is the delay after the first failure; it doubles after each
	// further one. Zero means 1 second.
	MinDelay time.Duration
	// MaxDelay caps the delay. Zero means 1 minute.
	MaxDelay time.Duration
}

// DialAndServe is the outstation's end of a TCP connection that the
// outstation establishes (the dual end point of IEEE 1815-2012 annex
// A.3, for an outstation behind a firewall or on a dial-out link): it
// connects to the master at addr, with TLS when WithTLS was given (the
// outstation is then the TLS client: the configuration's RootCAs verify
// the master, its Certificates are presented, ServerName defaults to the
// host of addr), serves
// the connection like an accepted one, and connects again when it ends,
// with the delays of r. It returns when ctx is done (ctx.Err()) or the
// server is closed (nil).
func (s *Server) DialAndServe(ctx context.Context, addr string, r Redial) error {
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
		conn, err := s.dial(ctx, addr)
		if err == nil {
			delay = r.MinDelay
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			err = s.ServeConn(conn, conn.RemoteAddr())
			stop()
		}
		if s.isClosed() {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.log.Info("connection to the master lost, reconnecting", "address", addr, "error", err, "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			if s.isClosed() {
				return nil
			}
			return ctx.Err()
		}
		delay = min(2*delay, r.MaxDelay)
	}
}

func (s *Server) dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if s.opts.tls == nil {
		return conn, nil
	}
	cfg := s.opts.tls.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName, _, _ = net.SplitHostPort(addr)
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

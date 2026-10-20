// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// Result is the answer of the outstation to a request.
type Result struct {
	// IIN are the internal indications of the last fragment.
	IIN app.IIN
	// Fragments are the response fragments, in order. Empty for requests
	// without a response.
	Fragments []*app.Fragment

	// request is the encoding of the request as sent; a session key
	// change's confirmation is a MAC over it.
	request []byte
}

// Measurements returns the measurements of all fragments.
func (r *Result) Measurements() []Measurement {
	var out []Measurement
	for _, f := range r.Fragments {
		out = append(out, Measurements(f)...)
	}
	return out
}

// Headers returns the object headers of all fragments.
func (r *Result) Headers() []app.Header {
	var out []app.Header
	for _, f := range r.Fragments {
		out = append(out, f.Headers...)
	}
	return out
}

// transaction is one request waiting for its response.
type transaction struct {
	frags chan received
	errc  chan error
}

// received is a response fragment with its encoding, which secure
// authentication needs exactly as it was sent.
type received struct {
	f   *app.Fragment
	raw []byte
}

func newTransaction() *transaction {
	return &transaction{frags: make(chan received, 16), errc: make(chan error, 1)}
}

// accept takes a response fragment, on the session's goroutine.
func (t *transaction) accept(f *app.Fragment, raw []byte) bool {
	select {
	case t.frags <- received{f, raw}:
		return true
	default:
		return false
	}
}

func (t *transaction) fail(err error) {
	if err == nil {
		err = dnp3.ErrClosed
	}
	select {
	case t.errc <- err:
	default:
	}
}

// acquire waits for the client's turn: one transaction at a time.
func (c *Client) acquire(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return dnp3.ErrClosed
	}
	if c.waiting >= c.opts.queueLimit {
		c.mu.Unlock()
		return fmt.Errorf("%w: %d requests waiting", dnp3.ErrBusy, c.waiting)
	}
	c.waiting++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.waiting--
		c.mu.Unlock()
	}()
	select {
	case c.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closeCh:
		return dnp3.ErrClosed
	}
}

func (c *Client) release() { <-c.turn }

// exchange sends one request and collects its response. The caller holds
// the turn.
func (c *Client) exchange(ctx context.Context, fc app.FunctionCode, hs []app.Header) (*Result, error) {
	c.mu.Lock()
	sess := c.sess
	if sess == nil {
		c.mu.Unlock()
		return nil, dnp3.ErrNotConnected
	}
	seq := c.seq
	c.seq = app.NextSeq(seq)
	t := newTransaction()
	c.pending = t
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.pending == t {
			c.pending = nil
		}
		c.mu.Unlock()
	}()

	req := &app.Fragment{Control: app.SingleControl(seq), Function: fc, Headers: hs}
	if err := c.aggressive(req); err != nil {
		return nil, err
	}
	data, err := req.Encode()
	if err != nil {
		return nil, err
	}
	if c.log.DebugEnabled() {
		c.log.DebugContext(ctx, "request sent", "fragment", req.String())
	}
	if err := sess.Send(ctx, data); err != nil {
		return nil, sendError(err)
	}
	if m := c.opts.metrics; m != nil {
		m.OnFragmentSent(c.remoteAddr(), req, len(data))
	}
	res := &Result{request: data}
	if fc.NoAck() {
		return res, nil
	}

	timer := time.NewTimer(c.opts.responseTimeout)
	defer timer.Stop()
	expect := seq
	for {
		select {
		case rf := <-t.frags:
			f := rf.f
			if f.Function == app.FuncAuthResponse {
				next, err := c.onAuthResponse(ctx, sess, f, rf.raw, data)
				if err != nil {
					if fc != app.FuncAuthRequest && errors.Is(err, dnp3.ErrAuthentication) {
						// The outstation refused the session keys, or there
						// are none: change them now rather than at the next
						// interval (IEEE 1815-2012 clause 7.5.2.3).
						c.rekeySoon()
					}
					return res, err
				}
				if next >= 0 {
					expect = uint8(next)
					timer.Reset(c.opts.responseTimeout)
					continue
				}
			}
			first := len(res.Fragments) == 0
			if f.Control.Seq != expect || f.Control.FIR != first {
				c.log.Debug("response fragment out of sequence ignored", "seq", f.Control.Seq, "want", expect)
				continue
			}
			if f.Control.CON {
				c.confirm(sess, f.Control.Seq, false)
			}
			res.Fragments = append(res.Fragments, f)
			res.IIN = f.IIN
			c.events.response(f, false)
			if f.Control.FIN {
				c.onIIN(f.IIN)
				if bits := f.IIN & dnp3.IINErrorBits; bits != 0 {
					return res, &dnp3.IINError{Function: fc, IIN: f.IIN}
				}
				return res, nil
			}
			expect = app.NextSeq(expect)
			timer.Reset(c.opts.responseTimeout)
		case err := <-t.errc:
			return res, fmt.Errorf("%w: %w", dnp3.ErrConnectionLost, err)
		case <-timer.C:
			return res, fmt.Errorf("%w: no response to %s (seq %d) within %v", dnp3.ErrTimeout, fc, expect, c.opts.responseTimeout)
		case <-ctx.Done():
			return res, ctx.Err()
		case <-c.closeCh:
			return res, dnp3.ErrClosed
		}
	}
}

func sendError(err error) error {
	switch {
	case errors.Is(err, dnp3.ErrConnectionLost), errors.Is(err, dnp3.ErrClosed),
		errors.Is(err, dnp3.ErrTimeout), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: %w", dnp3.ErrConnectionLost, err)
	}
}

// do runs fn with the turn held, reporting to metrics and repeating it as
// WithRetry says when idempotent.
func (c *Client) do(ctx context.Context, fc app.FunctionCode, idempotent bool, fn func(ctx context.Context) error) error {
	remote := c.remoteAddr()
	out := uint16(c.opts.remote)
	if c.rm != nil {
		c.rm.OnRequest(remote, out, fc)
	}
	start := time.Now()
	attempts := 1
	var backoff time.Duration
	if r := c.opts.retry; r != nil && idempotent {
		attempts, backoff = r.Attempts, r.Backoff
	}
	var err error
	for i := 1; ; i++ {
		err = c.attempt(ctx, fn)
		if err == nil || i >= attempts || !retryable(ctx, err) {
			break
		}
		c.log.WarnContext(ctx, "request failed, retrying", "function", fc.String(), "attempt", i,
			"retry_in", backoff.String(), "error", err)
		if c.rm != nil {
			c.rm.OnRetry(remote, out, fc, i, err)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			err = ctx.Err()
		case <-c.closeCh:
			err = dnp3.ErrClosed
		}
		if ctx.Err() != nil || c.isClosed() {
			break
		}
		backoff = min(2*backoff, c.opts.retry.MaxBackoff)
	}
	if c.rm != nil {
		c.rm.OnRequestDone(c.remoteAddr(), out, fc, time.Since(start), err)
	}
	return err
}

func (c *Client) attempt(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	return fn(ctx)
}

// retryable reports whether a failed attempt may be repeated: transport
// failures and timeouts, while the caller's context is still alive.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	return errors.Is(err, dnp3.ErrTimeout) || errors.Is(err, dnp3.ErrConnectionLost) || errors.Is(err, dnp3.ErrNotConnected)
}

// request is a single exchange through do.
func (c *Client) request(ctx context.Context, fc app.FunctionCode, idempotent bool, hs ...app.Header) (*Result, error) {
	var res *Result
	err := c.do(ctx, fc, idempotent, func(ctx context.Context) error {
		var err error
		res, err = c.exchange(ctx, fc, hs)
		return err
	})
	return res, err
}

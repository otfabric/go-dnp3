// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
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
	// raw are the encodings of Fragments, as received.
	raw [][]byte
	// sending and sent are when the request was handed to the link layer
	// and when that returned; arrived is when the first fragment of the
	// response reached the client.
	sending, sent, arrived time.Time
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
// authentication needs exactly as it was sent, and the time it reached the
// client.
type received struct {
	f   *app.Fragment
	raw []byte
	at  time.Time
}

func newTransaction() *transaction {
	return &transaction{frags: make(chan received, 16), errc: make(chan error, 1)}
}

// accept takes a response fragment, on the session's goroutine.
func (t *transaction) accept(f *app.Fragment, raw []byte, at time.Time) bool {
	select {
	case t.frags <- received{f, raw, at}:
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
	if n := c.waiting; n >= c.opts.queueLimit {
		c.mu.Unlock()
		return fmt.Errorf("%w: %d requests waiting", dnp3.ErrBusy, n)
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
//
// The request takes the next sequence number only once it is about to be
// sent: one refused before (WithMaxRequestFragment) leaves no gap (IEEE
// 1815-2012 clause 4.3 Rule 14). The response is received as Table 6-2 of
// clause 6.3 says: awaiting its first fragment, a fragment that is not
// the first (FIR) or has another sequence number is discarded (rows 3 and
// 5); during a multi-fragment response, a repeat of the last fragment is
// confirmed again (rows 8 and 14), and any other fragment but the next
// abandons the response with dnp3.ErrProtocol, unconfirmed (rows 9, 11,
// 13 and 15 to 17).
func (c *Client) exchange(ctx context.Context, fc app.FunctionCode, hs []app.Header) (*Result, error) {
	c.mu.Lock()
	sess := c.sess
	seq := c.seq
	c.mu.Unlock()
	if sess == nil {
		return nil, dnp3.ErrNotConnected
	}
	req := &app.Fragment{Control: app.SingleControl(seq), Function: fc, Headers: hs}
	if err := c.fits(req); err != nil {
		return nil, err
	}
	aggressive, err := c.aggressive(req)
	if err != nil {
		return nil, err
	}
	data, err := req.Encode()
	if err != nil {
		return nil, err
	}
	if lim := c.opts.maxTxFragment; lim > 0 && len(data) > lim {
		return nil, invalidOption("%s request of %d octets exceeds the request fragment limit of %d (WithMaxRequestFragment)", fc, len(data), lim)
	}
	t := newTransaction()
	c.mu.Lock()
	c.seq = app.NextSeq(seq)
	c.pending = t
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.pending == t {
			c.pending = nil
		}
		c.mu.Unlock()
	}()

	if c.log.DebugEnabled() {
		c.log.DebugContext(ctx, "request sent", "fragment", req.String())
	}
	res := &Result{request: data}
	c.proc.sendMu.Lock()
	res.sending = time.Now()
	if isTimeSync(fc, hs) {
		// IEEE 1815-2012 clause 10.3.4.1: as unconfirmed user data, with
		// no link layer retries.
		err = sess.SendUnconfirmed(ctx, data)
	} else {
		err = sess.Send(ctx, data)
	}
	res.sent = time.Now()
	c.proc.sendMu.Unlock()
	if err != nil {
		return nil, sendError(err)
	}
	c.sent(req, len(data))
	if fc.NoAck() {
		if aggressive {
			return res, nil
		}
		return res, c.noAckChallenge(ctx, sess, t, fc, seq, data)
	}

	timer := time.NewTimer(c.opts.responseTimeout)
	defer timer.Stop()
	expect := seq
	var last []byte // the last fragment accepted
	challenged := false
	for {
		select {
		case rf := <-t.frags:
			f := rf.f
			if f.Function == app.FuncAuthResponse {
				// Secure authentication: a challenge of the request or of
				// a CONFIRM, or an error (IEEE 1815-2012 clauses 7.5.1.3,
				// 7.5.2.3.2 j).
				critical, ofRequest := c.challenged(f.Control.Seq, seq, data, len(res.Fragments) > 0)
				if critical == nil {
					c.onStrayAuth(sess, f, rf.raw)
					continue
				}
				next, err := c.onAuthResponse(ctx, sess, f, rf.raw, critical)
				if err != nil {
					c.onAuthFailure(fc, aggressive, err)
					return res, err
				}
				if next >= 0 {
					if ofRequest {
						expect, challenged = uint8(next&0x0F), true // an application sequence number, 0..15
					}
					timer.Reset(c.opts.responseTimeout)
					continue
				}
			}
			if len(res.Fragments) == 0 {
				// AwaitFirst.
				if f.Control.Seq != expect || !f.Control.FIR {
					c.log.Debug("response fragment out of sequence ignored", "seq", f.Control.Seq, "want", expect)
					continue
				}
				res.arrived = rf.at
				if challenged {
					c.challengeAccepted()
				}
			} else {
				// Assembly.
				if bytes.Equal(rf.raw, last) {
					c.log.Debug("repeated response fragment", "seq", f.Control.Seq)
					c.confirmSolicited(sess, f, rf.raw)
					timer.Reset(c.opts.responseTimeout)
					continue
				}
				if f.Control.Seq != expect || f.Control.FIR {
					return res, fmt.Errorf("%w: response fragment seq %d (FIR %t) where seq %d was due: %s response abandoned",
						dnp3.ErrProtocol, f.Control.Seq, f.Control.FIR, expect, fc)
				}
			}
			if f.Control.FIN {
				// What follows the last fragment, such as a challenge of
				// its CONFIRM (IEEE 1815-2012 clause 7.5.2.3.2 j), is no
				// longer this request's.
				c.mu.Lock()
				if c.pending == t {
					c.pending = nil
				}
				c.mu.Unlock()
			}
			c.confirmSolicited(sess, f, rf.raw)
			last = rf.raw
			res.Fragments = append(res.Fragments, f)
			res.raw = append(res.raw, rf.raw)
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

// confirmSolicited confirms a solicited response fragment that asks for it
// (CON), raw as received, unless WithSolicitedConfirm turned that off.
func (c *Client) confirmSolicited(sess *channel.Session, f *app.Fragment, raw []byte) {
	if !f.Control.CON {
		return
	}
	if c.opts.noSolConfirm {
		c.log.Debug("response not confirmed (WithSolicitedConfirm)", "seq", f.Control.Seq)
		return
	}
	c.confirmResponse(sess, f, raw, false)
}

// fits checks, with WithMaxRequestFragment, that a request fits the
// request fragment limit before secure authentication adds its aggressive
// mode objects, so that a request refused for its size does not use up a
// challenge sequence number.
func (c *Client) fits(req *app.Fragment) error {
	lim := c.opts.maxTxFragment
	if lim == 0 {
		return nil
	}
	data, err := req.Encode()
	if err != nil {
		return err
	}
	if len(data) > lim {
		return invalidOption("%s request of %d octets exceeds the request fragment limit of %d (WithMaxRequestFragment)", req.Function, len(data), lim)
	}
	return nil
}

// isTimeSync reports whether a request is a time synchronization message
// of IEEE 1815-2012 clause 10.3.4.1: DELAY_MEASURE, RECORD_CURRENT_TIME or
// a WRITE of g50v1 or g50v3.
func isTimeSync(fc app.FunctionCode, hs []app.Header) bool {
	switch fc {
	case app.FuncDelayMeasure, app.FuncRecordCurrentTime:
		return true
	case app.FuncWrite:
		for _, h := range hs {
			if h.GV == app.G50V1 || h.GV == app.G50V3 {
				return true
			}
		}
		return false
	default:
		return false
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

// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
)

// TestJitteredBounds: every jittered pause lies in [(1-f)·d, d], and the
// draws spread over that range.
func TestJitteredBounds(t *testing.T) {
	const d = 800 * time.Millisecond
	for _, f := range []float64{0.01, 0.25, 0.5, 1} {
		lo := d - time.Duration(f*float64(d))
		minSeen, maxSeen := d, time.Duration(0)
		for range 2000 {
			w := jittered(d, f)
			if w < lo || w > d {
				t.Fatalf("jitter %v: pause %v outside [%v, %v]", f, w, lo, d)
			}
			minSeen, maxSeen = min(minSeen, w), max(maxSeen, w)
		}
		if spread := maxSeen - minSeen; spread < (d-lo)/2 {
			t.Errorf("jitter %v: pauses spread over %v of %v", f, spread, d-lo)
		}
	}
}

// TestJitteredZero: without jitter the pause is the delay exactly, as
// before Jitter existed; a zero delay stays zero.
func TestJitteredZero(t *testing.T) {
	for _, d := range []time.Duration{0, time.Nanosecond, time.Millisecond, time.Minute} {
		for range 100 {
			if w := jittered(d, 0); w != d {
				t.Fatalf("jittered(%v, 0) = %v", d, w)
			}
		}
	}
	if w := jittered(0, 1); w != 0 {
		t.Fatalf("jittered(0, 1) = %v", w)
	}
}

// TestJitterValidation: WithRetry and WithReconnect refuse a jitter
// outside [0, 1] with dnp3.ErrInvalidOption and accept 0 and 1.
func TestJitterValidation(t *testing.T) {
	for _, f := range []float64{-0.1, 1.01, math.NaN(), math.Inf(1)} {
		if _, err := New("127.0.0.1", WithRetry(Retry{Attempts: 2, Jitter: f})); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("retry jitter %v: %v", f, err)
		}
		if _, err := New("127.0.0.1", WithReconnect(Reconnect{Jitter: f})); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("reconnect jitter %v: %v", f, err)
		}
	}
	for _, f := range []float64{0, 0.5, 1} {
		c, err := New("127.0.0.1", WithRetry(Retry{Attempts: 2, Jitter: f}), WithReconnect(Reconnect{Jitter: f}))
		if err != nil {
			t.Fatalf("jitter %v: %v", f, err)
		}
		if c.opts.retry.Jitter != f || c.opts.reconnect.Jitter != f {
			t.Fatalf("jitter %v kept as %v and %v", f, c.opts.retry.Jitter, c.opts.reconnect.Jitter)
		}
		_ = c.Close()
	}
}

// TestRetryWithJitter: a request retried with full jitter still makes
// every attempt, each pause at most the doubling backoff.
func TestRetryWithJitter(t *testing.T) {
	addr := silent(t)
	m := &metrics{}
	c, err := Dial(testCtx(t), addr, WithResponseTimeout(50*time.Millisecond), WithStartup(Startup{}),
		WithRetry(Retry{Attempts: 3, Backoff: 200 * time.Millisecond, Jitter: 1}), WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	if _, err := c.IntegrityPoll(testCtx(t)); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("silent outstation: %v", err)
	}
	if m.retries.Load() != 2 {
		t.Fatalf("retries %d, want 2", m.retries.Load())
	}
	// Three timeouts of 50 ms and pauses of at most 200 and 400 ms.
	if el := time.Since(start); el < 150*time.Millisecond || el > 3*time.Second {
		t.Fatalf("retries took %v", el)
	}
}

// TestReconnectWithJitter: with Jitter the pause before each reconnect
// attempt lies in [(1-Jitter)·d, d] of the doubling delay d.
func TestReconnectWithJitter(t *testing.T) {
	const (
		minDelay = 40 * time.Millisecond
		maxDelay = 160 * time.Millisecond
		jitter   = 0.5
	)
	var mu sync.Mutex
	var dials []time.Time
	refuse := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, time.Now())
		mu.Unlock()
		return nil, errors.New("refused")
	})
	c, err := New("127.0.0.1:20000", WithDialer(refuse),
		WithReconnect(Reconnect{MinDelay: minDelay, MaxDelay: maxDelay, Jitter: jitter}))
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.dialing = true
	c.mu.Unlock()
	start := time.Now()
	c.wg.Go(c.reconnectLoop)
	time.Sleep(900 * time.Millisecond)
	_ = c.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(dials) < 4 {
		t.Fatalf("%d reconnect attempts in 900 ms, want at least 4", len(dials))
	}
	const slack = 60 * time.Millisecond // scheduling, under -race
	prev, d := start, minDelay
	for i, at := range dials {
		gap := at.Sub(prev)
		lo := d - time.Duration(jitter*float64(d))
		if gap < lo || gap > d+slack {
			t.Errorf("attempt %d after %v, want within [%v, %v]", i+1, gap, lo, d)
		}
		prev, d = at, min(2*d, maxDelay)
	}
}

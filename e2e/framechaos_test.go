// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// frameChaosSeed is the default seed of TestFrameChaos: the run is
// deterministic in which frames it drops, duplicates and reorders (the
// timing of the two sides is not). DNP3_CHAOS_SEED replaces it.
const frameChaosSeed = 1815

// frameProxy is a TCP proxy between a master and an outstation that reads
// whole link frames (IEEE 1815-2012 clause 9.2) and, while enabled, drops,
// duplicates and reorders them. Octets inside a frame are never changed:
// every frame that arrives passes its CRCs, so what the faults test is the
// transport function (clause 8) and the application layer (clause 4) above
// a link that loses, repeats and swaps frames.
type frameProxy struct {
	l       net.Listener
	target  string
	enabled atomic.Bool
	mu      sync.Mutex
	rng     *rand.Rand
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup

	frames, dropped, duplicated, reordered atomic.Int64
}

func newFrameProxy(t *testing.T, target string, seed int64) *frameProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &frameProxy{l: l, target: target, rng: rand.New(rand.NewSource(seed)), conns: map[net.Conn]struct{}{}}
	p.enabled.Store(true)
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(p.close)
	return p
}

func (p *frameProxy) addr() string { return p.l.Addr().String() }

func (p *frameProxy) float() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Float64()
}

func (p *frameProxy) accept() {
	defer p.wg.Done()
	for {
		in, err := p.l.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = in.Close()
			continue
		}
		p.mu.Lock()
		if p.conns == nil {
			p.mu.Unlock()
			_ = in.Close()
			_ = out.Close()
			return
		}
		p.conns[in], p.conns[out] = struct{}{}, struct{}{}
		p.mu.Unlock()
		p.wg.Add(2)
		go p.pump(in, out)
		go p.pump(out, in)
	}
}

// pump forwards the frames read from src to dst with the faults. A frame
// held back to be reordered goes out after the next frame, or after 30 ms
// when no other frame follows.
func (p *frameProxy) pump(src, dst net.Conn) {
	defer p.wg.Done()
	defer func() { _ = src.Close(); _ = dst.Close() }()
	frames := make(chan []byte)
	done := make(chan struct{})
	defer close(done)
	p.wg.Go(func() {
		defer close(frames)
		r := link.NewReader(src)
		for {
			f, err := r.ReadFrame()
			if errors.Is(err, link.ErrFraming) {
				continue
			}
			if err != nil {
				return
			}
			b, err := f.Encode()
			if err != nil {
				return
			}
			select {
			case frames <- b:
			case <-done:
				return
			}
		}
	})
	var held []byte
	flush := time.NewTimer(time.Hour)
	defer flush.Stop()
	write := func(b []byte) bool {
		_, err := dst.Write(b)
		return err == nil
	}
	for {
		select {
		case b, ok := <-frames:
			if !ok {
				return
			}
			p.frames.Add(1)
			if !p.enabled.Load() {
				if (held != nil && !write(held)) || !write(b) {
					return
				}
				held = nil
				continue
			}
			switch x := p.float(); {
			case x < 0.08:
				p.dropped.Add(1)
				continue
			case x < 0.16:
				p.duplicated.Add(1)
				if !write(b) {
					return
				}
			case x < 0.24 && held == nil:
				p.reordered.Add(1)
				held = b
				flush.Reset(30 * time.Millisecond)
				continue
			}
			if !write(b) {
				return
			}
			if held != nil {
				if !write(held) {
					return
				}
				held = nil
			}
		case <-flush.C:
			if held != nil {
				if !write(held) {
					return
				}
				held = nil
			}
		}
	}
}

func (p *frameProxy) close() {
	_ = p.l.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
	p.wg.Wait()
}

// expectedUnderFrameFaults reports whether err is a failure that lost,
// repeated or reordered frames may cause, as ERRORS.md documents: what
// expectedUnderChaos accepts, and dnp3.ErrProtocol for a multi-fragment
// response abandoned on an unexpected fragment (IEEE 1815-2012 Table 6-2).
func expectedUnderFrameFaults(err error) bool {
	return expectedUnderChaos(err) || errors.Is(err, dnp3.ErrProtocol)
}

// TestFrameChaos runs polls, controls and a file transfer through a proxy
// that drops, duplicates and reorders whole link frames, with a
// deterministic seed. While the faults last every request either succeeds
// with the data that was sent or fails with a documented error, no control
// runs more often than it was sent, and once the faults stop the session
// recovers without a new Connect.
func TestFrameChaos(t *testing.T) {
	duration := 3 * time.Second
	if testing.Short() {
		duration = time.Second
	}
	seed := chaosSeed(t, frameChaosSeed)

	files := newMemFS()
	content := bytes.Repeat([]byte("frame chaos "), 400) // several fragments
	files.files["/data.bin"] = content
	handler := &relay{status: app.StatusSuccess}
	srv, err := server.New(server.WithMasters(1), server.WithHandler(handler), server.WithFileServer(files))
	if err != nil {
		t.Fatal(err)
	}
	db := srv.Database()
	_ = db.AddAnalogInput(0, server.PointConfig{Class: 1}, app.Analog{Value: 0, Flags: app.FlagOnline})
	_ = db.AddBinaryOutput(0, server.PointConfig{}, app.Binary{Flags: app.FlagOnline})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()
	proxy := newFrameProxy(t, l.Addr().String(), seed)

	c, err := client.New(proxy.addr(),
		client.WithResponseTimeout(200*time.Millisecond), client.WithAutoIntegrity(false),
		client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond, Jitter: 0.5}),
		client.WithRetry(client.Retry{Attempts: 3, Backoff: 5 * time.Millisecond, Jitter: 0.5}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ccancel()
	for c.Connect(cctx) != nil && cctx.Err() == nil {
		time.Sleep(10 * time.Millisecond)
	}

	var written atomic.Int64
	var sent, succeeded atomic.Int64
	var mu sync.Mutex
	var unexpected []error
	fail := func(what string, err error) {
		if err == nil {
			return
		}
		if errors.Is(err, dnp3.ErrNotConnected) {
			time.Sleep(time.Millisecond)
		}
		if !expectedUnderFrameFaults(err) {
			mu.Lock()
			unexpected = append(unexpected, fmt.Errorf("%s: %w", what, err))
			mu.Unlock()
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func(ctx context.Context)) {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				f(ctx)
				cancel()
			}
		})
	}
	run(func(context.Context) {
		n := written.Load() + 1
		written.Store(n)
		_ = db.UpdateAnalogInput(0, app.Analog{Value: float64(n), Flags: app.FlagOnline})
		time.Sleep(time.Millisecond)
	})
	run(func(ctx context.Context) {
		res, err := c.IntegrityPoll(ctx)
		fail("integrity poll", err)
		if err == nil {
			for _, m := range res.Measurements() {
				if a, ok := m.Value.(app.Analog); ok && (a.Value < 0 || a.Value > float64(written.Load())) {
					fail("integrity poll", fmt.Errorf("analog value %v never written", a.Value))
				}
			}
		}
	})
	run(func(ctx context.Context) {
		sent.Add(1)
		_, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0))
		if err == nil {
			succeeded.Add(1)
		}
		fail("operate", err)
	})
	run(func(ctx context.Context) {
		var buf bytes.Buffer
		_, err := c.ReadFile(ctx, "/data.bin", &buf, client.FileOptions{})
		fail("read file", err)
		if err == nil && !bytes.Equal(buf.Bytes(), content) {
			fail("read file", fmt.Errorf("%d octets differ from the file", buf.Len()))
		}
	})

	time.Sleep(duration)
	close(stop)
	wg.Wait()
	proxy.enabled.Store(false)
	t.Logf("%d frames: %d dropped, %d duplicated, %d reordered; %d of %d controls succeeded",
		proxy.frames.Load(), proxy.dropped.Load(), proxy.duplicated.Load(), proxy.reordered.Load(), succeeded.Load(), sent.Load())
	if proxy.dropped.Load() == 0 || proxy.duplicated.Load() == 0 || proxy.reordered.Load() == 0 {
		t.Errorf("not every fault happened: %d dropped, %d duplicated, %d reordered",
			proxy.dropped.Load(), proxy.duplicated.Load(), proxy.reordered.Load())
	}
	for _, err := range unexpected {
		t.Error(err)
	}
	_, ops, _ := handler.snapshot()
	if int64(len(ops)) > sent.Load() || int64(len(ops)) < succeeded.Load() {
		t.Errorf("%d controls executed for %d sent and %d succeeded", len(ops), sent.Load(), succeeded.Load())
	}

	// Without faults everything works again, on the same client.
	recovered := func(what string, f func(context.Context) error) {
		t.Helper()
		var err error
		for deadline := time.Now().Add(10 * time.Second); ; {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = f(ctx)
			cancel()
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Errorf("%s after the faults stopped: %v", what, err)
		}
	}
	recovered("integrity poll", func(ctx context.Context) error {
		res, err := c.IntegrityPoll(ctx)
		if err != nil {
			return err
		}
		for _, m := range res.Measurements() {
			if a, ok := m.Value.(app.Analog); ok && !m.Event && a.Value != float64(written.Load()) {
				return fmt.Errorf("analog input %v, database %d", a.Value, written.Load())
			}
		}
		return nil
	})
	recovered("control", func(ctx context.Context) error {
		_, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOff, 0, 0))
		return err
	})
	recovered("file", func(ctx context.Context) error {
		var buf bytes.Buffer
		if _, err := c.ReadFile(ctx, "/data.bin", &buf, client.FileOptions{}); err != nil {
			return err
		}
		if !bytes.Equal(buf.Bytes(), content) {
			return fmt.Errorf("%d octets differ from the file", buf.Len())
		}
		return nil
	})
}

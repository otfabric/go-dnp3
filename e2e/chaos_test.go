// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// chaosProxy is a TCP proxy between a master and an outstation that, while
// enabled, corrupts octets, splits and delays writes, and kills
// connections at random.
type chaosProxy struct {
	l       net.Listener
	target  string
	enabled atomic.Bool
	kills   atomic.Int64
	mu      sync.Mutex
	rng     *rand.Rand
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func newChaosProxy(t *testing.T, target string, seed int64) *chaosProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &chaosProxy{l: l, target: target, rng: rand.New(rand.NewSource(seed)), conns: map[net.Conn]struct{}{}}
	p.enabled.Store(true)
	p.wg.Add(2)
	go p.accept()
	go p.killer()
	t.Cleanup(p.close)
	return p
}

func (p *chaosProxy) addr() string { return p.l.Addr().String() }

func (p *chaosProxy) float() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Float64()
}

func (p *chaosProxy) intn(n int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Intn(n)
}

func (p *chaosProxy) accept() {
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
		p.conns[in], p.conns[out] = struct{}{}, struct{}{}
		p.mu.Unlock()
		p.wg.Add(2)
		go p.pump(in, out)
		go p.pump(out, in)
	}
}

// pump copies src to dst with the faults.
func (p *chaosProxy) pump(src, dst net.Conn) {
	defer p.wg.Done()
	defer func() { _ = src.Close(); _ = dst.Close() }()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		b := append([]byte(nil), buf[:n]...)
		if p.enabled.Load() {
			for i := range b {
				if p.float() < 0.0002 {
					b[i] ^= byte(1 << p.intn(8))
				}
			}
			if p.float() < 0.05 {
				time.Sleep(time.Duration(p.intn(20)) * time.Millisecond)
			}
		}
		// Split writes at random points: the reader must reassemble.
		for len(b) > 0 {
			k := len(b)
			if p.enabled.Load() && k > 1 && p.float() < 0.3 {
				k = 1 + p.intn(k-1)
			}
			if _, err := dst.Write(b[:k]); err != nil {
				return
			}
			b = b[k:]
		}
	}
}

// killer closes a random connection every few hundred milliseconds.
func (p *chaosProxy) killer() {
	defer p.wg.Done()
	for {
		time.Sleep(time.Duration(150+p.intn(400)) * time.Millisecond)
		p.mu.Lock()
		if p.conns == nil {
			p.mu.Unlock()
			return
		}
		if p.enabled.Load() && len(p.conns) > 0 {
			k := p.rng.Intn(len(p.conns))
			for c := range p.conns {
				if k == 0 {
					_ = c.Close()
					delete(p.conns, c)
					p.kills.Add(1)
					break
				}
				k--
			}
		}
		p.mu.Unlock()
	}
}

func (p *chaosProxy) close() {
	_ = p.l.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
	p.wg.Wait()
}

// expectedUnderChaos reports whether err is a failure faults may cause:
// a lost or not yet re-established connection, a timeout, a session key
// change or a file transfer cut short by the connection's end.
func expectedUnderChaos(err error) bool {
	var fe *dnp3.FileError
	switch {
	case errors.Is(err, dnp3.ErrTimeout), errors.Is(err, dnp3.ErrConnectionLost), errors.Is(err, dnp3.ErrNotConnected),
		errors.Is(err, dnp3.ErrAuthentication), errors.Is(err, context.DeadlineExceeded), errors.As(err, &fe):
		return true
	}
	return false
}

// TestChaos runs every kind of request at once through the chaos proxy,
// with and without secure authentication, and checks what must hold
// whatever the faults: no data that was not sent, no control executed
// more often than it was sent, and full recovery once the faults stop.
func TestChaos(t *testing.T) {
	duration := 3 * time.Second
	if testing.Short() {
		duration = time.Second
	}
	for _, sa := range []bool{false, true} {
		t.Run(fmt.Sprintf("secureAuth=%v", sa), func(t *testing.T) {
			seed := time.Now().UnixNano()
			t.Logf("seed %d", seed)
			baseline := runtime.NumGoroutine()

			files := newMemFS()
			content := make([]byte, 5000)
			for i := range content {
				content[i] = byte(i*7 + 3)
			}
			files.files["/data.bin"] = content
			handler := &relay{status: app.StatusSuccess}
			sopts := []server.Option{server.WithMasters(1), server.WithHandler(handler), server.WithFileServer(files)}
			copts := []client.Option{
				client.WithResponseTimeout(300 * time.Millisecond), client.WithAutoIntegrity(false),
				client.WithReconnect(client.Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}),
				client.WithRetry(client.Retry{Attempts: 3, Backoff: 5 * time.Millisecond}),
			}
			if sa {
				user := secauth.User{Number: 1, UpdateKey: []byte("0123456789abcdef")}
				sopts = append(sopts, server.WithSecureAuthentication(server.SecureAuth{User: user}))
				copts = append(copts, client.WithSecureAuthentication(user), client.WithKeyChangeInterval(200*time.Millisecond))
			}
			srv, err := server.New(sopts...)
			if err != nil {
				t.Fatal(err)
			}
			db := srv.Database()
			_ = db.AddAnalogInput(0, server.PointConfig{Class: 1}, app.Analog{Value: 0, Flags: app.FlagOnline})
			for i := range uint32(4) {
				_ = db.AddBinaryOutput(i, server.PointConfig{}, app.Binary{Flags: app.FlagOnline})
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve(l) }()
			proxy := newChaosProxy(t, l.Addr().String(), seed)

			c, err := client.New(proxy.addr(), copts...)
			if err != nil {
				t.Fatal(err)
			}
			cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer ccancel()
			for c.Connect(cctx) != nil && cctx.Err() == nil {
				time.Sleep(10 * time.Millisecond)
			}

			var written atomic.Int64 // the highest analog value the database holds
			var sent, succeeded atomic.Int64
			var unexpected []error
			var mu sync.Mutex
			fail := func(what string, err error) {
				if errors.Is(err, dnp3.ErrNotConnected) {
					time.Sleep(time.Millisecond) // not spinning while the link is down
				}
				if err != nil && !expectedUnderChaos(err) {
					mu.Lock()
					unexpected = append(unexpected, fmt.Errorf("%s: %w", what, err))
					mu.Unlock()
				}
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			run := func(f func(ctx context.Context)) {
				wg.Add(1)
				go func() {
					defer wg.Done()
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
				}()
			}
			// The database changes all the time.
			run(func(context.Context) {
				n := written.Load() + 1
				_ = db.UpdateAnalogInput(0, app.Analog{Value: float64(n), Flags: app.FlagOnline})
				written.Store(n)
				time.Sleep(time.Millisecond)
			})
			// Polls: every value read was written.
			run(func(ctx context.Context) {
				res, err := c.IntegrityPoll(ctx)
				fail("integrity poll", err)
				if err == nil {
					for _, m := range res.Measurements() {
						if a, ok := m.Value.(app.Analog); ok && (a.Value < 0 || a.Value > float64(written.Load()) || a.Value != float64(int64(a.Value))) {
							fail("integrity poll", fmt.Errorf("analog value %v never written", a.Value))
						}
					}
				}
				_, err = c.EventPoll(ctx)
				fail("event poll", err)
			})
			// Controls: counted when sent and when they succeed.
			run(func(ctx context.Context) {
				sent.Add(1)
				_, err := c.Operate(ctx, client.DirectOperate, client.CROB(uint32(sent.Load()%4), app.OpLatchOn, 0, 0))
				if err == nil {
					succeeded.Add(1)
				}
				fail("operate", err)
			})
			// A file of several blocks: when it arrives, it arrives intact.
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
			t.Logf("%d connections killed; %d of %d controls succeeded", proxy.kills.Load(), succeeded.Load(), sent.Load())
			for _, err := range unexpected {
				t.Error(err)
			}
			_, ops, _ := handler.snapshot()
			if int64(len(ops)) > sent.Load() || int64(len(ops)) < succeeded.Load() {
				t.Errorf("%d controls executed for %d sent and %d succeeded", len(ops), sent.Load(), succeeded.Load())
			}

			// Without faults everything works again.
			var res *client.Result
			deadline := time.Now().Add(10 * time.Second)
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				res, err = c.IntegrityPoll(ctx)
				cancel()
				if err == nil || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("no recovery after the faults stopped: %v", err)
			}
			for _, m := range res.Measurements() {
				if a, ok := m.Value.(app.Analog); ok && !m.Event && a.Value != float64(written.Load()) {
					t.Errorf("analog input after recovery %v, database %d", a.Value, written.Load())
				}
			}
			// Critical requests too, once the session keys are back: a
			// client that reconnected without them fails the first one at
			// once and changes the keys (secure authentication).
			eventually := func(what string, f func(context.Context) error) {
				t.Helper()
				var err error
				deadline := time.Now().Add(10 * time.Second)
				for {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					err = f(ctx)
					cancel()
					if err == nil || time.Now().After(deadline) {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				if err != nil {
					t.Errorf("%s after recovery: %v", what, err)
				}
			}
			eventually("control", func(ctx context.Context) error {
				_, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOff, 0, 0))
				return err
			})
			eventually("file", func(ctx context.Context) error {
				var buf bytes.Buffer
				if _, err := c.ReadFile(ctx, "/data.bin", &buf, client.FileOptions{}); err != nil {
					return err
				}
				if !bytes.Equal(buf.Bytes(), content) {
					return fmt.Errorf("%d octets differ from the file", buf.Len())
				}
				return nil
			})

			// Nothing is left running.
			_ = c.Close()
			_ = srv.Close()
			proxy.close()
			deadline = time.Now().Add(5 * time.Second)
			for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if n := runtime.NumGoroutine(); n > baseline+2 {
				buf := make([]byte, 1<<16)
				t.Errorf("%d goroutines after Close, %d before:\n%s", n, baseline, buf[:runtime.Stack(buf, true)])
			}
		})
	}
}

// TestParallelMastersSecureAuthAndFiles runs masters with their own
// session keys, key changes, challenged controls and file transfers at
// the same time against one outstation.
func TestParallelMastersSecureAuthAndFiles(t *testing.T) {
	const masters = 6
	addrs := make([]link.Address, masters)
	for i := range addrs {
		addrs[i] = link.Address(1 + i)
	}
	user := secauth.User{Number: 1, UpdateKey: []byte("0123456789abcdef")}
	files := newMemFS()
	handler := &relay{status: app.StatusSuccess}
	srv, err := server.New(server.WithMasters(addrs...), server.WithHandler(handler), server.WithFileServer(files),
		server.WithSecureAuthentication(server.SecureAuth{User: user}))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryOutput(0, server.PointConfig{}, app.Binary{Flags: app.FlagOnline})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	var wg sync.WaitGroup
	errs := make(chan error, masters)
	for i := range masters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c, err := client.Dial(ctx, l.Addr().String(), client.WithAddresses(addrs[i], 10), client.WithAutoIntegrity(false),
				client.WithSecureAuthentication(user), client.WithKeyChangeInterval(50*time.Millisecond),
				client.WithAggressiveMode(), client.WithResponseTimeout(3*time.Second))
			if err != nil {
				errs <- fmt.Errorf("master %d: %w", i, err)
				return
			}
			defer func() { _ = c.Close() }()
			name := fmt.Sprintf("/master-%d.bin", i)
			data := bytes.Repeat([]byte{byte(i)}, 3000+i*100)
			for round := range 10 {
				if _, err := c.Operate(ctx, client.SelectBeforeOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
					errs <- fmt.Errorf("master %d round %d control: %w", i, round, err)
					return
				}
				if _, err := c.WriteFile(ctx, name, bytes.NewReader(data), uint32(len(data)), client.FileOptions{}); err != nil {
					errs <- fmt.Errorf("master %d round %d write: %w", i, round, err)
					return
				}
				var back bytes.Buffer
				if _, err := c.ReadFile(ctx, name, &back, client.FileOptions{}); err != nil || !bytes.Equal(back.Bytes(), data) {
					errs <- fmt.Errorf("master %d round %d read back: %v", i, round, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if _, ops, _ := handler.snapshot(); len(ops) != masters*10 {
		t.Errorf("%d controls executed, want %d", len(ops), masters*10)
	}
}

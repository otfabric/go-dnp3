// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/internal/leaktest"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// pipeOutstation is an outstation of internal/channel at the far end of a
// net.Pipe, so that a client and it run in a synctest bubble. Requests are
// answered with answer's headers (a null response when answer is nil) and
// counted; confirmations are counted.
type pipeOutstation struct {
	sess     *channel.Session
	ch       *channel.Channel
	requests atomic.Int64
	confirms atomic.Int64
}

// newPipeOutstation serves the far end of a pipe.
func newPipeOutstation(far net.Conn, answer func(*app.Fragment) []app.Header) *pipeOutstation {
	o := &pipeOutstation{}
	o.ch = channel.New(far, channel.Config{})
	reqs := make(chan *app.Fragment, 64)
	o.sess = o.ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1, OnFragment: func(raw []byte, _ link.Address) {
		f, err := app.Decode(raw)
		if err != nil {
			return
		}
		if f.Function == app.FuncConfirm {
			o.confirms.Add(1)
			return
		}
		o.requests.Add(1)
		reqs <- f
	}})
	o.ch.Start()
	go func() {
		for {
			select {
			case r := <-reqs:
				var hs []app.Header
				if answer != nil {
					hs = answer(r)
				}
				o.send(&app.Fragment{Control: app.SingleControl(r.Control.Seq), Function: app.FuncResponse, Headers: hs})
			case <-o.ch.Done():
				return
			}
		}
	}()
	return o
}

// close ends the outstation's channel and waits for it.
func (o *pipeOutstation) close() {
	o.ch.Close(nil)
	<-o.ch.Done()
}

// pipeClient returns a connected client of a pipeOutstation.
func pipeClient(t *testing.T, answer func(*app.Fragment) []app.Header, opts ...Option) (*Client, *pipeOutstation) {
	t.Helper()
	near, far := net.Pipe()
	o := newPipeOutstation(far, answer)
	var once sync.Once
	open := func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
		var s io.ReadWriteCloser
		once.Do(func() { s = near })
		if s == nil {
			return nil, nil, errors.New("one stream only")
		}
		return s, near.RemoteAddr(), nil
	}
	c, err := New("outstation", append([]Option{WithStream(open), WithStartup(Startup{}), WithAutoIntegrity(false), WithAutoEventPoll(false)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		o.close()
	})
	return c, o
}

func (o *pipeOutstation) send(f *app.Fragment) {
	b, err := f.Encode()
	if err != nil {
		panic(err)
	}
	_ = o.sess.Send(context.Background(), b)
}

// unsolicitedNo is the i-th of a series of unsolicited responses, each with
// another point, asking for confirmation.
func unsolicitedNo(i int, iin app.IIN) *app.Fragment {
	return &app.Fragment{Control: app.Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: uint8(i & 0x0F)},
		Function: app.FuncUnsolicitedResponse, IIN: iin,
		Headers: []app.Header{app.Indexed(app.G2V1, app.Object{Index: uint32(i), Value: app.Binary{Value: true, Flags: app.FlagOnline}})}}
}

// TestHandlerQueueBounded: while the handler has 64 fragments it has not
// taken, an unsolicited response is neither processed nor confirmed, so
// the outstation keeps its events and repeats it; once the handler catches
// up, the repeat is taken.
func TestHandlerQueueBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var delivered atomic.Int64
		c, o := pipeClient(t, nil, WithHandler(HandlerFunc(func(ResponseInfo, []Measurement) {
			<-release
			delivered.Add(1)
		})))
		const sent = 200
		for i := range sent {
			o.send(unsolicitedNo(i, 0))
			synctest.Wait()
		}
		c.events.mu.Lock()
		queued := len(c.events.queue)
		c.events.mu.Unlock()
		// One notice is with the handler, the others wait.
		if queued+1 > 64 {
			t.Errorf("%d unsolicited responses with the handler blocked: %d notices held, want at most 64", sent, queued+1)
		}
		if got := o.confirms.Load(); got != 64 {
			t.Errorf("%d unsolicited responses confirmed, want the 64 taken", got)
		}
		close(release)
		synctest.Wait()
		if got := delivered.Load(); got != 64 {
			t.Errorf("%d notices delivered, want 64", got)
		}
		// The outstation repeats the first one that was not taken.
		o.send(unsolicitedNo(64, 0))
		synctest.Wait()
		if got := o.confirms.Load(); got != 65 {
			t.Errorf("repeat of an unsolicited response not taken: %d confirmed", got)
		}
		if got := delivered.Load(); got != 65 {
			t.Errorf("repeat not delivered: %d notices delivered", got)
		}
	})
}

// TestPollsWaitForHandler: the client's automatic polls wait while the
// handler's queue is full, and run once it has room; the application's
// own requests do not wait.
func TestPollsWaitForHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		c, o := pipeClient(t, nil, WithAutoEventPoll(true), WithHandler(HandlerFunc(func(ResponseInfo, []Measurement) { <-release })))
		for i := range 64 {
			o.send(unsolicitedNo(i, 0))
			synctest.Wait()
		}
		before := o.requests.Load()
		c.onIIN(app.IINClass1Events) // as a response reporting class 1 events would
		synctest.Wait()
		if got := o.requests.Load(); got != before {
			t.Errorf("%d requests sent by the event poll while the handler's queue was full", got-before)
		}
		// A request of the application is sent and answered.
		if _, err := c.Read(context.Background(), app.AllObjects(app.G1V0)); err != nil {
			t.Fatalf("READ of the application: %v", err)
		}
		close(release)
		synctest.Wait()
		if got := o.requests.Load(); got != before+2 {
			t.Errorf("after the handler caught up: %d requests, want the application's READ and the event poll", got-before)
		}
	})
}

// TestHandlerPanicRecovered: a panic in the measurement handler or in the
// state handler is recovered and logged; the next notification is
// delivered and the client goes on.
func TestHandlerPanicRecovered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		var calls, states atomic.Int64
		c, o := pipeClient(t, nil,
			WithLogger(dnp3.NewSlogLogger(slog.NewTextHandler(&logs, nil))),
			WithHandler(HandlerFunc(func(ResponseInfo, []Measurement) {
				if calls.Add(1) == 1 {
					panic("handler of the application")
				}
			})),
			WithStateHandler(func(dnp3.State, error) {
				if states.Add(1) == 1 {
					panic("state handler of the application")
				}
			}))
		o.send(unsolicitedNo(0, 0))
		o.send(unsolicitedNo(1, 0))
		synctest.Wait()
		if got := calls.Load(); got != 2 {
			t.Errorf("handler called %d times, want 2 (the second after the first one's panic)", got)
		}
		if _, err := c.Read(context.Background(), app.AllObjects(app.G1V0)); err != nil {
			t.Fatalf("READ after the panics: %v", err)
		}
		if !bytes.Contains([]byte(logs.String()), []byte("panic while delivering")) {
			t.Errorf("panic not logged:\n%s", logs.String())
		}
	})
}

// TestListDirectoryBounded: a directory listing that goes on beyond 16 MiB
// is refused with ErrProtocol and the transfer aborted; the client does not
// read more blocks than that.
func TestListDirectoryBounded(t *testing.T) {
	const block = 65000
	var reads, aborts atomic.Int64
	limit := int64(maxDirectory/block + 1)
	s := newScripted(t, func(r *app.Fragment) (app.IIN, []app.Header) {
		switch r.Function {
		case app.FuncOpenFile:
			return 0, []app.Header{app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 7, Size: 100, MaxBlockSize: block, RequestID: 1})}
		case app.FuncRead:
			ft := r.Headers[0].Objects[0].Value.(app.FileTransport)
			// Past the bound the outstation ends the file, so that a client
			// without it ends too.
			n := reads.Add(1)
			return 0, []app.Header{app.FreeFormat(app.G70V5, app.FileTransport{Handle: 7, Block: ft.Block, Last: n > limit+1, Data: make([]byte, block)})}
		default:
			if r.Function == app.FuncAbortFile {
				aborts.Add(1)
			}
		}
		return 0, []app.Header{app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 7, RequestID: 1})}
	})
	c, err := New(s.addr, WithStartup(Startup{}), WithAutoIntegrity(false), WithMaxFragment(block+64))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	ds, err := c.ListDirectory(ctx, "/", FileOptions{})
	if !errors.Is(err, dnp3.ErrProtocol) || ds != nil {
		t.Errorf("endless listing: %d entries, %v; want ErrProtocol", len(ds), err)
	}
	if got := reads.Load(); got > limit {
		t.Errorf("%d blocks of %d octets read, at most %d hold 16 MiB", got, block, limit)
	}
	if aborts.Load() != 1 {
		t.Errorf("transfer aborted %d times, want once", aborts.Load())
	}
}

// TestListingBuffer: the listing takes up to its limit and refuses what
// goes beyond it, the boundary included.
func TestListingBuffer(t *testing.T) {
	for _, tc := range []struct {
		max, have, write int
		ok               bool
	}{
		{10, 0, 0, true}, {10, 0, 1, true}, {10, 0, 9, true}, {10, 0, 10, true}, {10, 0, 11, false},
		{10, 9, 1, true}, {10, 10, 1, false}, {10, 10, 0, true}, {0, 0, 1, false},
	} {
		l := listing{max: tc.max}
		_, _ = l.Buffer.Write(make([]byte, tc.have))
		n, err := l.Write(make([]byte, tc.write))
		if (err == nil) != tc.ok || (tc.ok && n != tc.write) {
			t.Errorf("max %d, holding %d, write %d: %d, %v", tc.max, tc.have, tc.write, n, err)
		}
	}
}

// TestAcceptAttemptsShareOneAccept (L14): attempts of a client.Accept
// opener that time out leave one Accept in progress, not one each; the
// next attempt takes the connection it returns, and closing the listener
// ends it.
func TestAcceptAttemptsShareOneAccept(t *testing.T) {
	leaktest.Check(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	open := Accept(l)
	base := runtime.NumGoroutine()
	for range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		_, _, err := open(ctx)
		cancel()
		if err == nil {
			t.Fatal("attempt without a connection succeeded")
		}
	}
	// The timers of the attempts' contexts may still be ending: wait,
	// within a bound, for the count to come down to the one Accept.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > base+1 {
		t.Errorf("5 attempts that timed out: %d goroutines more, want at most the one Accept", got-base)
	}
	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := open(ctx)
	if err != nil {
		t.Fatalf("attempt after the timeouts: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := peer.Write([]byte{0x05, 0x64}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Errorf("the outstation's first connection did not reach the attempt: %v", err)
	}
}

// TestClientCopiesKeys: WithSecureAuthentication keeps its own copy of the
// keys: the caller may clear its slices.
func TestClientCopiesKeys(t *testing.T) {
	updateKey := []byte("0123456789abcdef")
	sessionKey := []byte("fedcba9876543210")
	c, err := New("127.0.0.1", WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey, Key: sessionKey}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	clear(updateKey)
	clear(sessionKey)
	if got := c.opts.auth.UpdateKey; !bytes.Equal(got, []byte("0123456789abcdef")) {
		t.Errorf("update key after the caller cleared its slice: % x", got)
	}
	if got := c.opts.auth.Key; !bytes.Equal(got, []byte("fedcba9876543210")) {
		t.Errorf("session key after the caller cleared its slice: % x", got)
	}
}

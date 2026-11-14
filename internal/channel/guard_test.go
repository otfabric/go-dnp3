// SPDX-License-Identifier: MIT

package channel

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/logx"
)

// failingStream is a net.Pipe end whose Read, Write or Close does not
// return normally, as fail names; the others work.
type failingStream struct {
	net.Conn
	fail string
}

func (s *failingStream) Read(b []byte) (int, error) {
	if s.fail == "Read" {
		panic("stream Read of the application")
	}
	return s.Conn.Read(b)
}

func (s *failingStream) Write(b []byte) (int, error) {
	if s.fail == "Write" {
		panic("stream Write of the application")
	}
	return s.Conn.Write(b)
}

func (s *failingStream) Close() error {
	err := s.Conn.Close()
	if s.fail == "Close" {
		panic("stream Close of the application")
	}
	return err
}

// syncBuffer is a bytes.Buffer safe for the channel's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestStreamThatDoesNotReturnNormally: the stream may be the
// application's. A Read or Write of it that does not return normally ends
// the channel with dnp3.ErrConnectionLost, as a failed one does, and a
// Close that does not return normally still stops it; each is logged with
// its stack, and a later write does not wait on the write lock.
func TestStreamThatDoesNotReturnNormally(t *testing.T) {
	for _, fail := range []string{"Read", "Write", "Close"} {
		t.Run(fail, func(t *testing.T) {
			var buf syncBuffer
			log := logx.New(dnp3.NewSlogLogger(slog.NewTextHandler(&buf, nil)), "test")
			near, far := net.Pipe()
			t.Cleanup(func() { _ = far.Close() })
			go func() { // the peer: takes what is written, sends nothing
				b := make([]byte, 512)
				for {
					if _, err := far.Read(b); err != nil {
						return
					}
				}
			}()
			ch := New(&failingStream{Conn: near, fail: fail}, Config{Log: log})
			s := ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true})
			ch.Start()
			switch fail {
			case "Read":
				<-ch.Done()
			case "Write":
				err := s.Send(context.Background(), []byte{0xC0, 0x01})
				if !errors.Is(err, dnp3.ErrConnectionLost) {
					t.Fatalf("Send: %v, want ErrConnectionLost", err)
				}
				<-ch.Done()
				if err := s.Send(context.Background(), []byte{0xC0, 0x01}); err == nil {
					t.Fatal("Send on the ended channel succeeded")
				}
			case "Close":
				ch.Close(nil)
				<-ch.Done()
			}
			if fail != "Close" && !errors.Is(ch.Err(), dnp3.ErrConnectionLost) {
				t.Errorf("channel ended with %v, want ErrConnectionLost", ch.Err())
			}
			out := buf.String()
			for _, want := range []string{`msg="callback did not return normally"`, "callback=Stream." + fail,
				`value="stream ` + fail + ` of the application"`, "stack="} {
				if !strings.Contains(out, want) {
					t.Errorf("log misses %q:\n%s", want, out)
				}
			}
		})
	}
}

// probeHandler is a slog.Handler that hands each record to probe.
type probeHandler struct{ probe func(slog.Record) }

func (h probeHandler) Enabled(context.Context, slog.Level) bool      { return true }
func (h probeHandler) Handle(_ context.Context, r slog.Record) error { h.probe(r); return nil }
func (h probeHandler) WithAttrs([]slog.Attr) slog.Handler            { return h }
func (h probeHandler) WithGroup(string) slog.Handler                 { return h }

// TestStreamWriteLoggedAfterUnlock: a write that does not return normally
// is logged after the channel released its write lock, so that a logger
// that writes on the channel returns. The logger here takes the lock when
// it is called, on another goroutine and within a bounded wait.
func TestStreamWriteLoggedAfterUnlock(t *testing.T) {
	var ch atomic.Pointer[Channel]
	underLock := make(chan bool, 1)
	log := logx.New(dnp3.NewSlogLogger(probeHandler{func(r slog.Record) {
		if r.Message != "callback did not return normally" {
			return
		}
		// wmu is taken on another goroutine, within 5 s: a lock the
		// logger's caller holds while it waits is not.
		c, got := ch.Load(), make(chan struct{})
		go func() {
			c.wmu.Lock()
			close(got) // taken
			c.wmu.Unlock()
		}()
		select {
		case <-got:
			underLock <- false
		case <-time.After(5 * time.Second):
			underLock <- true
		}
	}}), "test")
	near, far := net.Pipe()
	t.Cleanup(func() { _ = far.Close() })
	go func() { // the peer: takes what is written, sends nothing
		b := make([]byte, 512)
		for {
			if _, err := far.Read(b); err != nil {
				return
			}
		}
	}()
	c := New(&failingStream{Conn: near, fail: "Write"}, Config{Log: log})
	ch.Store(c)
	s := c.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true})
	c.Start()
	if err := s.Send(context.Background(), []byte{0xC0, 0x01}); !errors.Is(err, dnp3.ErrConnectionLost) {
		t.Fatalf("Send: %v, want ErrConnectionLost", err)
	}
	select {
	case held := <-underLock:
		if held {
			t.Fatal("the write that did not return normally was logged under the write lock")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the write that did not return normally was not logged")
	}
	<-c.Done()
}

// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// The rows of the lifecycle contract matrix (TESTING.md, L1 to L16) for the
// master that other tests do not cover. They run in a synctest bubble,
// over net.Pipe: every wait is for the bubble to settle, never a sleep.

func binaryInput(*app.Fragment) []app.Header {
	return []app.Header{app.Ranged(app.G1V2, 0, app.Binary{Value: true, Flags: app.FlagOnline})}
}

// TestCloseWithRequestInFlight (L3): Close while a request waits for its
// response: the request fails with ErrClosed, and Close returns.
func TestCloseWithRequestInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := make(chan struct{})
		defer close(hold)
		c, _ := pipeClient(t, func(*app.Fragment) []app.Header { <-hold; return nil })
		done := make(chan error, 1)
		go func() {
			_, err := c.Read(context.Background(), app.AllObjects(app.G1V0))
			done <- err
		}()
		synctest.Wait()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, dnp3.ErrClosed) {
			t.Errorf("request in flight at Close: %v, want ErrClosed", err)
		}
	})
}

// TestCloseDuringWrite (L4): Close while a request is being written to an
// outstation that does not read: the write ends with the stream, the
// request fails, and Close returns.
func TestCloseDuringWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		near, far := net.Pipe()
		defer func() { _ = far.Close() }()
		var once sync.Once
		open := func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
			var s io.ReadWriteCloser
			once.Do(func() { s = near })
			if s == nil {
				return nil, nil, errors.New("one stream only")
			}
			return s, near.RemoteAddr(), nil
		}
		c, err := New("outstation", WithStream(open), WithStartup(Startup{}), WithAutoIntegrity(false))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Connect(context.Background()); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := c.Read(context.Background(), app.AllObjects(app.G1V0))
			done <- err
		}()
		synctest.Wait() // the request is blocked in the write
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Error("request written at Close succeeded")
		}
	})
}

// TestRequestAfterReconnect (L8): a request whose connection is lost fails
// with ErrConnectionLost; after the reconnect a request is answered on the
// new connection only.
func TestRequestAfterReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var outstations []*pipeOutstation
		first := make(chan struct{})
		open := func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
			near, far := net.Pipe()
			mu.Lock()
			defer mu.Unlock()
			n := len(outstations)
			answer := binaryInput
			if n == 0 {
				// The first connection ends with the request unanswered.
				answer = func(*app.Fragment) []app.Header {
					close(first)
					_ = far.Close()
					return nil
				}
			}
			outstations = append(outstations, newPipeOutstation(far, answer))
			return near, near.RemoteAddr(), nil
		}
		c, err := New("outstation", WithStream(open), WithStartup(Startup{}), WithAutoIntegrity(false),
			WithReconnect(Reconnect{MinDelay: time.Second, MaxDelay: time.Second}))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = c.Close()
			mu.Lock()
			defer mu.Unlock()
			for _, o := range outstations {
				o.close()
			}
		}()
		if err := c.Connect(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(context.Background(), app.AllObjects(app.G1V0)); !errors.Is(err, dnp3.ErrConnectionLost) {
			t.Fatalf("request of the lost connection: %v, want ErrConnectionLost", err)
		}
		<-first
		time.Sleep(2 * time.Second) // the bubble's clock: the reconnect delay
		synctest.Wait()
		res, err := c.Read(context.Background(), app.AllObjects(app.G1V0))
		if err != nil || len(res.Measurements()) != 1 {
			t.Fatalf("request after the reconnect: %v, %v", res, err)
		}
		mu.Lock()
		n := len(outstations)
		mu.Unlock()
		if n != 2 {
			t.Errorf("%d connections, want 2", n)
		}
	})
}

// TestHandlerIssuesRequest (L9): the handler may make requests of the
// client: one made from the handler of an unsolicited response is
// answered.
func TestHandlerIssuesRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c *Client
		got := make(chan error, 1)
		var once sync.Once
		c, o := pipeClient(t, binaryInput, WithHandler(HandlerFunc(func(info ResponseInfo, _ []Measurement) {
			if !info.Unsolicited {
				return
			}
			once.Do(func() {
				res, err := c.Read(context.Background(), app.AllObjects(app.G1V0))
				if err == nil && len(res.Measurements()) != 1 {
					err = errors.New("no measurement")
				}
				got <- err
			})
		})))
		o.send(unsolicitedNo(0, 0))
		synctest.Wait()
		select {
		case err := <-got:
			if err != nil {
				t.Errorf("request from the handler: %v", err)
			}
		default:
			t.Error("the handler's request did not complete")
		}
	})
}

// TestHandlerStartsClose (L10): a handler, or the state handler, that
// wants the client closed starts Close on another goroutine (Close waits
// for the handler): Close completes once the handler has returned.
func TestHandlerStartsClose(t *testing.T) {
	for _, state := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			var client atomic.Pointer[Client]
			var returned atomic.Bool
			closed := make(chan bool, 1)
			var once sync.Once
			start := func() {
				once.Do(func() {
					go func() {
						_ = client.Load().Close()
						closed <- returned.Load()
					}()
					returned.Store(true)
				})
			}
			opts := []Option{WithHandler(HandlerFunc(func(ResponseInfo, []Measurement) {
				if !state {
					start()
				}
			}))}
			if state {
				// The state handler closes the client when the outstation
				// ends the connection.
				opts = append(opts, WithStateHandler(func(s dnp3.State, err error) {
					if s == dnp3.StateDisconnected && err != nil {
						start()
					}
				}))
			}
			c, o := pipeClient(t, nil, opts...)
			client.Store(c)
			if state {
				o.close()
			} else {
				o.send(unsolicitedNo(0, 0))
			}
			synctest.Wait()
			select {
			case after := <-closed:
				if !after {
					t.Error("Close completed before the handler returned")
				}
			default:
				t.Errorf("Close started by the handler (state handler %t) did not complete", state)
			}
		})
	}
}

// TestSlowHandlerDoesNotDelayRequests (L11): a handler that does not
// return does not hold up the requests: a READ is answered while it runs,
// and Close waits for it.
func TestSlowHandlerDoesNotDelayRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		c, o := pipeClient(t, binaryInput, WithHandler(HandlerFunc(func(ResponseInfo, []Measurement) { <-release })))
		o.send(unsolicitedNo(0, 0))
		synctest.Wait() // the handler holds the first notice
		res, err := c.Read(context.Background(), app.AllObjects(app.G1V0))
		if err != nil || len(res.Measurements()) != 1 {
			t.Fatalf("READ while the handler runs: %v, %v", res, err)
		}
		closed := make(chan struct{})
		go func() {
			_ = c.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close returned while the handler runs")
		default:
		}
		close(release)
		<-closed
	})
}

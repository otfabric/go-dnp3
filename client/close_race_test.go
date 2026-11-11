package client

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// clientGoroutines returns the stacks of goroutines that Close waits for:
// a channel's watch, the reconnect loop and the dual end point's accept.
func clientGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		for _, fn := range []string{"client.(*Client).watch(", "client.(*Client).reconnectLoop(", "client.(*dualEndpoint).accept("} {
			if strings.Contains(g, fn) {
				out = append(out, g)
			}
		}
	}
	return out
}

// TestCloseDuringConnectLeavesNoGoroutine: Close, run at any point of a
// Connect, waits for every goroutine the client started, and none starts
// after it: each is added to the client's WaitGroup under the lock where
// Close marks the client closed, as sync.WaitGroup requires of an Add
// from zero. Run with the race detector, an Add after Close's Wait is
// also reported. Closes land before, during and after the dial and the
// startup sequence, with and without a dual end point.
func TestCloseDuringConnectLeavesNoGoroutine(t *testing.T) {
	_, addr := outstation(t)
	for i := range 60 {
		opts := quiet(WithReconnect(Reconnect{MinDelay: time.Millisecond, MaxDelay: time.Millisecond}))
		if i%2 == 1 {
			opts = append(opts, WithDualEndpoint(listenTCP(t), nil))
		}
		c, err := New(addr, opts...)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.Connect(context.Background())
		}()
		time.Sleep(time.Duration(i%15) * 200 * time.Microsecond)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if left := clientGoroutines(); len(left) > 0 {
			t.Fatalf("close %d: a goroutine runs after Close returned:\n%s", i, strings.Join(left, "\n\n"))
		}
		<-done
		if left := clientGoroutines(); len(left) > 0 {
			t.Fatalf("close %d: a goroutine runs after Close and Connect returned:\n%s", i, strings.Join(left, "\n\n"))
		}
	}
}

// TestDualEndpointNoAcceptAfterClose: the dual end point of a closed
// client starts no accept loop, also when a Connect that began before
// Close reaches it only after: Close would not wait for that loop.
func TestDualEndpointNoAcceptAfterClose(t *testing.T) {
	c, err := New(deadAddr(t), quiet(WithDualEndpoint(listenTCP(t), nil))...)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// What a Connect checked before Close does next.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if s, _, err := c.dual.open(ctx); err == nil {
		_ = s.Close()
		t.Fatal("a closed client opened a connection")
	}
	if left := clientGoroutines(); len(left) > 0 {
		t.Fatalf("accept runs on a closed client:\n%s", strings.Join(left, "\n\n"))
	}
}

// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// sized encodes a response fragment of exactly size octets (10 to 264): one
// octet string of index 0 (g110, qualifier 0x00).
func sized(c app.Control, size int) []byte {
	n := size - 9 // 4 octets of fragment header, 5 of object header
	obj := append([]byte{110, byte(n), 0x00, 0, 0}, make([]byte, n)...)
	return frag(c, app.FuncResponse, 0, obj)
}

// multiFragment answers a request with fragments of the given sizes, each
// asking for confirmation.
func multiFragment(sizes ...int) func(specFrag) [][]byte {
	return func(req specFrag) [][]byte {
		var out [][]byte
		for i, s := range sizes {
			out = append(out, sized(ctl(i == 0, i == len(sizes)-1, true, req.f.Control.Seq+uint8(i)), s))
		}
		return out
	}
}

func TestMaxResponseOption(t *testing.T) {
	for _, tc := range []struct {
		n  int
		ok bool
	}{{math.MinInt, false}, {-1, false}, {0, false}, {248, false}, {249, true}, {DefaultMaxResponse, true}, {math.MaxInt, true}} {
		c, err := New("127.0.0.1:1", WithMaxResponse(tc.n))
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, dnp3.ErrInvalidOption)) {
			t.Errorf("WithMaxResponse(%d): %v", tc.n, err)
		}
		if err == nil {
			if c.opts.maxResponse != tc.n {
				t.Errorf("WithMaxResponse(%d): limit %d", tc.n, c.opts.maxResponse)
			}
			_ = c.Close()
		}
	}
	c, err := New("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.opts.maxResponse != 16<<20 {
		t.Errorf("default limit %d, want 16 MiB", c.opts.maxResponse)
	}
}

// TestMaxResponseBoundary: a response whose fragments add up to the limit
// or less is taken whole; with one octet more it is abandoned with
// dnp3.ErrProtocol at the fragment that crosses the limit, which is not
// confirmed, as an unexpected fragment is (Table 6-2). The fragments before
// it are confirmed and held in the Result. A first fragment beyond the
// limit is refused alike.
func TestMaxResponseBoundary(t *testing.T) {
	for _, tc := range []struct {
		limit int
		sizes []int
		taken int // fragments in the Result; len(sizes): the response is taken
	}{
		{1000, []int{250, 250, 250, 249}, 4},     // limit-1
		{1000, []int{250, 250, 250, 250}, 4},     // limit
		{1000, []int{250, 250, 250, 251}, 3},     // limit+1, at the last fragment
		{1000, []int{250, 250, 250, 250, 10}, 4}, // limit+10, at the last fragment
		{1000, []int{264, 264, 264, 264, 10}, 3}, // beyond at a middle fragment
		{249, []int{249}, 1},                     // the smallest limit
		{249, []int{250, 10}, 0},                 // beyond at the first fragment
		{math.MaxInt, []int{264, 264}, 2},        // no limit
	} {
		total := 0
		for _, s := range tc.sizes {
			total += s
		}
		limit := tc.limit
		t.Run(fmt.Sprintf("%d octets in %d, limit %d", total, len(tc.sizes), limit), func(t *testing.T) {
			o := newSpecOutstation(t, multiFragment(tc.sizes...))
			c := specDial(t, o, append(specQuiet, WithMaxResponse(limit))...)
			res, err := c.Read(testCtx(t), app.ClassHeaders(0)...)
			whole := tc.taken == len(tc.sizes)
			if whole != (total <= limit) {
				t.Fatalf("case: %d octets, taken %d of %d", total, tc.taken, len(tc.sizes))
			}
			switch {
			case whole && err != nil:
				t.Fatalf("response of %d octets, limit %d: %v", total, limit, err)
			case !whole && !errors.Is(err, dnp3.ErrProtocol):
				t.Fatalf("response of %d octets, limit %d: %v, want ErrProtocol", total, limit, err)
			}
			held := 0
			for _, r := range res.raw {
				held += len(r)
			}
			if len(res.Fragments) != tc.taken || held > limit {
				t.Fatalf("Result holds %d fragments, %d octets; want %d, at most %d", len(res.Fragments), held, tc.taken, limit)
			}
			// The next request comes after the confirmations of this one:
			// those of the fragments taken.
			if _, err := c.Read(testCtx(t), app.ClassHeaders(0)...); !whole && !errors.Is(err, dnp3.ErrProtocol) {
				t.Fatal(err)
			}
			sent := o.waitLog(t, "the second request", func(sent []specFrag) bool {
				n := 0
				for _, f := range sent {
					if f.f.Function == app.FuncRead {
						n++
					}
				}
				return n == 2
			})
			confirms := 0
			for _, f := range sent {
				if f.f.Function == app.FuncRead && confirms > 0 {
					break
				}
				if f.f.Function == app.FuncConfirm {
					confirms++
				}
			}
			if confirms != tc.taken {
				t.Errorf("%d fragments confirmed, want %d", confirms, tc.taken)
			}
		})
	}
}

// pacedOutstation answers each READ with a response of n fragments of
// size octets, each asking for confirmation and sent once the master
// confirmed the one before, as an outstation that asks for confirmations
// waits for each. sent counts the fragments it sent.
func pacedOutstation(t *testing.T, n, size int) (addr string, sent *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	sent = new(atomic.Int64)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		in := make(chan *app.Fragment, 64)
		sess := ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1, OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil {
				in <- f
			}
		}})
		ch.Start()
		defer func() { ch.Close(nil); <-ch.Done() }()
		var seq uint8
		i := n // the fragment due: none while no response is in progress
		for {
			select {
			case f := <-in:
				switch {
				case f.Function == app.FuncRead:
					seq, i = f.Control.Seq, 0
				case f.Function == app.FuncConfirm && i < n && f.Control.Seq == (seq+uint8(i))&0x0F:
					if i++; i == n {
						continue
					}
				default:
					continue
				}
				_ = sess.Send(context.Background(), sized(ctl(i == 0, i == n-1, true, seq+uint8(i)), size))
				sent.Add(1)
			case <-ch.Done():
				return
			}
		}
	}()
	return l.Addr().String(), sent
}

// TestMaxResponseBudget: what the client holds of a response is bounded by
// the limit however long the response: of a response of 200 fragments of
// 250 octets (50 000 octets) from an outstation that waits for each
// confirmation, it takes those within 4096 octets, does not confirm the
// next, and the heap it keeps for the Result stays within a few times the
// limit.
func TestMaxResponseBudget(t *testing.T) {
	const limit, n, size = 4096, 200, 250
	addr, sent := pacedOutstation(t, n, size)
	c, err := Dial(testCtx(t), addr, append(specQuiet, WithResponseTimeout(500*time.Millisecond), WithMaxResponse(limit))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	taken := limit / size
	read := func() *Result {
		t.Helper()
		res, err := c.Read(testCtx(t), app.ClassHeaders(0)...)
		if !errors.Is(err, dnp3.ErrProtocol) {
			t.Fatalf("response of %d octets: %d fragments, %v; want ErrProtocol", n*size, len(res.Fragments), err)
		}
		return res
	}
	read() // warm-up: the buffers of the channel
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := read()
	runtime.GC()
	runtime.ReadMemStats(&after)
	held := 0
	for _, r := range res.raw {
		held += len(r)
	}
	if len(res.Fragments) != taken || held > limit {
		t.Fatalf("Result holds %d fragments of %d octets; want %d within %d", len(res.Fragments), held, taken, limit)
	}
	if got := sent.Load(); got > int64(2*(taken+1)) {
		t.Fatalf("the outstation sent %d fragments for two responses: the client confirmed beyond the limit", got)
	}
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("response of %d octets, limit %d: the heap grew by %d octets", n*size, limit, grew)
	if budget := int64(4*limit + 16<<10); grew > budget {
		t.Errorf("the heap grew by %d octets for a Result within %d octets, budget %d", grew, limit, budget)
	}
	runtime.KeepAlive(res)
}

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

// packed encodes a response fragment of exactly size octets (12 or more)
// of packed binary inputs, g1v1 (8 points an octet) or g3v1 (4), qualifier
// 0x01.
func packed(gv app.GroupVariation, size int) func(app.Control) []byte {
	perOctet := 8
	if gv == app.G3V1 {
		perOctet = 4
	}
	n := size - 11 // 4 octets of fragment header, 7 of object header
	stop := uint16(n*perOctet - 1)
	obj := append([]byte{byte(gv >> 8), byte(gv), 0x01, 0, 0, byte(stop), byte(stop >> 8)}, make([]byte, n)...)
	for i := 7; i < len(obj); i++ {
		obj[i] = byte(i)
	}
	return func(c app.Control) []byte { return frag(c, app.FuncResponse, 0, obj) }
}

// pacedOutstation answers each READ with a response of n fragments of
// size octets, each asking for confirmation and sent once the master
// confirmed the one before, as an outstation that asks for confirmations
// waits for each. sent counts the fragments it sent.
func pacedOutstation(t *testing.T, n, size int) (addr string, sent *atomic.Int64) {
	return pacedOutstationOf(t, n, func(c app.Control) []byte { return sized(c, size) })
}

// pacedOutstationOf is pacedOutstation with the fragments encode returns.
func pacedOutstationOf(t *testing.T, n int, encode func(app.Control) []byte) (addr string, sent *atomic.Int64) {
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
				_ = sess.Send(context.Background(), encode(ctl(i == 0, i == n-1, true, seq+uint8(i))))
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

// TestMaxResponseBudgetPacked: WithMaxResponse bounds what the client
// keeps of a response however densely its objects are packed. Of a
// response of 200 fragments of 2048 octets (the largest fragment by
// default) of packed binary inputs, g1v1 (16 296 points each) or g3v1
// (8 148), each fragment counts objectCost per point: the client takes
// those within 2 MiB, does not confirm the next, and the heap it keeps for
// the Result stays within a few times the limit, as for octet strings
// (TestMaxResponseBudget).
func TestMaxResponseBudgetPacked(t *testing.T) {
	const limit, n, size = 2 << 20, 200, 2048
	for _, tc := range []struct {
		gv     app.GroupVariation
		points int
	}{{app.G1V1, 8 * (size - 11)}, {app.G3V1, 4 * (size - 11)}} {
		t.Run(tc.gv.String(), func(t *testing.T) {
			addr, sent := pacedOutstationOf(t, n, packed(tc.gv, size))
			c, err := Dial(testCtx(t), addr, append(specQuiet, WithResponseTimeout(500*time.Millisecond), WithMaxResponse(limit))...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			taken := limit / (tc.points * objectCost)
			read := func() *Result {
				t.Helper()
				res, err := c.Read(testCtx(t), app.ClassHeaders(0)...)
				if !errors.Is(err, dnp3.ErrProtocol) {
					t.Fatalf("response of %d points: %d fragments, %v; want ErrProtocol", n*tc.points, len(res.Fragments), err)
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
			points := 0
			for _, f := range res.Fragments {
				for _, h := range f.Headers {
					points += len(h.Objects)
				}
			}
			if len(res.Fragments) != taken || points != taken*tc.points {
				t.Fatalf("Result holds %d fragments of %d points; want %d of %d", len(res.Fragments), points, taken, tc.points)
			}
			if got := sent.Load(); got > int64(2*(taken+1)) {
				t.Fatalf("the outstation sent %d fragments for two responses: the client confirmed beyond the limit", got)
			}
			grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			t.Logf("%s response of %d points, limit %d: the heap grew by %d octets", tc.gv, n*tc.points, limit, grew)
			if budget := int64(4*limit + 16<<10); grew > budget {
				t.Errorf("the heap grew by %d octets for a Result within %d octets, budget %d", grew, limit, budget)
			}
			runtime.KeepAlive(res)
		})
	}
}

// TestFragmentCost: a fragment counts its octets, or objectCost for each
// object when that is more.
func TestFragmentCost(t *testing.T) {
	g110 := sized(app.SingleControl(0), 250)
	f, err := app.Decode(g110)
	if err != nil {
		t.Fatal(err)
	}
	if got := fragmentCost(f, g110); got != 250 {
		t.Errorf("one octet string of 250 octets: cost %d", got)
	}
	bits := packed(app.G1V1, 100)(app.SingleControl(0))
	if f, err = app.Decode(bits); err != nil {
		t.Fatal(err)
	}
	if got, want := fragmentCost(f, bits), 8*89*objectCost; got != want {
		t.Errorf("712 packed binary inputs: cost %d, want %d", got, want)
	}
	if got := fragmentCost(&app.Fragment{}, nil); got != 0 {
		t.Errorf("empty fragment: cost %d", got)
	}
}

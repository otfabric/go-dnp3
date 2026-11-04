// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// TestFreezeAtTimeInterval: an interval that does not fit the 32 bits of
// milliseconds of g50v2 is refused before anything is sent, rather than
// sent modulo 2^32; the largest that fits reaches the outstation intact.
func TestFreezeAtTimeInterval(t *testing.T) {
	var (
		mu  sync.Mutex
		got []uint32
	)
	c := dialScripted(t, func(req *app.Fragment) (app.IIN, []app.Header) {
		for _, h := range req.Headers {
			for _, o := range h.Objects {
				if at, ok := o.Value.(app.AbsoluteTime); ok {
					mu.Lock()
					got = append(got, at.Interval)
					mu.Unlock()
				}
			}
		}
		return 0, nil
	})
	ctx := testCtx(t)
	for _, d := range []time.Duration{-time.Millisecond, (1 << 32) * time.Millisecond, 50 * 24 * time.Hour} {
		if err := c.FreezeAtTime(ctx, time.Now(), d, app.AllObjects(app.G20V0)); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Fatalf("interval %v: %v, want ErrInvalidOption", d, err)
		}
	}
	if err := c.FreezeAtTime(ctx, time.Now(), (1<<32-1)*time.Millisecond, app.AllObjects(app.G20V0)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != 1<<32-1 {
		t.Fatalf("outstation saw intervals %v, want only 4294967295", got)
	}
}

// TestWriteFileBlockFitsObject: an outstation that announces a block size
// of 65535 gets blocks of at most 65527 octets, the most a g70v5 object
// holds beside its handle and block number, rather than a WRITE that
// cannot be encoded.
func TestWriteFileBlockFitsObject(t *testing.T) {
	var (
		mu     sync.Mutex
		blocks []int
	)
	s := newScriptedMax(t, 100_000, func(r *app.Fragment) (app.IIN, []app.Header) {
		switch r.Function {
		case app.FuncOpenFile:
			return 0, opened(0xFFFF)
		case app.FuncWrite:
			mu.Lock()
			blocks = append(blocks, len(r.Headers[0].Objects[0].Value.(app.FileTransport).Data))
			mu.Unlock()
			return 0, []app.Header{ff(app.FileTransportStatus{Handle: 1})}
		default:
			return 0, []app.Header{ff(app.FileCommandStatus{Handle: 1})}
		}
	})
	c, err := Dial(testCtx(t), s.addr, WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	const size = 70_000
	if n, err := c.WriteFile(testCtx(t), "/f", bytes.NewReader(make([]byte, size)), size, FileOptions{}); err != nil || n != size {
		t.Fatalf("write: %d %v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(blocks) != 2 || blocks[0] != 0xFFFF-8 || blocks[1] != size-(0xFFFF-8) {
		t.Fatalf("blocks %v", blocks)
	}
}

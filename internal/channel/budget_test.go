// SPDX-License-Identifier: MIT

package channel

import (
	"runtime"
	"testing"

	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// TestReceiveAllocationPerOctet: a long stream of valid fragments through
// the link reader, the reassembler and the session costs a bounded number
// of octets per octet received, and what the channel holds does not grow
// with the number of fragments.
func TestReceiveAllocationPerOctet(t *testing.T) {
	_, peer, in := outstationWithRaw(t, SessionConfig{})
	const n = 200
	frag := payload(transport.DefaultMaxFragment)
	var seg transport.Segmenter
	wire := make([][]byte, n)
	total := 0
	for i := range wire {
		for _, s := range seg.Segment(frag) {
			f := link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: masterAddr, Data: s}
			var err error
			if wire[i], err = f.AppendEncode(wire[i]); err != nil {
				t.Fatal(err)
			}
		}
		total += len(wire[i])
	}
	send := func(b []byte) {
		if _, err := peer.conn.Write(b); err != nil {
			t.Fatal(err)
		}
		if d := in.next(t); len(d.frag) != len(frag) {
			t.Fatalf("fragment of %d octets delivered, sent %d", len(d.frag), len(frag))
		}
	}
	send(wire[0]) // warm up: the buffers of the reader and the reassembler
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for _, b := range wire[1:] {
		send(b)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	octets := float64(total - len(wire[0]))
	perOctet := float64(after.TotalAlloc-before.TotalAlloc) / octets
	t.Logf("%d fragments, %.0f octets: %.2f octets allocated per octet received", n-1, octets, perOctet)
	// Each octet is copied twice, into a frame's user data and into the
	// fragment handed to OnFragment, plus the test's own timer per
	// fragment: four leaves room for the size classes.
	if perOctet > 4 {
		t.Errorf("%.2f octets allocated per octet received, budget 4", perOctet)
	}
	// The fragments were handed over: the heap holds about what it held
	// before, not the 450 kB that went through.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 64<<10 {
		t.Errorf("heap grew by %d octets over %d fragments", grew, n-1)
	}
}

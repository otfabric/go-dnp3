// SPDX-License-Identifier: MIT

package transport

import (
	"runtime"
	"testing"
)

// allocated returns the octets f allocates on the heap per call, averaged
// over runs calls after one call to warm up.
func allocated(runs int, f func()) float64 {
	f()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(runs)
}

// heldLimit is the most a Reassembler of max octets may hold in its
// buffer: max, rounded up by the growth of append.
func heldLimit(max int) int { return 2 * max }

// TestReassemblerHoldsAtMostItsLimit: segments that would make a fragment
// longer than the limit are refused, and the buffer of the reassembler
// stays within its limit whatever follows.
func TestReassemblerHoldsAtMostItsLimit(t *testing.T) {
	for _, max := range []int{1, 249, DefaultMaxFragment, 65536} {
		r := NewReassembler(max)
		seg := make([]byte, MaxSegment)
		first, seq := true, uint8(0)
		for range 10 * (max/MaxSegmentData + 2) {
			seg[0] = byte(NewHeader(first, false, seq))
			out, _ := r.Add(seg)
			if out != nil {
				t.Fatalf("max %d: a fragment without FIN returned", max)
			}
			if len(r.buf) > max || cap(r.buf) > heldLimit(max) {
				t.Fatalf("max %d: the reassembler holds %d/%d octets", max, len(r.buf), cap(r.buf))
			}
			first, seq = false, (seq+1)&seqMask
			if !r.Pending() {
				// Refused for its size: the next segment starts a new
				// fragment.
				first, seq = true, 0
			}
		}
	}
}

// TestReassemblerAllocationPerFragment: once its buffer has grown, a
// fragment costs one allocation, the copy handed to the caller; a refused
// segment costs at most its error.
func TestReassemblerAllocationPerFragment(t *testing.T) {
	frag := fragment(DefaultMaxFragment)
	var s Segmenter
	segs := s.Segment(frag)
	r := NewReassembler(0)
	assemble := func() {
		for _, seg := range segs {
			_, _ = r.Add(seg)
		}
	}
	if n := testing.AllocsPerRun(100, assemble); n > 1 {
		t.Errorf("a fragment of %d octets: %.0f allocations, want 1", len(frag), n)
	}
	// The copy (2048 octets) and nothing that grows with the segments.
	if got := allocated(100, assemble); got > float64(len(frag))+64 {
		t.Errorf("a fragment of %d octets: %.0f octets allocated", len(frag), got)
	}
	small := NewReassembler(249)
	long := segs[0] // 249 octets of data with FIR: the limit, not above it
	over := append([]byte{byte(NewHeader(false, false, 1))}, segs[1][1:]...)
	refuse := func() {
		_, _ = small.Add(long)
		_, _ = small.Add(over)
	}
	if got := allocated(100, refuse); got > 256 {
		t.Errorf("a segment beyond the limit: %.0f octets allocated", got)
	}
}

// SPDX-License-Identifier: MIT

package transport

import (
	"bytes"
	"errors"
	"testing"
)

func fragment(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 13)
	}
	return b
}

func TestHeader(t *testing.T) {
	h := NewHeader(true, true, 65)
	if !h.FIR() || !h.FIN() || h.Seq() != 1 || byte(h) != 0xC1 || h.String() != "FIR FIN seq=1" {
		t.Fatalf("header %#x %s", byte(h), h)
	}
	if NewHeader(false, false, 63).String() != "seq=63" {
		t.Fatal("String")
	}
}

func TestSegmentAndReassemble(t *testing.T) {
	var s Segmenter
	r := NewReassembler(0)
	for _, n := range []int{0, 1, 248, 249, 250, 498, 499, 2048} {
		frag := fragment(n)
		segs := s.Segment(frag)
		want := max(1, (n+MaxSegmentData-1)/MaxSegmentData)
		if len(segs) != want {
			t.Fatalf("n=%d: %d segments, want %d", n, len(segs), want)
		}
		var got []byte
		for i, seg := range segs {
			if len(seg) > MaxSegment {
				t.Fatalf("segment of %d octets", len(seg))
			}
			h := Header(seg[0])
			if h.FIR() != (i == 0) || h.FIN() != (i == len(segs)-1) {
				t.Fatalf("n=%d seg %d: %s", n, i, h)
			}
			out, err := r.Add(seg)
			if err != nil {
				t.Fatal(err)
			}
			if i < len(segs)-1 && out != nil {
				t.Fatal("fragment before FIN")
			}
			got = out
		}
		if !bytes.Equal(got, frag) || got == nil {
			t.Fatalf("n=%d: reassembled %d octets", n, len(got))
		}
		if r.Pending() {
			t.Fatal("pending after FIN")
		}
	}
}

func TestSequenceWraps(t *testing.T) {
	var s Segmenter
	for range 70 {
		s.Segment([]byte{1})
	}
	if s.Seq() != 70%64 {
		t.Fatalf("seq = %d", s.Seq())
	}
	r := NewReassembler(0)
	for range 3 {
		for _, seg := range s.Segment(fragment(600)) {
			if _, err := r.Add(seg); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestReassemblyErrors(t *testing.T) {
	r := NewReassembler(300)
	if _, err := r.Add(nil); !errors.Is(err, ErrEmpty) {
		t.Fatal(err)
	}
	if _, err := r.Add([]byte{byte(NewHeader(false, true, 0)), 1}); !errors.Is(err, ErrNoFirst) {
		t.Fatal(err)
	}
	// Out of sequence middle segment discards the fragment.
	_, _ = r.Add([]byte{byte(NewHeader(true, false, 10)), 1})
	if _, err := r.Add([]byte{byte(NewHeader(false, true, 12)), 2}); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	if r.Pending() {
		t.Fatal("pending after sequence error")
	}
	// A repeated segment is out of sequence too.
	_, _ = r.Add([]byte{byte(NewHeader(true, false, 5)), 1})
	if _, err := r.Add([]byte{byte(NewHeader(false, false, 5)), 1}); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	// A new FIR replaces a partial fragment.
	_, _ = r.Add([]byte{byte(NewHeader(true, false, 1)), 9, 9})
	got, err := r.Add([]byte{byte(NewHeader(true, true, 40)), 7})
	if err != nil || !bytes.Equal(got, []byte{7}) {
		t.Fatalf("got %v %v", got, err)
	}
	// Size limit.
	big := append([]byte{byte(NewHeader(true, false, 0))}, fragment(249)...)
	_, _ = r.Add(big)
	big[0] = byte(NewHeader(false, true, 1))
	if _, err := r.Add(big); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func FuzzReassembler(f *testing.F) {
	f.Add([]byte{0xC0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReassembler(512)
		// Treat the input as a sequence of length-prefixed segments.
		for len(b) > 0 {
			n := min(int(b[0])%(MaxSegment+1), len(b)-1)
			out, _ := r.Add(b[1 : 1+n])
			if len(out) > 512 {
				t.Fatal("fragment above limit")
			}
			b = b[1+n:]
		}
	})
}

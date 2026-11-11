// SPDX-License-Identifier: MIT

package transport

import (
	"bytes"
	"errors"
	"testing"
)

// Spec tests: IEEE 1815-2012 clause 8, one case per rule or table row.

func seg(fir, fin bool, seq uint8, data ...byte) []byte {
	return append([]byte{byte(NewHeader(fir, fin, seq))}, data...)
}

// TestSpecTable8_1 drives the reception state table (clause 8.2.4, Table
// 8-1, p. 272) row by row: the state before the segment, the segment, the
// error (if it is discarded), the fragment passed up, and the state after.
func TestSpecTable8_1(t *testing.T) {
	type step struct {
		seg     []byte
		err     error
		frag    []byte
		pending bool
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"row 1: Idle, not a first segment, discarded", []step{
			{seg(false, false, 3, 1), ErrNoFirst, nil, false},
			{seg(false, true, 4, 1), ErrNoFirst, nil, false},
		}},
		{"row 2: Idle, FIR FIN passes the fragment", []step{
			{seg(true, true, 17, 1, 2), nil, []byte{1, 2}, false},
		}},
		{"row 3: Idle, first of several starts assembly", []step{
			{seg(true, false, 63, 1), nil, nil, true},
		}},
		{"row 4: Assembly, identical repeat discarded, series goes on", []step{
			{seg(true, false, 5, 0xA), nil, nil, true},
			{seg(false, false, 6, 0xB), nil, nil, true},
			{seg(false, false, 6, 0xB), ErrDuplicate, nil, true},
			{seg(false, true, 7, 0xC), nil, []byte{0xA, 0xB, 0xC}, false},
		}},
		{"row 4: Assembly, repeat of the first segment without FIR is not identical", []step{
			{seg(true, false, 5, 0xA), nil, nil, true},
			{seg(false, false, 5, 0xA), ErrSequence, nil, false},
		}},
		{"row 5: Assembly, same SEQ but other octets ends the series", []step{
			{seg(true, false, 5, 0xA), nil, nil, true},
			{seg(false, false, 6, 0xB), nil, nil, true},
			{seg(false, false, 6, 0xD), ErrSequence, nil, false},
			{seg(false, true, 7, 0xC), ErrNoFirst, nil, false},
		}},
		{"row 6: Assembly, next segment appended", []step{
			{seg(true, false, 62, 1), nil, nil, true},
			{seg(false, false, 63, 2), nil, nil, true},
			{seg(false, false, 0, 3), nil, nil, true}, // modulo 64
			{seg(false, true, 1, 4), nil, []byte{1, 2, 3, 4}, false},
		}},
		{"row 7: Assembly, final segment passes the fragment", []step{
			{seg(true, false, 9, 1), nil, nil, true},
			{seg(false, true, 10, 2), nil, []byte{1, 2}, false},
		}},
		{"row 8: Assembly, SEQ out of order ends the series", []step{
			{seg(true, false, 9, 1), nil, nil, true},
			{seg(false, true, 12, 2), ErrSequence, nil, false},
		}},
		{"row 8: Assembly, SEQ +63 (one behind, not identical) ends the series", []step{
			{seg(true, false, 9, 1), nil, nil, true},
			{seg(false, false, 10, 2), nil, nil, true},
			{seg(false, false, 9, 1), ErrSequence, nil, false},
		}},
		{"row 9: Assembly, new first segment restarts", []step{
			{seg(true, false, 9, 1), nil, nil, true},
			{seg(true, false, 30, 7), nil, nil, true},
			{seg(false, true, 31, 8), nil, []byte{7, 8}, false},
		}},
		{"row 10: Assembly, FIR FIN replaces the series", []step{
			{seg(true, false, 9, 1), nil, nil, true},
			{seg(true, true, 9, 1), nil, []byte{1}, false},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewReassembler(0)
			for i, st := range c.steps {
				got, err := r.Add(st.seg)
				if !errors.Is(err, st.err) || (st.err == nil && err != nil) {
					t.Fatalf("step %d: error %v, want %v", i, err, st.err)
				}
				if !bytes.Equal(got, st.frag) || (st.frag == nil) != (got == nil) {
					t.Fatalf("step %d: fragment %v, want %v", i, got, st.frag)
				}
				if r.Pending() != st.pending {
					t.Fatalf("step %d: pending %v, want %v", i, r.Pending(), st.pending)
				}
			}
		})
	}
}

// TestSpec8_2_2 checks clause 8.2.2 (p. 269): a segment carries 1 to 249
// octets of the fragment, segments may vary in size, and octet order is
// kept.
func TestSpec8_2_2(t *testing.T) {
	var s Segmenter
	if segs := s.Segment(nil); len(segs) != 0 {
		t.Fatalf("empty fragment: %d segments, want none", len(segs))
	}
	if s.Seq() != 0 {
		t.Fatal("an empty fragment used a sequence number")
	}
	// A header with no data is not a segment; a series in progress stays.
	r := NewReassembler(0)
	if _, err := r.Add(seg(true, true, 0)); !errors.Is(err, ErrNoData) {
		t.Fatalf("header only: %v", err)
	}
	_, _ = r.Add(seg(true, false, 0, 1))
	if _, err := r.Add(seg(false, false, 1)); !errors.Is(err, ErrNoData) || !r.Pending() {
		t.Fatalf("header only in a series: %v, pending %v", err, r.Pending())
	}
	// Rule 1: segments of varying sizes are accepted.
	r = NewReassembler(0)
	_, _ = r.Add(seg(true, false, 0, 1))
	_, _ = r.Add(append(seg(false, false, 1), fragment(249)...))
	got, err := r.Add(seg(false, true, 2, 2, 3))
	want := append(append([]byte{1}, fragment(249)...), 2, 3)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("varying sizes: %v", err)
	}
}

// TestSpecEX8_1 checks the segmenting example of clause 8.2.3 (EX 8-1,
// p. 270): a 600-octet fragment travels in three segments of 249, 249 and
// 102 octets, FIR on the first, FIN on the last, sequence numbers N, N+1,
// N+2.
func TestSpecEX8_1(t *testing.T) {
	s := Segmenter{seq: 62}
	frag := fragment(600)
	segs := s.Segment(frag)
	sizes := []int{249, 249, 102}
	seqs := []uint8{62, 63, 0}
	if len(segs) != 3 {
		t.Fatalf("%d segments", len(segs))
	}
	var joined []byte
	for i, sg := range segs {
		h := Header(sg[0])
		if len(sg)-1 != sizes[i] || h.Seq() != seqs[i] || h.FIR() != (i == 0) || h.FIN() != (i == 2) {
			t.Fatalf("segment %d: %d octets, %s", i, len(sg)-1, h)
		}
		joined = append(joined, sg[1:]...)
	}
	if !bytes.Equal(joined, frag) {
		t.Fatal("octet order not kept")
	}
}

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

// TestSpec8_2_1_HeaderFields checks the header octet of clause 8.2.1
// (Figure 8-3, p. 268): FIN is bit 7, FIR bit 6, and the sequence number
// bits 5..0 (8.2.1.3, 0 to 63). Every octet is a header.
func TestSpec8_2_1_HeaderFields(t *testing.T) {
	for b := range 256 {
		h := Header(b)
		if h.FIN() != (b&0x80 != 0) || h.FIR() != (b&0x40 != 0) || h.Seq() != uint8(b&0x3F) {
			t.Fatalf("%#02x: %s", b, h)
		}
		if NewHeader(h.FIR(), h.FIN(), h.Seq()) != h {
			t.Fatalf("%#02x does not round-trip", b)
		}
	}
	if NewHeader(false, false, 64) != 0 || NewHeader(false, false, 65) != 1 {
		t.Fatal("sequence numbers are not taken modulo 64")
	}
}

// TestSpec8_2_1_3_SequenceModulo64 checks clause 8.2.1.3 (p. 268): the
// sequence number increments by one for each segment, also from one
// fragment to the next, and 63 is followed by 0.
func TestSpec8_2_1_3_SequenceModulo64(t *testing.T) {
	s := Segmenter{seq: 60}
	var seqs []uint8
	for _, n := range []int{1, 600, 250, 1} {
		for _, sg := range s.Segment(fragment(n)) {
			seqs = append(seqs, Header(sg[0]).Seq())
		}
	}
	want := []uint8{60, 61, 62, 63, 0, 1, 2}
	if !bytes.Equal(seqs, want) {
		t.Fatalf("sequence numbers %v, want %v", seqs, want)
	}
	if s.Seq() != 3 {
		t.Fatalf("next sequence number %d, want 3", s.Seq())
	}
}

// TestSpec8_2_1_4_Rule4_AnyFirstSequence checks rules 4 and 6 of clause
// 8.2.1.4 (p. 269): a segment with FIR set may carry any sequence number,
// and a single segment with FIR and FIN is a whole fragment.
func TestSpec8_2_1_4_Rule4_AnyFirstSequence(t *testing.T) {
	r := NewReassembler(0)
	for seq := range uint8(64) {
		got, err := r.Add(seg(true, true, seq, seq))
		if err != nil || !bytes.Equal(got, []byte{seq}) {
			t.Fatalf("FIR FIN with sequence %d: %v %v", seq, got, err)
		}
	}
	// A series that starts at 63 continues at 0 (rule 5.1).
	_, _ = r.Add(seg(true, false, 63, 1))
	if got, err := r.Add(seg(false, true, 0, 2)); err != nil || !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("series 63, 0: %v %v", got, err)
	}
}

// TestSpec8_2_1_4_Rule5_3_Repeats checks rule 5.3 of clause 8.2.1.4 (p.
// 269) against its neighbours: only a repeat of the preceding segment is
// discarded without ending the series; several repeats in a row are all
// discarded; a repeat of an older segment is out of sequence (rule 5.4);
// a repeated first segment restarts the series with the same octets (rule
// 5.2), so the fragment is not changed.
func TestSpec8_2_1_4_Rule5_3_Repeats(t *testing.T) {
	r := NewReassembler(0)
	_, _ = r.Add(seg(true, false, 5, 0xA))
	_, _ = r.Add(seg(false, false, 6, 0xB))
	for range 3 {
		if _, err := r.Add(seg(false, false, 6, 0xB)); !errors.Is(err, ErrDuplicate) || !r.Pending() {
			t.Fatalf("repeat of the preceding segment: %v, pending %v", err, r.Pending())
		}
	}
	if got, err := r.Add(seg(false, true, 7, 0xC)); err != nil || !bytes.Equal(got, []byte{0xA, 0xB, 0xC}) {
		t.Fatalf("after the repeats: %v %v", got, err)
	}

	// A repeat of an older segment, not the preceding one.
	_, _ = r.Add(seg(true, false, 5, 0xA))
	_, _ = r.Add(seg(false, false, 6, 0xB))
	_, _ = r.Add(seg(false, false, 7, 0xC))
	if _, err := r.Add(seg(false, false, 6, 0xB)); !errors.Is(err, ErrSequence) || r.Pending() {
		t.Fatalf("repeat of an older segment: %v, pending %v", err, r.Pending())
	}

	// A repeated first segment.
	_, _ = r.Add(seg(true, false, 9, 0xA))
	if _, err := r.Add(seg(true, false, 9, 0xA)); err != nil || !r.Pending() {
		t.Fatalf("repeated first segment: %v", err)
	}
	if got, err := r.Add(seg(false, true, 10, 0xB)); err != nil || !bytes.Equal(got, []byte{0xA, 0xB}) {
		t.Fatalf("after a repeated first segment: %v %v", got, err)
	}

	// The final segment repeated after the fragment was passed up: no
	// series is in progress any more (rule 3).
	_, _ = r.Add(seg(true, false, 1, 1))
	_, _ = r.Add(seg(false, true, 2, 2))
	if _, err := r.Add(seg(false, true, 2, 2)); !errors.Is(err, ErrNoFirst) {
		t.Fatalf("repeated final segment: %v", err)
	}
}

// TestSpec8_2_1_4_Rule5_4_SequenceGaps checks rule 5.4 of clause 8.2.1.4
// and Table 8-1 rows 8 and 1 (p. 269, 272): a segment without FIR whose
// sequence number is the preceding one plus M, M in 2..63 (modulo 64), is
// discarded with the series, and a segment that would have followed it
// finds no series (row 1).
func TestSpec8_2_1_4_Rule5_4_SequenceGaps(t *testing.T) {
	for _, m := range []uint8{2, 3, 32, 62, 63} {
		r := NewReassembler(0)
		_, _ = r.Add(seg(true, false, 40, 1))
		_, _ = r.Add(seg(false, false, 41, 2))
		bad := (41 + m) & 0x3F
		if _, err := r.Add(seg(false, false, bad, 3)); !errors.Is(err, ErrSequence) || r.Pending() {
			t.Fatalf("M=%d: %v, pending %v", m, err, r.Pending())
		}
		if _, err := r.Add(seg(false, true, (bad+1)&0x3F, 4)); !errors.Is(err, ErrNoFirst) {
			t.Fatalf("M=%d: the segment after: %v", m, err)
		}
		// The next FIR starts a new series (rule 4).
		if got, err := r.Add(seg(true, true, 0, 5)); err != nil || !bytes.Equal(got, []byte{5}) {
			t.Fatalf("M=%d: new series: %v %v", m, got, err)
		}
	}
}

// TestSpec8_2_2_Rule1_VaryingSizes checks rule 1 of clause 8.2.2 (p. 269):
// the receiver accepts segments of different sizes in one series, from 1
// to 249 octets, and keeps the octet order (rule 2).
func TestSpec8_2_2_Rule1_VaryingSizes(t *testing.T) {
	r := NewReassembler(0)
	sizes := []int{1, 249, 17, 100, 249, 1}
	var want []byte
	var got []byte
	var err error
	for i, n := range sizes {
		part := make([]byte, n)
		for j := range part {
			part[j] = byte(len(want) + j)
		}
		want = append(want, part...)
		got, err = r.Add(append(seg(i == 0, i == len(sizes)-1, uint8(i)), part...))
		if err != nil {
			t.Fatalf("segment %d of %d octets: %v", i, n, err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fragment of %d octets, want %d", len(got), len(want))
	}
}

// TestSpecEX8_1_Headers checks the header octets of EX 8-1 (clause 8.2.3,
// p. 270) with the example's sequence number 25: FIR with 25, then 26,
// then FIN with 27, that is 0x59, 0x1A and 0x9B.
func TestSpecEX8_1_Headers(t *testing.T) {
	s := Segmenter{seq: 25}
	frag := fragment(600)
	segs := s.Segment(frag)
	want := []byte{0x59, 0x1A, 0x9B}
	if len(segs) != len(want) {
		t.Fatalf("%d segments", len(segs))
	}
	r := NewReassembler(0)
	var got []byte
	for i, sg := range segs {
		if sg[0] != want[i] {
			t.Fatalf("segment %d: header %#02x, want %#02x", i, sg[0], want[i])
		}
		var err error
		if got, err = r.Add(sg); err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
	}
	if !bytes.Equal(got, frag) {
		t.Fatal("the receiver did not rebuild the fragment")
	}
}

// SPDX-License-Identifier: MIT

// Package transport is the DNP3 transport function (IEEE 1815-2012
// clause 8): it splits application fragments into segments that fit one
// link frame and reassembles received segments into fragments.
//
// Each segment is one transport header octet (FIN, FIR and a six-bit
// sequence number) followed by up to [MaxSegmentData] octets of the
// fragment. The package keeps the sequence state of one direction of one
// association; it does no I/O.
package transport

import (
	"errors"
	"fmt"
)

const (
	// MaxSegmentData is the largest part of a fragment one segment
	// carries: a link frame's 250 octets of user data minus the header.
	MaxSegmentData = 249

	// MaxSegment is the largest segment, header included.
	MaxSegment = MaxSegmentData + 1

	// DefaultMaxFragment is the default limit on reassembled fragments,
	// the size most outstations and masters use.
	DefaultMaxFragment = 2048

	finBit  = 0x80
	firBit  = 0x40
	seqMask = 0x3F
)

// Reassembly errors returned by [Reassembler.Add]. Each reports a segment,
// and possibly the partial fragment before it, that was discarded; the
// Reassembler stays usable.
var (
	// ErrEmpty reports a segment without a header octet.
	ErrEmpty = errors.New("transport: empty segment")

	// ErrNoFirst reports a segment without FIR while no fragment was
	// being assembled.
	ErrNoFirst = errors.New("transport: segment without FIR outside a fragment")

	// ErrSequence reports a segment whose sequence number does not follow
	// the previous one; the partial fragment is discarded with it.
	ErrSequence = errors.New("transport: unexpected sequence number")

	// ErrTooLarge reports a fragment that grew beyond the limit; it is
	// discarded.
	ErrTooLarge = errors.New("transport: fragment too large")
)

// Header is the transport header octet.
type Header uint8

// NewHeader returns the header with the given flags and sequence number
// (taken modulo 64).
func NewHeader(fir, fin bool, seq uint8) Header {
	h := Header(seq & seqMask)
	if fir {
		h |= firBit
	}
	if fin {
		h |= finBit
	}
	return h
}

// FIR reports whether the segment is the first of a fragment.
func (h Header) FIR() bool { return h&firBit != 0 }

// FIN reports whether the segment is the last of a fragment.
func (h Header) FIN() bool { return h&finBit != 0 }

// Seq returns the sequence number, 0..63.
func (h Header) Seq() uint8 { return uint8(h & seqMask) }

// String returns, for example, "FIR FIN seq=5".
func (h Header) String() string {
	s := ""
	if h.FIR() {
		s += "FIR "
	}
	if h.FIN() {
		s += "FIN "
	}
	return fmt.Sprintf("%sseq=%d", s, h.Seq())
}

// Segmenter splits fragments for one direction of an association. The
// zero value starts with sequence number 0.
type Segmenter struct {
	seq uint8
}

// Segment splits fragment into segments, each ready to be the user data of
// one link frame, and advances the sequence number. A fragment of zero
// length is sent as one segment with only the header.
func (s *Segmenter) Segment(fragment []byte) [][]byte {
	n := max(1, (len(fragment)+MaxSegmentData-1)/MaxSegmentData)
	out := make([][]byte, 0, n)
	for i := range n {
		part := fragment[i*MaxSegmentData : min(len(fragment), (i+1)*MaxSegmentData)]
		seg := make([]byte, 0, 1+len(part))
		seg = append(seg, byte(NewHeader(i == 0, i == n-1, s.seq)))
		out = append(out, append(seg, part...))
		s.seq = (s.seq + 1) & seqMask
	}
	return out
}

// Seq returns the sequence number of the next segment.
func (s *Segmenter) Seq() uint8 { return s.seq }

// Reassembler rebuilds fragments for one direction of an association.
type Reassembler struct {
	max     int
	buf     []byte
	active  bool
	nextSeq uint8
}

// NewReassembler returns a Reassembler that accepts fragments of up to max
// octets. A max below 1 selects [DefaultMaxFragment].
func NewReassembler(max int) *Reassembler {
	if max < 1 {
		max = DefaultMaxFragment
	}
	return &Reassembler{max: max}
}

// Add processes one received segment. It returns the fragment when the
// segment completed one; the fragment is a new slice owned by the caller.
//
// The rules are those of IEEE 1815-2012 clause 8.2.1.2: a FIR segment
// always starts a new fragment, discarding any partial one; a segment
// without FIR must carry the next sequence number of the fragment in
// progress, or it and the partial fragment are discarded.
func (r *Reassembler) Add(segment []byte) ([]byte, error) {
	if len(segment) == 0 {
		return nil, ErrEmpty
	}
	h := Header(segment[0])
	data := segment[1:]
	if h.FIR() {
		r.buf = r.buf[:0]
		r.active = true
	} else {
		switch {
		case !r.active:
			return nil, fmt.Errorf("%w (%s)", ErrNoFirst, h)
		case h.Seq() != r.nextSeq:
			r.Reset()
			return nil, fmt.Errorf("%w: %d, want %d", ErrSequence, h.Seq(), r.nextSeq)
		}
	}
	if len(r.buf)+len(data) > r.max {
		r.Reset()
		return nil, fmt.Errorf("%w: more than %d octets", ErrTooLarge, r.max)
	}
	r.buf = append(r.buf, data...)
	r.nextSeq = (h.Seq() + 1) & seqMask
	if !h.FIN() {
		return nil, nil
	}
	frag := make([]byte, len(r.buf))
	copy(frag, r.buf)
	r.Reset()
	return frag, nil
}

// Reset discards a partial fragment, for example when the link is reset.
func (r *Reassembler) Reset() {
	r.buf = r.buf[:0]
	r.active = false
}

// Pending reports whether a fragment is partially assembled.
func (r *Reassembler) Pending() bool { return r.active }

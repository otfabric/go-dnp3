// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"errors"
	"io"
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

// TestDecodeAllocationBudget: Decode allocates the user data of the frame,
// at most MaxUserData octets in one allocation, and an error for a frame it
// refuses; never more because of what the length octet declares.
func TestDecodeAllocationBudget(t *testing.T) {
	full, err := (&Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0x5A}, MaxUserData)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	badBlock := append([]byte(nil), full...)
	badBlock[len(badBlock)-1] ^= 0xFF
	short := full[:HeaderLength+5]
	if n := testing.AllocsPerRun(100, func() { _, _, _ = Decode(full) }); n > 1 {
		t.Errorf("a frame of %d octets of user data: %.0f allocations, want 1", MaxUserData, n)
	}
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"frame of the largest length", full},
		{"data block CRC error", badBlock},
		{"frame cut short", short},
	} {
		// The user data (256 with the size class of 250) and an error of
		// at most a few hundred octets.
		const budget = 256 + 512
		if got := allocated(100, func() { _, _, _ = Decode(c.b) }); got > budget {
			t.Errorf("%s: %.0f octets allocated, budget %d", c.name, got, budget)
		}
	}
}

// TestReaderAllocationPerOctet: reading a long stream, valid or damaged,
// allocates in proportion to its octets, and the Reader holds no more than
// its buffer of two frames however long the stream is.
func TestReaderAllocationPerOctet(t *testing.T) {
	frame, err := (&Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0x5A}, MaxUserData)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		stream []byte
		// budget is octets allocated per input octet.
		budget float64
	}{
		// Each frame's user data is copied once: 256 octets for 292.
		{"valid frames", bytes.Repeat(frame, 1000), 2},
		// Every start sequence with a damaged header costs a framing
		// error and the next start sequence is searched from the octet
		// after it: two errors per two octets, of about two hundred
		// octets each.
		{"start sequences without a valid header", bytes.Repeat([]byte{Start0, Start1}, 64<<10), 512},
		// Octets without a start sequence are skipped in buffer-sized
		// runs, with one error per run.
		{"no start sequence", bytes.Repeat([]byte{0xAA}, 256<<10), 2},
	} {
		var r *Reader
		got := allocated(3, func() {
			r = NewReader(bytes.NewReader(c.stream))
			for {
				_, err := r.ReadFrame()
				if err != nil && !errors.Is(err, ErrFraming) {
					if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatalf("%s: %v", c.name, err)
					}
					return
				}
			}
		}) / float64(len(c.stream))
		t.Logf("%s: %d octets, %.2f octets allocated per input octet", c.name, len(c.stream), got)
		if got > c.budget {
			t.Errorf("%s: %.2f octets allocated per input octet, budget %.0f", c.name, got, c.budget)
		}
		if len(r.buf) != 2*MaxFrameLength || cap(r.buf) != 2*MaxFrameLength {
			t.Errorf("%s: the Reader's buffer grew to %d/%d octets", c.name, len(r.buf), cap(r.buf))
		}
	}
}

// SPDX-License-Identifier: MIT

package app

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

// TestDecodeAllocationBoundedByInput: a header whose count, range, index
// list or object size names more objects than its octets carry is refused
// with an allocation bounded by the length of the input, not by the
// number it declares.
func TestDecodeAllocationBoundedByInput(t *testing.T) {
	resp := []byte{0xC0, byte(FuncResponse), 0, 0}
	req := []byte{0xC0, byte(FuncWrite)}
	tail := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cases := []struct {
		name string
		b    []byte
	}{
		{"count 0xFFFFFFFF of g1v2", append(append(append([]byte(nil), resp...), 1, 2, 0x09, 0xFF, 0xFF, 0xFF, 0xFF), tail...)},
		{"count 0xFFFF of g30v1", append(append(append([]byte(nil), resp...), 30, 1, 0x08, 0xFF, 0xFF), tail...)},
		{"range 0..0xFFFFFFFF of g30v1", append(append(append([]byte(nil), resp...), 30, 1, 0x02, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF), tail...)},
		{"range 0..0xFFFFFFFF of packed g1v1", append(append(append([]byte(nil), resp...), 1, 1, 0x02, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF), tail...)},
		{"index list of 0xFFFF g2v1", append(append(append([]byte(nil), resp...), 2, 1, 0x28, 0xFF, 0xFF), tail...)},
		{"index list of 0xFFFFFFFF g32v1", append(append(append([]byte(nil), resp...), 32, 1, 0x39, 0xFF, 0xFF, 0xFF, 0xFF), tail...)},
		{"free-format object of 0xFFFF octets", append(append(append([]byte(nil), req...), 70, 5, 0x5B, 1, 0xFF, 0xFF), tail...)},
		{"free-format count 0xFF", append(append(append([]byte(nil), req...), 70, 5, 0x5B, 0xFF, 8, 0), tail...)},
	}
	for _, c := range cases {
		if _, err := Decode(c.b); err == nil {
			t.Errorf("%s: decoded", c.name)
			continue
		}
		// Refusing such a header costs at most an error and the headers
		// before it: 64 octets per input octet leaves room for the error's
		// formatting, while one object per declared count would be
		// megabytes.
		budget := 64 * float64(len(c.b))
		if got := allocated(100, func() { _, _ = Decode(c.b) }); got > budget {
			t.Errorf("%s: %.0f octets allocated for %d octets of input, budget %.0f", c.name, got, len(c.b), budget)
		}
	}
}

// TestDecodeAllocationPerOctet: a valid fragment of the largest default
// size decodes into objects whose memory is bounded per input octet. Packed
// bits are the densest encoding: eight objects per octet.
func TestDecodeAllocationPerOctet(t *testing.T) {
	bits := make([]Value, 8*(2048-16))
	for i := range bits {
		bits[i] = Binary{Value: i%3 == 0}
	}
	analogs := make([]Value, (2048-16)/5)
	for i := range analogs {
		analogs[i] = Analog{Value: float64(i), Flags: FlagOnline}
	}
	for _, c := range []struct {
		name string
		h    Header
		// budget is octets allocated per input octet: an object (index
		// and interface value, 24 octets) and its boxed value (up to 32
		// octets) for each of the eight objects an octet of packed bits
		// carries, with room for slice growth.
		budget float64
	}{
		{"packed g1v1", Ranged(G1V1, 0, bits...), 8 * (24 + 32) * 2},
		{"g30v1", Ranged(G30V1, 0, analogs...), 8 * (24 + 32) * 2},
	} {
		f := &Fragment{Control: SingleControl(0), Function: FuncResponse, Headers: []Header{c.h}}
		enc, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) > 2048 {
			t.Fatalf("%s: %d octets", c.name, len(enc))
		}
		if _, err := Decode(enc); err != nil {
			t.Fatal(err)
		}
		got := allocated(20, func() { _, _ = Decode(enc) }) / float64(len(enc))
		t.Logf("%s: %d octets, %.1f octets allocated per input octet", c.name, len(enc), got)
		if got > c.budget {
			t.Errorf("%s: %.1f octets allocated per input octet, budget %.0f", c.name, got, c.budget)
		}
	}
}

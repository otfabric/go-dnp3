// SPDX-License-Identifier: MIT

package app

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// TestTwosComplement checks the signed reinterpretations against Go's
// conversions: every 8- and 16-bit value, and the 32-bit boundaries.
func TestTwosComplement(t *testing.T) {
	for v := range 256 {
		if got, want := int8of(byte(v)), int32(int8(v)); got != want {
			t.Fatalf("int8of(%#x) = %d, want %d", v, got, want)
		}
	}
	for v := range 1 << 16 {
		u := uint16(v)
		if got, want := int16of(u), int32(int16(u)); got != want {
			t.Fatalf("int16of(%#x) = %d, want %d", v, got, want)
		}
		if got := uint16of(int16(u)); got != u {
			t.Fatalf("uint16of(%d) = %#x", int16(u), got)
		}
	}
	for _, c := range []struct {
		u uint32
		i int32
	}{
		{0, 0}, {1, 1}, {0x7FFFFFFF, math.MaxInt32}, {0x80000000, math.MinInt32}, {0x80000001, math.MinInt32 + 1},
		{0xFFFFFFFE, -2}, {0xFFFFFFFF, -1}, {0x12345678, 0x12345678}, {0xDEADBEEF, -0x21524111},
	} {
		if got := int32of(c.u); got != c.i {
			t.Fatalf("int32of(%#x) = %d, want %d", c.u, got, c.i)
		}
		if got := uint32of(c.i); got != c.u {
			t.Fatalf("uint32of(%d) = %#x, want %#x", c.i, got, c.u)
		}
	}
}

// TestIntAttributeRoundTrip: signed attributes of every width keep their
// sign.
func TestIntAttributeRoundTrip(t *testing.T) {
	for _, v := range []int32{0, 1, -1, math.MaxInt32, math.MinInt32, -129, 300} {
		if got, err := IntAttribute(v).Int(); err != nil || got != v {
			t.Fatalf("IntAttribute(%d).Int() = %d, %v", v, got, err)
		}
	}
	for _, c := range []struct {
		data []byte
		want int32
	}{
		{[]byte{0xFF}, -1},
		{[]byte{0x80}, -128},
		{[]byte{0x7F}, 127},
		{binary.LittleEndian.AppendUint16(nil, 0x8000), -32768},
		{binary.LittleEndian.AppendUint16(nil, 0xFFFE), -2},
	} {
		a := Attribute{Type: AttrSignedInt, Data: c.data}
		if got, err := a.Int(); err != nil || got != c.want {
			t.Fatalf("Int of % x = %d, %v, want %d", c.data, got, err, c.want)
		}
	}
}

// TestOctetStringGVBounds: a length without a variation does not wrap to
// one that has a meaning.
func TestOctetStringGVBounds(t *testing.T) {
	for n, want := range map[int]uint8{-1: 0, 0: 0, 1: 1, 255: 255, 256: 0, 257: 0, 511: 0} {
		if got := OctetStringGV(110, n); got != GV(110, want) {
			t.Errorf("OctetStringGV(110, %d) = %s, want g110v%d", n, got, want)
		}
	}
	h := Indexed(OctetStringGV(110, 256), Object{Index: 0, Value: OctetString{Data: make([]byte, 256)}})
	if _, err := (&Fragment{Function: FuncResponse, Headers: []Header{h}}).Encode(); err == nil {
		t.Fatal("an octet string of 256 octets encoded")
	}
}

// TestActivateConfigStatusBounds: the delay and the status texts are
// checked at their limits.
func TestActivateConfigStatusBounds(t *testing.T) {
	ok := []ActivateConfigStatus{
		{Delay: 0},
		{Delay: 0xFFFFFFFF * time.Millisecond},
		{Results: []ActivateConfigResult{{Text: string(make([]byte, maxActivationText))}}},
		{Results: make([]ActivateConfigResult, maxActivationResults)},
	}
	for i, s := range ok {
		if _, err := s.Raw(); err != nil {
			t.Errorf("valid status %d: %v", i, err)
		}
	}
	bad := []ActivateConfigStatus{
		{Delay: -time.Millisecond},
		{Delay: 0x100000000 * time.Millisecond},
		{Results: []ActivateConfigResult{{Text: string(make([]byte, maxActivationText+1))}}},
		{Results: make([]ActivateConfigResult, maxActivationResults+1)},
	}
	for i, s := range bad {
		if _, err := s.Raw(); err == nil {
			t.Errorf("invalid status %d encoded", i)
		}
	}
}

// TestLengthHelpers: the clamps never wrap.
func TestLengthHelpers(t *testing.T) {
	if len16(-1) != 0 || len16(0xFFFF) != 0xFFFF || len16(0x10000) != 0xFFFF {
		t.Fatal("len16")
	}
	if len32(-1) != 0 || len32(1<<20) != 1<<20 {
		t.Fatal("len32")
	}
	if ulen(-5) != 0 || ulen(7) != 7 {
		t.Fatal("ulen")
	}
}

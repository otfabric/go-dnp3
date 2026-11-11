// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
)

// TestSpec11_3_3_PackedBits: packed bit strings start in bit 0 of the
// first octet and the last octet is padded with 0 bits (IEEE 1815-2012
// 11.3.3, printed p308). EX 4-10 (4.4.2, p43) reads 18 binary inputs as
// g1v1 qualifier 0x00, 0..17, with the octets 0F AA 03.
func TestSpec11_3_3_PackedBits(t *testing.T) {
	want := []bool{true, true, true, true, false, false, false, false,
		false, true, false, true, false, true, false, true, true, true}
	objs := make([]Object, len(want))
	for i, v := range want {
		objs[i] = Object{uint32(i), Binary{Value: v}}
	}
	vector(t, "EX 4-10", "C3 81 00 00 01 01 00 00 11 0F AA 03",
		Header{GV: G1V1, Qualifier: 0x00, Start: 0, Stop: 17, Objects: objs})
	// Padding bits that are not 0 are ignored, and sent as 0.
	f, err := Decode(unhex(t, "C3 81 00 00 01 01 00 00 11 0F AA FF"))
	if err != nil || !reflect.DeepEqual(f.Headers[0].Objects, objs) {
		t.Fatalf("non-zero padding: %v, %v", f, err)
	}
	if b := mustEncode(t, f); b[len(b)-1] != 0x03 {
		t.Fatalf("padding sent as % X", b[len(b)-1:])
	}

	// BSTR2 of g3v1: two bits a point, five points in two octets.
	states := []DoubleBit{DoubleBitOff, DoubleBitOn, DoubleBitIntermediate, DoubleBitIndeterminate, DoubleBitOn}
	dobjs := make([]Object, len(states))
	for i, s := range states {
		dobjs[i] = Object{uint32(i), DoubleBitBinary{Value: s}}
	}
	vector(t, "g3v1", "C0 81 00 00 03 01 00 00 04 C9 02",
		Header{GV: G3V1, Qualifier: 0x00, Start: 0, Stop: 4, Objects: dobjs})
}

// TestSpec11_3_4_Integers: integers are little-endian and signed integers
// two's complement (IEEE 1815-2012 11.3.4, printed p309). EX 11-1: the
// INT16 –22 000 is 10 AA and the UINT32 4 000 000 000 is 00 28 6B EE.
func TestSpec11_3_4_Integers(t *testing.T) {
	vector(t, "INT16 (g30v4)", "C0 81 00 00 1E 04 00 00 00 10 AA",
		Header{GV: G30V4, Qualifier: 0x00, Objects: []Object{{0, Analog{Value: -22000}}}})
	vector(t, "UINT32 (g20v5)", "C0 81 00 00 14 05 00 00 00 00 28 6B EE",
		Header{GV: G20V5, Qualifier: 0x00, Objects: []Object{{0, Counter{Value: 4_000_000_000}}}})
	vector(t, "INT32 (g30v1)", "C0 81 00 00 1E 01 00 00 00 01 60 79 FE FF",
		Header{GV: G30V1, Qualifier: 0x00, Objects: []Object{{0, Analog{Value: -100000, Flags: FlagOnline}}}})
	vector(t, "UINT16 (g20v6)", "C0 81 00 00 14 06 00 00 00 FF FF",
		Header{GV: G20V6, Qualifier: 0x00, Objects: []Object{{0, Counter{Value: 65535}}}})
}

// TestSpec11_3_5_FloatingPoint: FLT32 and FLT64 are IEEE 754 values sent
// least significant octet first (IEEE 1815-2012 11.3.5, printed p310–311).
// EX 11-2 is the FLT64 –2.325 889 034 4e+03: 20 74 85 2F C7 2B A2 C0.
func TestSpec11_3_5_FloatingPoint(t *testing.T) {
	ex := math.Float64frombits(0xC0A22BC72F857420)
	if math.Abs(ex-(-2325.8890344)) > 1e-6 {
		t.Fatalf("EX 11-2 value %v", ex)
	}
	vector(t, "FLT64 (g30v6)", "C0 81 00 00 1E 06 00 00 00 01 20 74 85 2F C7 2B A2 C0",
		Header{GV: G30V6, Qualifier: 0x00, Objects: []Object{{0, Analog{Value: ex, Flags: FlagOnline}}}})
	vector(t, "FLT64 (g40v4)", "C0 81 00 00 28 04 00 00 00 01 20 74 85 2F C7 2B A2 C0",
		Header{GV: G40V4, Qualifier: 0x00, Objects: []Object{{0, Analog{Value: ex, Flags: FlagOnline}}}})
	f32 := float64(float32(ex))
	vector(t, "FLT32 (g30v5)", "C0 81 00 00 1E 05 00 00 00 01 39 5E 11 C5",
		Header{GV: G30V5, Qualifier: 0x00, Objects: []Object{{0, Analog{Value: f32, Flags: FlagOnline}}}})
}

// TestSpecTable11_4_DNP3Time: DNP3TIME is a UINT48 of milliseconds since
// 1970-01-01 UTC (IEEE 1815-2012 clause 3, printed p5; Table 11-4, p321),
// sent least significant octet first (1.3, p2).
func TestSpecTable11_4_DNP3Time(t *testing.T) {
	vector(t, "g50v1", "C0 81 00 00 32 01 07 01 06 05 04 03 02 01",
		Header{GV: G50V1, Qualifier: 0x07, Count: 1, Objects: []Object{{0, AbsoluteTime{Time: 0x010203040506}}}})
	vector(t, "g50v1 max", "C0 81 00 00 32 01 07 01 FF FF FF FF FF FF",
		Header{GV: G50V1, Qualifier: 0x07, Count: 1, Objects: []Object{{0, AbsoluteTime{Time: MaxTimestamp}}}})
	if got := Timestamp(1_199_145_600_000).String(); got != "2008-01-01T00:00:00.000Z" {
		t.Fatalf("2008-01-01 is %s", got)
	}
}

// TestSpec11_3_7_VisibleStringOctets: only the characters 32..126 of a
// VSTR are guaranteed to be interoperable (IEEE 1815-2012 11.3.7.1,
// printed p312); the codec carries every octet unchanged.
func TestSpec11_3_7_VisibleStringOctets(t *testing.T) {
	a := Attribute{Type: AttrVisibleString, Data: []byte{0x00, 0x1F, 0x7F, 0x80, 0xFF, 'A'}}
	d := roundTrip(t, FuncResponse, Ranged(GV(0, AttrUserDeviceName), 0, a))
	if got := d.Headers[0].Objects[0].Value.(Attribute); !bytes.Equal(got.Data, a.Data) || got.Text() != string(a.Data) {
		t.Fatalf("VSTR % X", got.Data)
	}
}

// TestSpec11_3_8_OctetString: an octet string object's variation is its
// length (IEEE 1815-2012 11.3.8, printed p319; A.41.1, p715).
func TestSpec11_3_8_OctetString(t *testing.T) {
	vector(t, "g110v3", "C0 81 00 00 6E 03 00 00 00 41 00 FF",
		Header{GV: GV(110, 3), Qualifier: 0x00, Objects: []Object{{0, OctetString{Data: []byte{'A', 0, 0xFF}}}}})
	vector(t, "g111v2", "C0 81 00 00 6F 02 17 01 07 01 02",
		Header{GV: GV(111, 2), Qualifier: 0x17, Count: 1, Objects: []Object{{7, OctetString{Data: []byte{1, 2}}}}})
}

// TestSpec11_3_11_UnicodeAttribute: data type code 8, UNCD, is a UTF-8
// string (IEEE 1815-2012 11.3.11, printed p320; Table 11-4, p321); the
// codec carries an attribute of that type as its octets.
func TestSpec11_3_11_UnicodeAttribute(t *testing.T) {
	f := vector(t, "UNCD", "C0 81 00 00 00 FA 00 00 00 08 03 E6 97 A5",
		Header{GV: GV(0, AttrProductNameAndModel), Qualifier: 0x00, Objects: []Object{{0, Attribute{Type: 8, Data: []byte("日")}}}})
	if a := f.Headers[0].Objects[0].Value.(Attribute); a.Text() != "日" || a.Type.String() != "ATTR_TYPE(8)" {
		t.Fatalf("attribute %+v", a)
	}
}

// TestSpec11_4_FloatAttributeSize: floating-point values are 4 or 8
// octets, "no other sizes are acceptable" (IEEE 1815-2012 11.4, printed
// p321, and 5.5.4.3, p150). The encoder refuses another size and the
// decoder reports it malformed.
func TestSpec11_4_FloatAttributeSize(t *testing.T) {
	for _, n := range []int{4, 8} {
		a := Attribute{Type: AttrFloat, Data: make([]byte, n)}
		roundTrip(t, FuncResponse, Ranged(GV(0, AttrDeviceAltitude), 0, a))
		if v, err := a.Float(); err != nil || v != 0 {
			t.Errorf("FLT of %d octets: %v %v", n, v, err)
		}
	}
	for _, n := range []int{0, 1, 3, 5, 7, 9, 16} {
		a := Attribute{Type: AttrFloat, Data: make([]byte, n)}
		f := &Fragment{Function: FuncResponse, Headers: []Header{Ranged(GV(0, AttrDeviceAltitude), 0, a)}}
		if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("encode FLT of %d octets: %v", n, err)
		}
		if _, err := a.Float(); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Float of %d octets: %v", n, err)
		}
	}
	// g0v203 (an attribute variation the codec carries as any other) with
	// a FLT of 3 octets, in a response and in a WRITE.
	for _, hx := range []string{"C0 81 00 00 00 CB 00 00 00 04 03 01 02 03", "C0 02 00 CB 00 00 00 04 03 01 02 03"} {
		if _, err := Decode(unhex(t, hx)); !errors.Is(err, ErrMalformed) {
			t.Errorf("decode %s: %v", hx, err)
		}
	}
}

// TestSpecTable5_16_AttributeLists: U8BS8LIST (254) carries its length in
// the length octet; U8BS8EXLIST (255) is 256 plus the length octet
// (IEEE 1815-2012 5.5.4.3, Table 5-16, printed p150).
func TestSpecTable5_16_AttributeLists(t *testing.T) {
	enc := func(a Attribute) ([]byte, error) {
		return (&Fragment{Function: FuncResponse, Headers: []Header{Ranged(GV(0, AttrListOfVariations), 0, a)}}).Encode()
	}
	for _, c := range []struct {
		a      Attribute
		length byte
	}{
		{Attribute{Type: AttrList, Data: make([]byte, 255)}, 255},
		{Attribute{Type: AttrExtList, Data: make([]byte, 256)}, 0},
		{Attribute{Type: AttrExtList, Data: make([]byte, 511)}, 255},
	} {
		b, err := enc(c.a)
		if err != nil {
			t.Fatalf("%s of %d octets: %v", c.a.Type, len(c.a.Data), err)
		}
		if at := 4 + 5; b[at] != byte(c.a.Type) || b[at+1] != c.length {
			t.Errorf("%s of %d octets: type and length % X", c.a.Type, len(c.a.Data), b[at:at+2])
		}
		f, err := Decode(b)
		if err != nil || len(f.Headers[0].Objects[0].Value.(Attribute).Data) != len(c.a.Data) {
			t.Errorf("%s of %d octets: decoded %v, %v", c.a.Type, len(c.a.Data), f, err)
		}
	}
	for _, a := range []Attribute{
		{Type: AttrList, Data: make([]byte, 256)},
		{Type: AttrExtList, Data: make([]byte, 255)},
		{Type: AttrExtList, Data: make([]byte, 512)},
	} {
		if _, err := enc(a); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s of %d octets: %v", a.Type, len(a.Data), err)
		}
	}
	// ListAttribute switches to the extended list above 255 octets.
	if l := ListAttribute(make([]AttributeListEntry, 127)...); l.Type != AttrList || len(l.Data) != 254 {
		t.Errorf("127 entries: %s of %d", l.Type, len(l.Data))
	}
	if l := ListAttribute(make([]AttributeListEntry, 128)...); l.Type != AttrExtList || len(l.Data) != 256 {
		t.Errorf("128 entries: %s of %d", l.Type, len(l.Data))
	}
}

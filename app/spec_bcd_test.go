// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"testing"
)

// bcdResponse returns a RESPONSE with one g101 header (qualifier 0x00,
// index 0) carrying the octets of one BCD object.
func bcdResponse(gv GroupVariation, obj string) string {
	return "C0 81 00 00 65 0" + string('0'+rune(gv.Variation())) + " 00 00 00 " + obj
}

// TestSpec11_3_6_BCDValues: BCD characters are sent least significant
// first, two to an octet, and an odd number of characters is padded with
// a 0 in the most significant position (IEEE 1815-2012 11.3.6.2, printed
// p312: "173bcd is transmitted as 0173bcd, and –57bcd is transmitted as
// –057bcd"). BCD4, BCD8 and BCD16 are g101v1..v3 (A.39, p711–713).
func TestSpec11_3_6_BCDValues(t *testing.T) {
	cases := []struct {
		gv   GroupVariation
		wire string
		want BCD
	}{
		{G101V1, "73 01", BCD{Value: 173}},
		{G101V1, "00 00", BCD{}},
		{G101V1, "99 99", BCD{Value: 9999}},
		{G101V1, "57 F0", BCD{Value: 57, Negative: true}},
		{G101V1, "34 F2", BCD{Value: 234, Negative: true}},
		{G101V1, "99 F9", BCD{Value: 999, Negative: true}},
		{G101V2, "78 56 34 12", BCD{Value: 12345678}},
		{G101V2, "99 99 99 99", BCD{Value: 99999999}},
		{G101V2, "99 99 99 F9", BCD{Value: 9999999, Negative: true}},
		{G101V3, "99 99 99 99 99 99 99 99", BCD{Value: 9999999999999999}},
		{G101V3, "99 99 99 99 99 99 99 F9", BCD{Value: 999999999999999, Negative: true}},
		{G101V3, "01 00 00 00 00 00 00 F0", BCD{Value: 1, Negative: true}},
	}
	for _, c := range cases {
		b := unhex(t, bcdResponse(c.gv, c.wire))
		f, err := Decode(b)
		if err != nil {
			t.Fatalf("%s %s: %v", c.gv, c.wire, err)
		}
		if got := f.Headers[0].Objects[0].Value; got != c.want {
			t.Errorf("%s %s: decoded %+v, want %+v", c.gv, c.wire, got, c.want)
		}
		if re := mustEncode(t, f); !bytes.Equal(re, b) {
			t.Errorf("%s %+v: encoded % X, want % X", c.gv, c.want, re, b)
		}
	}
}

// TestSpec11_3_6_1_NegativeSign: in the most significant BCD character any
// of the codes 0xA..0xF indicates a negative value; in all other positions
// these codes are illegal (IEEE 1815-2012 11.3.6.1, Table 11-2, printed
// p311–312). The range of BCDn is –10^(n–1)+1 to 10^n–1 (11.3.6.2, p312).
func TestSpec11_3_6_1_NegativeSign(t *testing.T) {
	for _, sign := range []string{"A", "B", "C", "D", "E", "F"} {
		f, err := Decode(unhex(t, bcdResponse(G101V1, "34 "+sign+"2")))
		if err != nil {
			t.Fatalf("sign %s: %v", sign, err)
		}
		if got := f.Headers[0].Objects[0].Value; got != (BCD{Value: 234, Negative: true}) {
			t.Errorf("sign %s: %+v", sign, got)
		}
		// Sent back with the sign character of this package.
		if re := mustEncode(t, f); !bytes.Equal(re[len(re)-2:], []byte{0x34, 0xF2}) {
			t.Errorf("sign %s re-encoded as % X", sign, re[len(re)-2:])
		}
	}
	// A sign character anywhere but the most significant position.
	for _, wire := range []string{"F4 12", "3A 12", "34 2F", "99 99 A9 09"} {
		gv := G101V1
		if len(wire) > 5 {
			gv = G101V2
		}
		if _, err := Decode(unhex(t, bcdResponse(gv, wire))); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", wire, err)
		}
	}
	// A negative zero is zero.
	f, err := Decode(unhex(t, bcdResponse(G101V1, "00 F0")))
	if err != nil || f.Headers[0].Objects[0].Value != (BCD{}) {
		t.Fatalf("negative zero: %v %v", f, err)
	}
	if b := mustEncode(t, &Fragment{Function: FuncResponse, Headers: []Header{Ranged(G101V1, 0, BCD{Negative: true})}}); !bytes.Equal(b[len(b)-2:], []byte{0, 0}) {
		t.Fatalf("negative zero encoded as % X", b[len(b)-2:])
	}
	// Values outside the range of the variation are refused.
	for _, c := range []struct {
		gv GroupVariation
		v  BCD
	}{
		{G101V1, BCD{Value: 10000}},
		{G101V1, BCD{Value: 1000, Negative: true}},
		{G101V2, BCD{Value: 100000000}},
		{G101V2, BCD{Value: 10000000, Negative: true}},
		{G101V3, BCD{Value: 10000000000000000}},
		{G101V3, BCD{Value: 1000000000000000, Negative: true}},
	} {
		f := &Fragment{Function: FuncResponse, Headers: []Header{Ranged(c.gv, 0, c.v)}}
		if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s %+v: err = %v, want ErrInvalidValue", c.gv, c.v, err)
		}
	}
}

// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// vector decodes the fragment in hex, compares its headers with want and
// encodes it back to the same octets.
func vector(t *testing.T, name, hx string, want ...Header) *Fragment {
	t.Helper()
	b := unhex(t, hx)
	f, err := Decode(b)
	if err != nil {
		t.Fatalf("%s: decode: %v", name, err)
	}
	if !reflect.DeepEqual(f.Headers, want) {
		t.Fatalf("%s: headers\n %#v\nwant\n %#v", name, f.Headers, want)
	}
	if re := mustEncode(t, f); !bytes.Equal(re, b) {
		t.Fatalf("%s: encoded\n % X\nwant\n % X", name, re, b)
	}
	return f
}

// TestSpecTable4_6_QualifierVectors: one byte vector for each valid
// qualifier code of IEEE 1815-2012 Table 4-6 (4.2.2.7.3.4, printed p34),
// with the prefix of Table 4-4 (p32) and the range field of Table 4-5
// (p33). Every multi-octet field is little-endian (1.3, p2). The objects
// are g30v2 (flag, INT16), g102v1 (UINT8, the object of the virtual
// address codes 0x03..0x05, 4.2.2.7.3.3, p34) and g70v5 (free format).
func TestSpecTable4_6_QualifierVectors(t *testing.T) {
	a := func(v float64) Analog { return Analog{Value: v, Flags: FlagOnline} }
	u := func(v uint8) UnsignedInteger { return UnsignedInteger{Value: v} }
	const resp = "C0 81 00 00 "

	vector(t, "0x00", resp+"1E 02 00 05 06 01 0A 00 01 0B 00",
		Header{GV: G30V2, Qualifier: 0x00, Start: 5, Stop: 6, Objects: []Object{{5, a(10)}, {6, a(11)}}})
	vector(t, "0x01", resp+"1E 02 01 00 01 01 01 01 0A 00 01 0B 00",
		Header{GV: G30V2, Qualifier: 0x01, Start: 256, Stop: 257, Objects: []Object{{256, a(10)}, {257, a(11)}}})
	vector(t, "0x02", resp+"1E 02 02 70 11 01 00 70 11 01 00 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x02, Start: 70000, Stop: 70000, Objects: []Object{{70000, a(10)}}})
	vector(t, "0x03", resp+"66 01 03 02 03 AA BB",
		Header{GV: G102V1, Qualifier: 0x03, Start: 2, Stop: 3, Objects: []Object{{2, u(0xAA)}, {3, u(0xBB)}}})
	vector(t, "0x04", resp+"66 01 04 00 01 01 01 AA BB",
		Header{GV: G102V1, Qualifier: 0x04, Start: 256, Stop: 257, Objects: []Object{{256, u(0xAA)}, {257, u(0xBB)}}})
	vector(t, "0x05", resp+"66 01 05 70 11 01 00 70 11 01 00 AA",
		Header{GV: G102V1, Qualifier: 0x05, Start: 70000, Stop: 70000, Objects: []Object{{70000, u(0xAA)}}})
	vector(t, "0x06 in a request", "C0 01 1E 02 06",
		Header{GV: G30V2, Qualifier: 0x06})
	vector(t, "0x07", resp+"66 01 07 02 AA BB",
		Header{GV: G102V1, Qualifier: 0x07, Count: 2, Objects: []Object{{0, u(0xAA)}, {1, u(0xBB)}}})
	// A count of 0 carries no objects.
	vector(t, "0x07 count 0", resp+"32 01 07 00",
		Header{GV: G50V1, Qualifier: 0x07, Objects: []Object{}})
	many := make([]Object, 256)
	data := make([]string, 256)
	for i := range many {
		many[i] = Object{uint32(i), u(uint8(i))}
		data[i] = fmt.Sprintf("%02X", i)
	}
	vector(t, "0x08", resp+"66 01 08 00 01 "+strings.Join(data, " "),
		Header{GV: G102V1, Qualifier: 0x08, Count: 256, Objects: many})
	vector(t, "0x09", resp+"66 01 09 02 00 00 00 AA BB",
		Header{GV: G102V1, Qualifier: 0x09, Count: 2, Objects: []Object{{0, u(0xAA)}, {1, u(0xBB)}}})

	vector(t, "0x17", resp+"1E 02 17 02 05 01 0A 00 09 01 0B 00",
		Header{GV: G30V2, Qualifier: 0x17, Count: 2, Objects: []Object{{5, a(10)}, {9, a(11)}}})
	vector(t, "0x18", resp+"1E 02 18 02 00 05 01 0A 00 09 01 0B 00",
		Header{GV: G30V2, Qualifier: 0x18, Count: 2, Objects: []Object{{5, a(10)}, {9, a(11)}}})
	vector(t, "0x19", resp+"1E 02 19 01 00 00 00 05 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x19, Count: 1, Objects: []Object{{5, a(10)}}})
	vector(t, "0x27", resp+"1E 02 27 01 00 01 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x27, Count: 1, Objects: []Object{{256, a(10)}}})
	vector(t, "0x28", resp+"1E 02 28 01 00 00 01 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x28, Count: 1, Objects: []Object{{256, a(10)}}})
	vector(t, "0x29", resp+"1E 02 29 01 00 00 00 00 01 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x29, Count: 1, Objects: []Object{{256, a(10)}}})
	vector(t, "0x37", resp+"1E 02 37 01 70 11 01 00 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x37, Count: 1, Objects: []Object{{70000, a(10)}}})
	vector(t, "0x38", resp+"1E 02 38 01 00 70 11 01 00 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x38, Count: 1, Objects: []Object{{70000, a(10)}}})
	vector(t, "0x39", resp+"1E 02 39 01 00 00 00 70 11 01 00 01 0A 00",
		Header{GV: G30V2, Qualifier: 0x39, Count: 1, Objects: []Object{{70000, a(10)}}})

	ft := FileTransport{Handle: 0x1234, Block: 7, Last: true, Data: []byte("data")}
	vector(t, "0x4B", resp+"46 05 4B 01 0C 34 12 00 00 07 00 00 80 64 61 74 61",
		Header{GV: G70V5, Qualifier: 0x4B, Count: 1, Objects: []Object{{0, ft}}})
	vector(t, "0x5B", resp+"46 05 5B 01 0C 00 34 12 00 00 07 00 00 80 64 61 74 61",
		Header{GV: G70V5, Qualifier: 0x5B, Count: 1, Objects: []Object{{0, ft}}})
	vector(t, "0x6B", resp+"46 05 6B 01 0C 00 00 00 34 12 00 00 07 00 00 80 64 61 74 61",
		Header{GV: G70V5, Qualifier: 0x6B, Count: 1, Objects: []Object{{0, ft}}})
}

// TestSpec4_2_2_7_3_2_IndexListRequests: in a request, index prefixes
// with "null objects" name points without values (IEEE 1815-2012
// 4.2.2.7.3.2, Figure 4-12, printed p33), at each index width.
func TestSpec4_2_2_7_3_2_IndexListRequests(t *testing.T) {
	idx := func(xs ...uint32) []Object {
		o := make([]Object, len(xs))
		for i, x := range xs {
			o[i].Index = x
		}
		return o
	}
	vector(t, "0x17", "C0 01 1E 02 17 02 05 09", Header{GV: G30V2, Qualifier: 0x17, Count: 2, Objects: idx(5, 9)})
	vector(t, "0x28", "C0 01 1E 02 28 01 00 00 01", Header{GV: G30V2, Qualifier: 0x28, Count: 1, Objects: idx(256)})
	vector(t, "0x38", "C0 01 1E 02 38 01 00 70 11 01 00", Header{GV: G30V2, Qualifier: 0x38, Count: 1, Objects: idx(70000)})
	// A count of 0 names no point.
	vector(t, "0x28 count 0", "C0 01 1E 02 28 00 00", Header{GV: G30V2, Qualifier: 0x28})
}

// TestSpecTable4_6_ReservedQualifiers: the qualifier codes outside
// IEEE 1815-2012 Table 4-6 (printed p34) are reserved; so is bit 7
// (4.2.2.7.3.1, "shall be set to 0"). Every one of the 256 octets is
// checked, and the decoder refuses the reserved ones.
func TestSpecTable4_6_ReservedQualifiers(t *testing.T) {
	valid := map[Qualifier]bool{}
	for _, q := range []Qualifier{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x17, 0x18, 0x19, 0x27, 0x28, 0x29, 0x37, 0x38, 0x39, 0x4B, 0x5B, 0x6B} {
		valid[q] = true
	}
	for b := range 256 {
		q := Qualifier(b)
		if q.Valid() != valid[q] {
			t.Errorf("%s: Valid() = %v", q, q.Valid())
		}
		_, err := Decode([]byte{0xC0, 0x01, 0x1E, 0x02, byte(b), 0, 0, 0, 0, 0, 0, 0, 0})
		if !valid[q] && !errors.Is(err, ErrInvalidQualifier) {
			t.Errorf("%s: decode err = %v, want ErrInvalidQualifier", q, err)
		}
		if _, err := (&Fragment{Function: FuncRead, Headers: []Header{{GV: G30V2, Qualifier: q}}}).Encode(); !valid[q] && !errors.Is(err, ErrInvalidQualifier) {
			t.Errorf("%s: encode err = %v, want ErrInvalidQualifier", q, err)
		}
	}
}

// TestSpecTable4_7_BuilderQualifiers: the header constructors use the
// preferred qualifiers of IEEE 1815-2012 Table 4-7 (printed p35) while
// they hold the indexes and counts, a four-octet index only above 65 535,
// and a four-octet count only when nothing smaller holds it
// (4.2.2.7.3.4, p34, "should").
func TestSpecTable4_7_BuilderQualifiers(t *testing.T) {
	idx := func(n int, last uint32) []uint32 {
		xs := make([]uint32, n)
		for i := range xs {
			xs[i] = uint32(i)
		}
		xs[n-1] = last
		return xs
	}
	cases := []struct {
		name string
		h    Header
		want Qualifier
	}{
		{"AllObjects", AllObjects(G1V0), 0x06},
		{"ClassHeaders", ClassHeaders(1)[0], 0x06},
		{"IndexRange 0..255", IndexRange(G30V0, 0, 255), 0x00},
		{"IndexRange 0..256", IndexRange(G30V0, 0, 256), 0x01},
		{"IndexRange 0..65535", IndexRange(G30V0, 0, 65535), 0x01},
		{"IndexRange 0..65536", IndexRange(G30V0, 0, 65536), 0x02},
		{"Ranged at 255", Ranged(G30V1, 255, Analog{}), 0x00},
		{"Ranged at 256", Ranged(G30V1, 256, Analog{}), 0x01},
		{"Ranged 65535..65536", Ranged(G30V1, 65535, Analog{}, Analog{}), 0x02},
		{"CountOf 255", CountOf(G2V0, 255), 0x07},
		{"CountOf 256", CountOf(G2V0, 256), 0x08},
		{"CountOf 65535", CountOf(G2V0, 65535), 0x08},
		{"CountOf 65536", CountOf(G2V0, 65536), 0x09},
		{"Counted", Counted(G50V1, AbsoluteTime{}), 0x07},
		{"IndexList 255", IndexList(G30V0, 255), 0x17},
		{"IndexList 256", IndexList(G30V0, 256), 0x28},
		{"IndexList 65535", IndexList(G30V0, 65535), 0x28},
		{"IndexList 65536", IndexList(G30V0, 65536), 0x37},
		{"IndexList of 256", IndexList(G30V0, idx(256, 5)...), 0x28},
		{"IndexList of 256 to 70000", IndexList(G30V0, idx(256, 70000)...), 0x38},
		{"Indexed 255", Indexed(G12V1, Object{255, CROB{}}), 0x17},
		{"Indexed 256", Indexed(G12V1, Object{256, CROB{}}), 0x28},
		{"Indexed 70000", Indexed(G12V1, Object{70000, CROB{}}), 0x37},
		{"FreeFormat", FreeFormat(G70V3, FileCommand{}), 0x5B},
	}
	for _, c := range cases {
		if c.h.Qualifier != c.want {
			t.Errorf("%s: qualifier %s, want %s", c.name, c.h.Qualifier, c.want)
		}
	}
	for _, c := range []struct {
		n        int
		maxIndex uint32
		want     Qualifier
	}{
		{1, 0, 0x17}, {255, 255, 0x17}, {256, 0, 0x28}, {1, 256, 0x28}, {65535, 65535, 0x28},
		{65536, 65535, 0x29}, {1, 65536, 0x37}, {255, 1 << 31, 0x37}, {256, 65536, 0x38},
		{65535, 70000, 0x38}, {65536, 70000, 0x39},
	} {
		if got := IndexQualifier(c.n, c.maxIndex); got != c.want {
			t.Errorf("IndexQualifier(%d, %d) = %s, want %s", c.n, c.maxIndex, got, c.want)
		}
	}
	for stop, want := range map[uint32]Qualifier{0: 0x00, 255: 0x00, 256: 0x01, 65535: 0x01, 65536: 0x02, 1<<32 - 1: 0x02} {
		if got := RangeQualifier(stop); got != want {
			t.Errorf("RangeQualifier(%d) = %s, want %s", stop, got, want)
		}
	}
	for n, want := range map[int]Qualifier{0: 0x07, 255: 0x07, 256: 0x08, 65535: 0x08, 65536: 0x09} {
		if got := CountQualifier(n); got != want {
			t.Errorf("CountQualifier(%d) = %s, want %s", n, got, want)
		}
	}
}

// TestSpec4_2_2_7_3_3_RangeHasNoGaps: with the range codes 0..2 the
// objects follow each other in index order from the start index to the
// stop index (IEEE 1815-2012 4.2.2.7.3.3, printed p33, "shall"); the
// encoder refuses a gap at every width, and the decoder a stop before the
// start.
func TestSpec4_2_2_7_3_3_RangeHasNoGaps(t *testing.T) {
	for _, c := range []struct {
		q     Qualifier
		start uint32
	}{{0x00, 1}, {0x01, 300}, {0x02, 70000}} {
		h := Header{GV: G30V1, Qualifier: c.q, Objects: []Object{{c.start, Analog{}}, {c.start + 2, Analog{}}}}
		if _, err := (&Fragment{Function: FuncResponse, Headers: []Header{h}}).Encode(); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s gap: err = %v", c.q, err)
		}
	}
	for _, hx := range []string{"1E 01 00 05 04", "1E 01 01 05 00 04 00", "1E 01 02 05 00 00 00 04 00 00 00"} {
		if _, err := Decode(unhex(t, "C0 81 00 00 "+hx)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", hx, err)
		}
	}
}

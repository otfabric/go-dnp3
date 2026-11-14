// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"runtime"
	"testing"
)

// TestResponseIndexListRefused: in a response, values follow the indexes
// of a header, so a header of objects without values cannot be encoded
// there; requests keep their index lists.
func TestResponseIndexListRefused(t *testing.T) {
	for _, fc := range []FunctionCode{FuncResponse, FuncUnsolicitedResponse} {
		f := &Fragment{Function: fc, Headers: []Header{IndexList(G20V1, 1, 2)}}
		if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("%s with an index list: %v", fc, err)
		}
	}
	f := &Fragment{Function: FuncRead, Headers: []Header{IndexList(G20V1, 1, 2)}}
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, byte(FuncRead), 20, 1, 0x17, 2, 1, 2}; string(b) != string(want) {
		t.Fatalf("READ index list = % x, want % x", b, want)
	}
	// Objects with values in a response are unchanged.
	f = &Fragment{Function: FuncResponse, Headers: []Header{Indexed(G20V1, Object{Index: 1, Value: Counter{Value: 5}})}}
	mustEncode(t, f)
}

// TestDecodeValueTimeError: an error reading the time of an object is
// returned in every family that carries one.
func TestDecodeValueTimeError(t *testing.T) {
	for _, d := range []*desc{
		{fam: fBinaryCommandEvent, time: tRel},
		{fam: fCounter, num: nU32, time: tRel},
		{fam: fAnalog, num: nI32, time: tRel},
		{fam: fAnalogCommandEvent, num: nI32, time: tRel},
		{fam: fSecStat, time: tRel},
	} {
		// A relative time without a preceding CTO.
		if _, err := d.decodeValue(G20V1, make([]byte, 16), &codecCtx{}); !errors.Is(err, ErrMalformed) {
			t.Errorf("family %d: %v, want ErrMalformed", d.fam, err)
		}
	}
}

// TestDecodeFileDescriptorsAllocation: a directory listing of minimal
// descriptors decodes with memory proportional to its size.
func TestDecodeFileDescriptorsAllocation(t *testing.T) {
	const count = 1 << 15
	var b []byte
	for range count {
		var err error
		if b, err = AppendFileDescriptor(b, FileDescriptor{}); err != nil {
			t.Fatal(err)
		}
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	ds, err := DecodeFileDescriptors(b)
	runtime.ReadMemStats(&after)
	if err != nil || len(ds) != count {
		t.Fatalf("%d descriptors, %v", len(ds), err)
	}
	if cap(ds) != count {
		t.Fatalf("cap = %d, want %d", cap(ds), count)
	}
	if used := after.TotalAlloc - before.TotalAlloc; used > 3*uint64(len(b)) {
		t.Fatalf("%d octets allocated for a listing of %d", used, len(b))
	}
	// A cut listing returns the whole descriptors before the cut.
	ds, err = DecodeFileDescriptors(b[:3*g70v7NameOffset+5])
	if !errors.Is(err, ErrMalformed) || len(ds) != 3 {
		t.Fatalf("cut listing: %d descriptors, %v", len(ds), err)
	}
}

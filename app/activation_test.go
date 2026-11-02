// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// dscActivateConfigResponse is DSC go-dnp3's answer to ACTIVATE_CONFIG with
// one file specification: g91v1 with qualifier 0x07 (count 1), no delay,
// one status entry of length 1 with status code 0.
const dscActivateConfigResponse = "C0 81 00 00 5B 01 07 01 00 00 00 00 01 01 00"

func TestActivateConfigStatusDecode(t *testing.T) {
	tests := []struct {
		name  string
		frag  string
		qual  Qualifier
		count int
		want  []ActivateConfigStatus
	}{
		{"DSC go-dnp3, count qualifier 0x07", dscActivateConfigResponse, Qual1ByteCount, 1,
			[]ActivateConfigStatus{{Results: []ActivateConfigResult{{Code: 0}}}}},
		{"two-octet count 0x08, two objects",
			"C0 81 00 00 5B 01 08 02 00 E8 03 00 00 00 10 27 00 00 02 03 02 6F 6B 01 05", Qual2ByteCount, 2,
			[]ActivateConfigStatus{
				{Delay: time.Second},
				{Delay: 10 * time.Second, Results: []ActivateConfigResult{{Code: 2, Text: "ok"}, {Code: 5}}},
			}},
		{"range 0x00", "C0 81 00 00 5B 01 00 03 03 00 00 00 00 01 01 04", Qual1ByteStartStop, 1,
			[]ActivateConfigStatus{{Results: []ActivateConfigResult{{Code: 4}}}}},
		{"free format 0x5B (two-octet size)", "C0 81 00 00 5B 01 5B 01 07 00 00 00 00 00 01 01 00", Qual2ByteSizeFreeFormat, 1,
			[]ActivateConfigStatus{{Results: []ActivateConfigResult{{Code: 0}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := unhex(t, tt.frag)
			f, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Headers) != 1 {
				t.Fatalf("%d headers", len(f.Headers))
			}
			h := f.Headers[0]
			if h.GV != G91V1 || h.Qualifier != tt.qual || len(h.Objects) != tt.count {
				t.Fatalf("header %s %s with %d objects", h.GV, h.Qualifier, len(h.Objects))
			}
			for i, o := range h.Objects {
				r, ok := o.Value.(Raw)
				if !ok {
					t.Fatalf("object %d is %T, want Raw", i, o.Value)
				}
				s, err := ParseActivateConfigStatus(r.Data)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(s, tt.want[i]) {
					t.Errorf("object %d = %+v, want %+v", i, s, tt.want[i])
				}
			}
			e, err := f.Encode()
			if err != nil || !bytes.Equal(e, b) {
				t.Fatalf("re-encoded % X (%v), want % X", e, err, b)
			}
		})
	}
}

func TestActivateConfigStatusDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		frag string
		want error
	}{
		{"shorter than delay and count", "C0 81 00 00 5B 01 07 01 00 00 00 00", ErrMalformed},
		{"status of length 0", "C0 81 00 00 5B 01 07 01 00 00 00 00 01 00", ErrMalformed},
		{"status entry missing", "C0 81 00 00 5B 01 07 01 00 00 00 00 02 01 00", ErrMalformed},
		{"status text truncated", "C0 81 00 00 5B 01 07 01 00 00 00 00 01 05 00 61", ErrMalformed},
		{"count beyond the octets", "C0 81 00 00 5B 01 07 03 00 00 00 00 00 00 00 00 00 00", ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(unhex(t, tt.frag)); !errors.Is(err, tt.want) {
				t.Fatalf("Decode: %v, want %v", err, tt.want)
			}
		})
	}
}

// TestActivateConfigFreeFormatLenient keeps the decoding of v1.5: a
// free-format g91v1 object is carried as it is, its size given by the
// qualifier, whatever its content.
func TestActivateConfigFreeFormatLenient(t *testing.T) {
	b := unhex(t, "C0 81 00 00 5B 01 5B 01 03 00 01 02 03")
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	r := f.Headers[0].Objects[0].Value.(Raw)
	if !bytes.Equal(r.Data, []byte{1, 2, 3}) {
		t.Fatalf("data % X", r.Data)
	}
	if _, err := ParseActivateConfigStatus(r.Data); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Parse: %v", err)
	}
	if e, err := f.Encode(); err != nil || !bytes.Equal(e, b) {
		t.Fatalf("re-encoded % X (%v)", e, err)
	}
}

func TestActivateConfigStatusRoundTrip(t *testing.T) {
	for _, s := range []ActivateConfigStatus{
		{},
		{Delay: 1500 * time.Millisecond, Results: []ActivateConfigResult{{Code: 0}, {Code: 1, Text: "bad checksum"}}},
		{Delay: 0xFFFFFFFF * time.Millisecond, Results: []ActivateConfigResult{{Code: 255, Text: strings.Repeat("x", 254)}}},
		{Results: make([]ActivateConfigResult, 255)},
	} {
		r, err := s.Raw()
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []Header{Counted(G91V1, r), FreeFormat(G91V1, r)} {
			d := roundTrip(t, FuncResponse, h)
			got, err := ParseActivateConfigStatus(d.Headers[0].Objects[0].Value.(Raw).Data)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Results) == 0 {
				s.Results = nil
			}
			if !reflect.DeepEqual(got, s) {
				t.Fatalf("%s: %+v, want %+v", h.Qualifier, got, s)
			}
		}
	}
}

func TestActivateConfigStatusErrors(t *testing.T) {
	for _, s := range []ActivateConfigStatus{
		{Delay: -time.Millisecond},
		{Delay: 0x100000000 * time.Millisecond},
		{Results: make([]ActivateConfigResult, 256)},
		{Results: []ActivateConfigResult{{Text: strings.Repeat("x", 255)}}},
	} {
		if _, err := s.Raw(); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Raw of delay %v, %d results: %v", s.Delay, len(s.Results), err)
		}
	}
	for _, data := range [][]byte{
		nil,
		{0, 0, 0, 0},
		{0, 0, 0, 0, 0, 9},          // octets after the entries
		{0, 0, 0, 0, 1, 0},          // length 0
		{0, 0, 0, 0, 1, 3, 0, 'a'},  // text shorter than its length
		{0, 0, 0, 0, 2, 1, 0, 2, 0}, // the second entry truncated
	} {
		if _, err := ParseActivateConfigStatus(data); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse % X: %v", data, err)
		}
	}
	// Without a size, an object must delimit itself.
	for _, h := range []Header{
		Counted(G91V1, Raw{Data: []byte{1, 2, 3}}),
		Counted(G91V1, Raw{Data: []byte{0, 0, 0, 0, 0, 7}}),
		Counted(G91V1, StringAttribute("x")),
	} {
		f := &Fragment{Control: SingleControl(0), Function: FuncResponse, Headers: []Header{h}}
		if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Encode %v: %v", h.Objects[0].Value, err)
		}
	}
	// With a size, any data are sent as they are.
	f := &Fragment{Control: SingleControl(0), Function: FuncResponse,
		Headers: []Header{FreeFormat(G91V1, Raw{Data: []byte{1, 2, 3}})}}
	if _, err := f.Encode(); err != nil {
		t.Errorf("Encode free format: %v", err)
	}
}

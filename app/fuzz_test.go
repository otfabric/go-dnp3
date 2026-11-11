// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// FuzzDecodeFileDescriptors: the content of a directory file (g70v7
// descriptors one after another, IEEE 1815-2012 clause A.27.7) decodes
// without panicking, fails only with ErrMalformed, and what it decodes
// encodes back to the octets it came from. The corpus is in
// testdata/fuzz/FuzzDecodeFileDescriptors.
func FuzzDecodeFileDescriptors(f *testing.F) {
	one, err := AppendFileDescriptor(nil, FileDescriptor{
		Name: "data.csv", Type: FileTypeSimple, Size: 1024, Created: 0x0123456789AB,
		Permissions: 0o644, RequestID: 7,
	})
	if err != nil {
		f.Fatal(err)
	}
	two, err := AppendFileDescriptor(append([]byte(nil), one...), FileDescriptor{Name: "logs", Type: FileTypeDirectory})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(one)
	f.Add(two)
	f.Add(one[:len(one)-1])        // name cut short
	f.Add(one[:g70v7NameOffset-1]) // fixed part cut short
	f.Fuzz(func(t *testing.T, b []byte) {
		ds, err := DecodeFileDescriptors(b)
		var again []byte
		for _, d := range ds {
			var eerr error
			if again, eerr = AppendFileDescriptor(again, d); eerr != nil {
				t.Fatalf("decoded descriptor %+v does not encode: %v", d, eerr)
			}
		}
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error %v is not ErrMalformed", err)
			}
			if !bytes.HasPrefix(b, again) {
				t.Fatalf("descriptors before the error re-encode to %x, not a prefix of %x", again, b)
			}
			return
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("decode then encode changed the content:\n%x\n%x", b, again)
		}
	})
}

// FuzzParseActivateConfigStatus: the data of a g91v1 object (IEEE
// 1815-2012 clause A.37.1) parse without panicking, fail only with
// ErrMalformed, and what parses encodes back to the same octets. The
// corpus is in testdata/fuzz/FuzzParseActivateConfigStatus.
func FuzzParseActivateConfigStatus(f *testing.F) {
	for _, s := range []ActivateConfigStatus{
		{},
		{Delay: 1500 * time.Millisecond, Results: []ActivateConfigResult{{Code: 0}}},
		{Delay: 0xFFFFFFFF * time.Millisecond, Results: []ActivateConfigResult{{Code: 1, Text: "bad file"}, {Code: 0, Text: "ok"}}},
	} {
		raw, err := s.Raw()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw.Data)
	}
	f.Add([]byte{0, 0, 0, 0, 1, 0})       // a status of length 0
	f.Add([]byte{0, 0, 0, 0, 2, 1, 0})    // the second status missing
	f.Add([]byte{0, 0, 0, 0, 0, 0xFF})    // octets after the statuses
	f.Add([]byte{0, 0, 0, 0, 1, 5, 0, 1}) // a text cut short
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseActivateConfigStatus(b)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error %v is not ErrMalformed", err)
			}
			return
		}
		raw, err := s.Raw()
		if err != nil {
			t.Fatalf("parsed status %+v does not encode: %v", s, err)
		}
		if !bytes.Equal(raw.Data, b) {
			t.Fatalf("parse then encode changed the data:\n%x\n%x", b, raw.Data)
		}
	})
}

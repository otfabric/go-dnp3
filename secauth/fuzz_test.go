// SPDX-License-Identifier: MIT

package secauth

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzKeyUnwrap feeds arbitrary wrapped key data, as an outstation
// receives it in a session key change (g120v6), to KeyUnwrap and
// ParseKeyChangeData. Neither may panic; whatever KeyUnwrap accepts must
// wrap back to the same octets, and whatever ParseKeyChangeData accepts
// must be keys of 16..64 octets that KeyChangeData encodes back to a
// prefix of the input.
func FuzzKeyUnwrap(f *testing.F) {
	kek := bytes.Repeat([]byte{0x11}, 16)
	status := []byte{1, 0, 0, 0, 1, 0, 1, 2, 4, 4, 0, 1, 2, 3, 4}
	control, monitoring := bytes.Repeat([]byte{0xC0}, 16), bytes.Repeat([]byte{0x40}, 16)
	plain, err := KeyChangeData(control, monitoring, status)
	if err != nil {
		f.Fatal(err)
	}
	wrapped, err := KeyWrap(kek, plain)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wrapped, plain)
	f.Add(make([]byte, 24), []byte{16, 0})
	f.Add(wrapped[:len(wrapped)-8], []byte{64, 0})
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, wrapped, plain []byte) {
		if keys, err := KeyUnwrap(kek, wrapped); err == nil {
			again, err := KeyWrap(kek, keys)
			if err != nil {
				t.Fatalf("unwrapped %d octets do not wrap: %v", len(keys), err)
			}
			if !bytes.Equal(again, wrapped) {
				t.Fatalf("unwrap then wrap changed the data:\n%x\n%x", wrapped, again)
			}
		} else if !errors.Is(err, ErrKeyWrap) {
			t.Fatalf("unwrap error %v is not ErrKeyWrap", err)
		}

		c, m, err := ParseKeyChangeData(plain, status, nil)
		if err != nil {
			if !errors.Is(err, ErrKeyWrap) {
				t.Fatalf("parse error %v is not ErrKeyWrap", err)
			}
			return
		}
		if len(c) != len(m) || len(c) < 16 || len(c) > 64 {
			t.Fatalf("accepted session keys of %d and %d octets", len(c), len(m))
		}
		for _, ks := range [][]byte{status, nil} {
			enc, err := KeyChangeData(c, m, ks)
			if err != nil {
				t.Fatalf("accepted keys do not encode: %v", err)
			}
			if bytes.HasPrefix(plain, enc[:2+2*len(c)]) {
				return
			}
		}
		t.Fatalf("accepted keys are not those of the input %x", plain)
	})
}

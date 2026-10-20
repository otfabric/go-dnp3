// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"testing"
)

// TestReaderShort: after the first short read every read returns zero and
// done reports the error.
func TestReaderShort(t *testing.T) {
	r := reader{b: []byte{1}}
	if r.u16() != 0 || r.u8() != 0 || r.u32() != 0 || r.u64() != 0 || r.time() != 0 || r.rest() != nil || r.bytes(-1) != nil {
		t.Fatal("reads after a short read")
	}
	if err := r.done(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("done: %v", err)
	}
	// A negative length is short too.
	r = reader{b: []byte{1, 2}}
	if r.bytes(-1) != nil || !errors.Is(r.done(), ErrMalformed) {
		t.Fatal("negative length")
	}
	// Octets left over are an error; none left is not.
	r = reader{b: []byte{1, 2}}
	if r.u8() != 1 || !errors.Is(r.done(), ErrMalformed) {
		t.Fatal("left over")
	}
	if r.u8() != 2 || r.done() != nil {
		t.Fatal("all read")
	}
}

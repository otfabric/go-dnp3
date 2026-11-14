// SPDX-License-Identifier: MIT

package capture

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestLengthsAbove31Bits: 32-bit length and index fields of 2^31 or more
// are a format error on every platform, also where int has 32 bits.
func TestLengthsAbove31Bits(t *testing.T) {
	le := binary.LittleEndian
	u32 := func(b []byte, v ...uint32) []byte {
		for _, x := range v {
			b = le.AppendUint32(b, x)
		}
		return b
	}
	pcapHeader := u32(nil, 0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1)
	shb := u32(nil, 0x0a0d0d0a, 28, 0x1a2b3c4d, 0x00000001, 0xffffffff, 0xffffffff, 28)
	idb := u32(nil, 1, 20, 1, 65535, 20)
	block := func(typ uint32, body ...uint32) []byte {
		n := uint32(12 + 4*len(body))
		b := u32(nil, typ, n)
		b = u32(b, body...)
		return u32(b, n)
	}
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for name, b := range map[string][]byte{
		"pcap record":              cat(pcapHeader, u32(nil, 0, 0, 0x80000000, 0x80000000)),
		"pcapng block length":      cat(shb, u32(nil, 6, 0x80000000, 0)),
		"pcapng interface index":   cat(shb, idb, block(6, 0x80000000, 0, 0, 0, 0)),
		"pcapng captured length":   cat(shb, idb, block(6, 0, 0, 0, 0x80000000, 0)),
		"pcapng simple packet len": cat(shb, idb, block(3, 0xffffffff)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := packets(b); !errors.Is(err, ErrFormat) {
				t.Fatalf("packets = %v, want ErrFormat", err)
			}
		})
	}
	// The limit itself is accepted by the conversion.
	if n, ok := length(0x7fffffff); !ok || n != 0x7fffffff {
		t.Fatalf("length(2^31-1) = %d, %v", n, ok)
	}
}

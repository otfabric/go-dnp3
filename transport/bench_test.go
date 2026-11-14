// SPDX-License-Identifier: MIT

package transport

import (
	"bytes"
	"testing"
)

// benchFragment is the result of the benchmark, kept so that the work is
// not optimised away.
var benchFragment []byte

func BenchmarkSegmentReassemble(b *testing.B) {
	frag := fragment(DefaultMaxFragment)
	var s Segmenter
	r := NewReassembler(0)
	var out []byte
	for _, seg := range s.Segment(frag) {
		var err error
		if out, err = r.Add(seg); err != nil {
			b.Fatal(err)
		}
	}
	if !bytes.Equal(out, frag) {
		b.Fatal("the reassembled fragment differs")
	}
	b.SetBytes(int64(len(frag)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for _, seg := range s.Segment(frag) {
			if out, _ := r.Add(seg); out != nil {
				benchFragment = out
			}
		}
	}
}

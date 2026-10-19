// SPDX-License-Identifier: MIT

package transport

import "testing"

func BenchmarkSegmentReassemble(b *testing.B) {
	frag := fragment(DefaultMaxFragment)
	var s Segmenter
	r := NewReassembler(0)
	b.SetBytes(int64(len(frag)))
	for range b.N {
		for _, seg := range s.Segment(frag) {
			_, _ = r.Add(seg)
		}
	}
}

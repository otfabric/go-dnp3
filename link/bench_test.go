// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"testing"
)

// Results of the benchmarks, kept so that the work is not optimised away.
var (
	benchEncoded []byte
	benchFrame   Frame
)

func BenchmarkEncode(b *testing.B) {
	f := Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0x5A}, MaxUserData)}
	buf := make([]byte, 0, MaxFrameLength)
	if _, err := f.AppendEncode(buf[:0]); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(MaxFrameLength)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchEncoded, _ = f.AppendEncode(buf[:0])
	}
}

func BenchmarkDecode(b *testing.B) {
	f := Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0x5A}, MaxUserData)}
	enc, err := f.Encode()
	if err != nil {
		b.Fatal(err)
	}
	if _, _, err := Decode(enc); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchFrame, _, _ = Decode(enc)
	}
}

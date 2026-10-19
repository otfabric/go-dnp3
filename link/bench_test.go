// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"testing"
)

func BenchmarkEncode(b *testing.B) {
	f := Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0x5A}, MaxUserData)}
	buf := make([]byte, 0, MaxFrameLength)
	b.SetBytes(MaxFrameLength)
	for range b.N {
		_, _ = f.AppendEncode(buf[:0])
	}
}

func BenchmarkDecode(b *testing.B) {
	f := Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0x5A}, MaxUserData)}
	enc, _ := f.Encode()
	b.SetBytes(int64(len(enc)))
	for range b.N {
		_, _, _ = Decode(enc)
	}
}

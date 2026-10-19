// SPDX-License-Identifier: MIT

package app

import "testing"

// integrityResponse is a typical response: 100 binary inputs, 50 analog
// inputs with flags, 20 counters and 10 analog events with time.
func integrityResponse() *Fragment {
	bin := make([]Value, 100)
	for i := range bin {
		bin[i] = Binary{Value: i%2 == 0, Flags: FlagOnline}
	}
	ana := make([]Value, 50)
	for i := range ana {
		ana[i] = Analog{Value: float64(i) * 1.5, Flags: FlagOnline}
	}
	cnt := make([]Value, 20)
	for i := range cnt {
		cnt[i] = Counter{Value: uint32(i * 1000), Flags: FlagOnline}
	}
	ev := make([]Object, 10)
	for i := range ev {
		ev[i] = Object{Index: uint32(i), Value: Analog{Value: 1, Flags: FlagOnline, Time: 1_700_000_000_000}}
	}
	return &Fragment{Control: SingleControl(1), Function: FuncResponse, Headers: []Header{
		Ranged(G1V2, 0, bin...), Ranged(G30V5, 0, ana...), Ranged(G20V1, 0, cnt...), Indexed(G32V7, ev...),
	}}
}

func BenchmarkEncodeResponse(b *testing.B) {
	f := integrityResponse()
	buf := make([]byte, 0, 2048)
	for range b.N {
		_, _ = f.AppendEncode(buf[:0])
	}
}

func BenchmarkDecodeResponse(b *testing.B) {
	enc, _ := integrityResponse().Encode()
	b.SetBytes(int64(len(enc)))
	for range b.N {
		_, _ = Decode(enc)
	}
}

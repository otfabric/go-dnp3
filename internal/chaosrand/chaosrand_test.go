// SPDX-License-Identifier: MIT

package chaosrand

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"
)

// TestKnownAnswer: the first draws are the first block, SHA-256 of the
// key and counter 0, and the fifth draw is the first of block 1.
func TestKnownAnswer(t *testing.T) {
	key := sha256.Sum256([]byte("1815"))
	block := func(i uint64) [sha256.Size]byte {
		in := append(key[:len(key):len(key)], make([]byte, 8)...)
		binary.LittleEndian.PutUint64(in[len(key):], i)
		return sha256.Sum256(in)
	}
	r := New(1815)
	for i := range uint64(3) {
		b := block(i)
		for j := 0; j < len(b); j += 8 {
			if got, want := r.Uint64(), binary.LittleEndian.Uint64(b[j:]); got != want {
				t.Fatalf("block %d word %d: %#x, want %#x", i, j/8, got, want)
			}
		}
	}
}

// TestReplay: one seed, one sequence; another seed, another one.
func TestReplay(t *testing.T) {
	a, b, c := New(-7), New(-7), New(7)
	same := true
	for range 100 {
		x := a.Uint64()
		if y := b.Uint64(); x != y {
			t.Fatalf("seed -7 drew %#x and %#x", x, y)
		}
		same = same && x == c.Uint64()
	}
	if same {
		t.Fatal("seeds -7 and 7 drew the same sequence")
	}
}

func TestRanges(t *testing.T) {
	r := New(0)
	var lo, hi bool
	for range 10_000 {
		f := r.Float64()
		if f < 0 || f >= 1 {
			t.Fatalf("Float64 %v outside [0, 1)", f)
		}
		lo, hi = lo || f < 0.1, hi || f > 0.9
		if n := r.IntN(8); n < 0 || n >= 8 {
			t.Fatalf("IntN(8) = %d", n)
		}
		if n := r.IntN(1); n != 0 {
			t.Fatalf("IntN(1) = %d", n)
		}
		_ = r.Uint32()
	}
	if !lo || !hi {
		t.Fatalf("Float64 does not spread over [0, 1): below 0.1 %v, above 0.9 %v", lo, hi)
	}
}

// TestIntNUniform: every value of a small bound comes up about as often.
func TestIntNUniform(t *testing.T) {
	r := New(42)
	var counts [8]int
	const draws = 80_000
	for range draws {
		counts[r.IntN(len(counts))]++
	}
	for v, c := range counts {
		if c < draws/len(counts)*9/10 || c > draws/len(counts)*11/10 {
			t.Errorf("IntN(8) drew %d %d times of %d", v, c, draws)
		}
	}
}

// TestIntNRejects: with a bound just above 2^62 about half the draws are
// rejected, and every result is still below the bound.
func TestIntNRejects(t *testing.T) {
	r := New(3)
	n := math.MaxInt/2 + 2
	for range 1000 {
		if v := r.IntN(n); v < 0 || v >= n {
			t.Fatalf("IntN(%d) = %d", n, v)
		}
	}
}

func TestIntNPanics(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("IntN(%d) did not panic", n)
				}
			}()
			New(1).IntN(n)
		}()
	}
}

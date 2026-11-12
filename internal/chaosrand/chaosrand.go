// SPDX-License-Identifier: MIT

// Package chaosrand is the deterministic generator of the chaos tests: the
// same seed gives the same draws on every platform and Go release, so that
// a run's faults replay from its logged DNP3_CHAOS_SEED. It is SHA-256 in
// counter mode over the seed: block i is SHA-256(key || i), the key being
// SHA-256 of the seed's decimal text. It is test infrastructure, not a
// source of secrets: anyone who knows the seed knows every draw. No
// package of the library imports it outside its tests.
package chaosrand

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
)

// Rand is a generator. It is not safe for concurrent use.
type Rand struct {
	key   [sha256.Size]byte
	ctr   uint64
	block [sha256.Size]byte
	off   int // the octets of block used; len(block) when it is spent
}

// New returns the generator of seed.
func New(seed int64) *Rand {
	r := &Rand{key: sha256.Sum256([]byte(strconv.FormatInt(seed, 10)))}
	r.off = len(r.block)
	return r
}

// Uint64 returns the next 64 bits.
func (r *Rand) Uint64() uint64 {
	if r.off+8 > len(r.block) {
		var in [sha256.Size + 8]byte
		copy(in[:], r.key[:])
		binary.LittleEndian.PutUint64(in[sha256.Size:], r.ctr)
		r.ctr++
		r.block = sha256.Sum256(in[:])
		r.off = 0
	}
	v := binary.LittleEndian.Uint64(r.block[r.off:])
	r.off += 8
	return v
}

// Uint32 returns the next 32 bits.
func (r *Rand) Uint32() uint32 {
	return uint32(r.Uint64() >> 32)
}

// Float64 returns a uniform draw from [0, 1), with 53 bits.
func (r *Rand) Float64() float64 {
	return float64(r.Uint64()>>11) / (1 << 53)
}

// IntN returns a uniform draw from [0, n). It panics when n <= 0.
func (r *Rand) IntN(n int) int {
	if n <= 0 {
		panic("chaosrand: IntN of a non-positive bound")
	}
	// Rejection sampling over [0, 2^63): the draws at or above the largest
	// multiple of n are drawn again, so that every result is as likely.
	limit := int64(n)
	top := (1<<63 - 1) - (1<<63-1)%limit
	for {
		v := int64(r.Uint64() >> 1)
		if v < top {
			return int(v % limit)
		}
	}
}

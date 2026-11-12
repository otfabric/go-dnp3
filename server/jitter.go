// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

// validJitter reports whether f is a jitter fraction Redial
// accepts: from 0 to 1.
func validJitter(f float64) bool {
	return f >= 0 && f <= 1 && !math.IsNaN(f)
}

// jittered returns the pause d with the jitter fraction f applied: drawn
// uniformly from [(1-f)·d, d]. With f zero it is d. The draw only spreads
// the attempts of several outstations apart; it comes from crypto/rand all the
// same, so that the pauses of a device cannot be predicted.
func jittered(d time.Duration, f float64) time.Duration {
	if f <= 0 || d <= 0 {
		return d
	}
	return d - time.Duration(f*unitFloat()*float64(d))
}

// unitFloat is a uniform draw from [0, 1) with 53 random bits, from
// crypto/rand. crypto/rand.Read does not fail (Go 1.24 and later).
func unitFloat() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}

// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"math/rand/v2"
	"time"
)

// validJitter reports whether f is a jitter fraction Redial
// accepts: from 0 to 1.
func validJitter(f float64) bool {
	return f >= 0 && f <= 1 && !math.IsNaN(f)
}

// jittered returns the pause d with the jitter fraction f applied: drawn
// uniformly from [(1-f)·d, d]. With f zero it is d. The draw needs no
// cryptographic randomness: it only spreads the attempts of several
// outstations apart.
func jittered(d time.Duration, f float64) time.Duration {
	if f <= 0 || d <= 0 {
		return d
	}
	return d - time.Duration(f*rand.Float64()*float64(d))
}

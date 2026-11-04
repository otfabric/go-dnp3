// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"math"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Range-checked conversions of the numbers the runner sends: they arrive
// as JSON numbers and are checked before they reach the outstation.

// pointIndex returns a point index of a request, which is 0..2^32-1.
func pointIndex(i int) (uint32, error) {
	if i < 0 || uint64(i) > math.MaxUint32 {
		return 0, fmt.Errorf("point index %d out of range", i)
	}
	return uint32(min(uint64(i), math.MaxUint32)), nil
}

// linkAddress returns a link address of a request, which is 0..65535.
func linkAddress(n int) (link.Address, error) {
	if n < 0 || n > 0xFFFF {
		return 0, fmt.Errorf("link address %d out of range", n)
	}
	return link.Address(n), nil
}

// millis returns a DNP3 time in milliseconds as a signed number for
// differences; the 48 bits of a DNP3 time always fit.
func millis(t app.Timestamp) int64 { return int64(min(t, app.MaxTimestamp)) }

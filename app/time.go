// SPDX-License-Identifier: MIT

package app

import "time"

// Timestamp is DNP3 absolute time: milliseconds since 1970-01-01 00:00 UTC,
// 48 bits on the wire (IEEE 1815-2012 clause 11.9.6.1).
//
// It is carried as the integer the standard defines rather than as a
// time.Time so that values round-trip exactly; [Timestamp.Time] and
// [TimestampOf] convert.
type Timestamp uint64

// MaxTimestamp is the largest value 48 bits hold.
const MaxTimestamp Timestamp = 1<<48 - 1

// TimestampOf returns the timestamp of t, truncated to milliseconds and
// clamped to 0..[MaxTimestamp].
func TimestampOf(t time.Time) Timestamp {
	ms := t.UnixMilli()
	switch {
	case ms < 0:
		return 0
	case ms > int64(MaxTimestamp):
		return MaxTimestamp
	default:
		return Timestamp(ms)
	}
}

// Now returns the current time as a Timestamp.
func Now() Timestamp { return TimestampOf(time.Now()) }

// Time returns the timestamp as a time.Time in UTC.
func (t Timestamp) Time() time.Time { return time.UnixMilli(int64(t & MaxTimestamp)).UTC() }

// String formats the timestamp in RFC 3339 with milliseconds.
func (t Timestamp) String() string { return t.Time().Format("2006-01-02T15:04:05.000Z07:00") }

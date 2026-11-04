// SPDX-License-Identifier: MIT

package app

import (
	"encoding/binary"
	"math"
)

// reader decodes little-endian fields with a sticky error: after the first
// short read every further read returns zero and done reports it.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = truncated("object: %d octets left, %d needed", len(r.b), n)
		return nil
	}
	p := r.b[:n]
	r.b = r.b[n:]
	return p
}

func (r *reader) u8() uint8 {
	if p := r.take(1); p != nil {
		return p[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if p := r.take(2); p != nil {
		return binary.LittleEndian.Uint16(p)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if p := r.take(4); p != nil {
		return binary.LittleEndian.Uint32(p)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if p := r.take(8); p != nil {
		return binary.LittleEndian.Uint64(p)
	}
	return 0
}

func (r *reader) time() Timestamp {
	if p := r.take(6); p != nil {
		return Timestamp(uint64(binary.LittleEndian.Uint32(p)) | uint64(binary.LittleEndian.Uint16(p[4:]))<<32)
	}
	return 0
}

func (r *reader) bytes(n int) []byte { return r.take(n) }

func (r *reader) rest() []byte {
	if r.err != nil {
		return nil
	}
	p := r.b
	r.b = nil
	return p
}

// done returns the read error, or an error when octets are left over.
func (r *reader) done() error {
	if r.err == nil && len(r.b) > 0 {
		return malformed("%d unexpected octets after the object", len(r.b))
	}
	return r.err
}

func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func le64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }

func le48(b []byte, t Timestamp) []byte {
	t &= MaxTimestamp
	return append(b, byte(t&0xFF), byte(t>>8&0xFF), byte(t>>16&0xFF), byte(t>>24&0xFF), byte(t>>32&0xFF), byte(t>>40&0xFF))
}

// len16 returns the length n as a two-octet field. Every caller checks n
// against 0xFFFF first and fails the encoding when it does not fit; the
// clamp only makes that bound visible here.
func len16(n int) uint16 { return uint16(max(min(n, 0xFFFF), 0)) }

// len32 returns the count n as a four-octet field, clamped like len16. A
// slice of more than 2^32-1 elements cannot be encoded in a fragment, so
// the encoders fail on the fragment size before such a count is used.
func len32(n int) uint32 { return uint32(min(uint64(max(n, 0)), math.MaxUint32)) }

// ulen returns a length or offset difference, never negative, as uint64
// for overflow-free bound checks.
func ulen(n int) uint64 { return uint64(max(n, 0)) }

func f32(b []byte, v float32) []byte { return le32(b, math.Float32bits(v)) }
func f64(b []byte, v float64) []byte { return le64(b, math.Float64bits(v)) }

// clone returns a copy of b that does not alias the fragment, or nil for
// an empty b.
func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// Two's complement reinterpretations between the signed values of the
// object library and their unsigned wire octets. They are written as
// arithmetic so that the reinterpretation is explicit, not an accident of
// a conversion.

// int8of returns octet b read as a signed 8-bit integer.
func int8of(b byte) int32 { return int32(b) - int32(b&0x80)<<1 }

// int16of returns v read as a signed 16-bit integer.
func int16of(v uint16) int32 { return int32(v) - int32(v&0x8000)<<1 }

// int32of returns v read as a signed 32-bit integer.
func int32of(v uint32) int32 {
	return int32(max(min(int64(v)-int64(v&0x80000000)<<1, math.MaxInt32), math.MinInt32))
}

// uint16of returns the two's complement octets of v.
func uint16of(v int16) uint16 { return uint16(int32(v) & 0xFFFF) }

// uint32of returns the two's complement octets of v.
func uint32of(v int32) uint32 { return uint32(int64(v) & 0xFFFFFFFF) }

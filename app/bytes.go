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
	return append(b, byte(t), byte(t>>8), byte(t>>16), byte(t>>24), byte(t>>32), byte(t>>40))
}

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

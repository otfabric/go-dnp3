// SPDX-License-Identifier: MIT

package app

import "fmt"

// Qualifier is the qualifier octet of an object header (IEEE 1815-2012
// clause 4.2.2.7.3): the object prefix code in bits 4..6 and the range
// specifier code in bits 0..3.
type Qualifier uint8

// The qualifiers in use. The name gives the prefix and the range: for
// example [Qual2ByteIndexCount] is "prefix: 2-octet index, range: 2-octet
// count" (0x28).
const (
	// Range of indexes, objects in index order.
	Qual1ByteStartStop Qualifier = 0x00
	Qual2ByteStartStop Qualifier = 0x01
	Qual4ByteStartStop Qualifier = 0x02

	// Range of virtual addresses (device attributes and similar).
	Qual1ByteVirtualStartStop Qualifier = 0x03
	Qual2ByteVirtualStartStop Qualifier = 0x04
	Qual4ByteVirtualStartStop Qualifier = 0x05

	// All objects of the group and variation; no range field.
	QualAll Qualifier = 0x06

	// A count of objects, without index.
	Qual1ByteCount Qualifier = 0x07
	Qual2ByteCount Qualifier = 0x08
	Qual4ByteCount Qualifier = 0x09

	// A count of objects, each preceded by its index.
	Qual1ByteIndexCount Qualifier = 0x17
	Qual2ByteIndexCount Qualifier = 0x28
	Qual4ByteIndexCount Qualifier = 0x39

	// A one-octet count of free-format objects, each preceded by its size.
	Qual1ByteSizeFreeFormat Qualifier = 0x4B
	Qual2ByteSizeFreeFormat Qualifier = 0x5B
	Qual4ByteSizeFreeFormat Qualifier = 0x6B
)

// Prefix returns the object prefix code, 0..7.
func (q Qualifier) Prefix() uint8 { return uint8(q>>4) & 0x07 }

// Range returns the range specifier code, 0..15.
func (q Qualifier) Range() uint8 { return uint8(q) & 0x0F }

// Valid reports whether q is a combination this package encodes and
// decodes. The reserved bit 7 must be clear.
func (q Qualifier) Valid() bool {
	if q&0x80 != 0 {
		return false
	}
	switch r, p := q.Range(), q.Prefix(); {
	case r <= 5:
		return p == 0
	case r == 6:
		return p == 0
	case r <= 9:
		return p <= 3
	case r == 0x0B:
		return p >= 4 && p <= 6
	default:
		return false
	}
}

// IsRange reports whether q carries a start and a stop index.
func (q Qualifier) IsRange() bool { return q.Range() <= 5 }

// IsCount reports whether q carries an object count.
func (q Qualifier) IsCount() bool { r := q.Range(); return r >= 7 && r <= 9 || r == 0x0B }

// IsFreeFormat reports whether q is a free-format qualifier: each object
// carries its own size.
func (q Qualifier) IsFreeFormat() bool { return q.Range() == 0x0B }

// IsIndexed reports whether each object is preceded by its index.
func (q Qualifier) IsIndexed() bool { p := q.Prefix(); return p >= 1 && p <= 3 }

// rangeWidth returns the octets of each start/stop value or of the count.
func (q Qualifier) rangeWidth() int {
	switch q.Range() {
	case 0, 3, 7, 0x0B:
		return 1
	case 1, 4, 8:
		return 2
	case 2, 5, 9:
		return 4
	default:
		return 0
	}
}

// prefixWidth returns the octets of each object's index or size prefix.
func (q Qualifier) prefixWidth() int {
	switch q.Prefix() {
	case 1, 4:
		return 1
	case 2, 5:
		return 2
	case 3, 6:
		return 4
	default:
		return 0
	}
}

// String returns the hexadecimal value, for example "0x28".
func (q Qualifier) String() string { return fmt.Sprintf("0x%02X", uint8(q)) }

// RangeQualifier returns the smallest start-stop qualifier that holds
// stop.
func RangeQualifier(stop uint32) Qualifier {
	switch {
	case stop <= 0xFF:
		return Qual1ByteStartStop
	case stop <= 0xFFFF:
		return Qual2ByteStartStop
	default:
		return Qual4ByteStartStop
	}
}

// CountQualifier returns the smallest count qualifier that holds n.
func CountQualifier(n int) Qualifier {
	switch {
	case n <= 0xFF:
		return Qual1ByteCount
	case n <= 0xFFFF:
		return Qual2ByteCount
	default:
		return Qual4ByteCount
	}
}

// IndexQualifier returns the smallest index-prefixed count qualifier that
// holds n objects with indexes up to maxIndex.
func IndexQualifier(n int, maxIndex uint32) Qualifier {
	m := max(uint32(n), maxIndex)
	switch {
	case m <= 0xFF:
		return Qual1ByteIndexCount
	case m <= 0xFFFF:
		return Qual2ByteIndexCount
	default:
		return Qual4ByteIndexCount
	}
}

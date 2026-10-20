// SPDX-License-Identifier: MIT

package app

import "slices"

// Constructors for the headers requests and responses are made of. Each
// picks the smallest qualifier that holds its indexes or count.

// AllObjects returns a header for all objects of gv (qualifier 0x06), for
// example the class 0 header of an integrity poll.
func AllObjects(gv GroupVariation) Header { return Header{GV: gv, Qualifier: QualAll} }

// ClassHeaders returns the headers that read the given classes (0..3), in
// the order given: ClassHeaders(1, 2, 3, 0) is an integrity poll.
func ClassHeaders(classes ...int) []Header {
	hs := make([]Header, 0, len(classes))
	for _, c := range classes {
		if c >= 0 && c <= 3 {
			hs = append(hs, AllObjects(GV(60, uint8(c+1))))
		}
	}
	return hs
}

// IndexRange returns a header naming the points start..stop of gv
// without values, as in a READ of a range.
func IndexRange(gv GroupVariation, start, stop uint32) Header {
	return Header{GV: gv, Qualifier: RangeQualifier(stop), Start: start, Stop: stop}
}

// IndexList returns a header naming the given indexes of gv without
// values (qualifier 0x17, 0x28 or 0x39), as in a READ of specific points.
func IndexList(gv GroupVariation, indexes ...uint32) Header {
	objs := make([]Object, len(indexes))
	var m uint32
	for i, x := range indexes {
		objs[i].Index = x
		m = max(m, x)
	}
	return Header{GV: gv, Qualifier: IndexQualifier(len(objs), m), Count: uint32(len(objs)), Objects: objs}
}

// CountOf returns a header naming up to n objects of gv without values,
// as in a READ of at most n events.
func CountOf(gv GroupVariation, n uint32) Header {
	return Header{GV: gv, Qualifier: CountQualifier(int(n)), Count: n}
}

// Ranged returns a header carrying values for the contiguous indexes
// start, start+1, ... (a start-stop qualifier).
func Ranged(gv GroupVariation, start uint32, values ...Value) Header {
	objs := make([]Object, len(values))
	for i, v := range values {
		objs[i] = Object{Index: start + uint32(i), Value: v}
	}
	stop := start
	if len(values) > 0 {
		stop = start + uint32(len(values)-1)
	}
	return Header{GV: gv, Qualifier: RangeQualifier(stop), Start: start, Stop: stop, Objects: objs}
}

// Indexed returns a header carrying objects each preceded by its index
// (qualifier 0x17, 0x28 or 0x39), as used for commands and events.
func Indexed(gv GroupVariation, objs ...Object) Header {
	var maxIndex uint32
	for _, o := range objs {
		maxIndex = max(maxIndex, o.Index)
	}
	return Header{GV: gv, Qualifier: IndexQualifier(len(objs), maxIndex), Count: uint32(len(objs)), Objects: slices.Clone(objs)}
}

// Counted returns a header carrying objects without index (qualifier
// 0x07..0x09), as used for time objects: Counted(G50V1, AbsoluteTime{...}).
func Counted(gv GroupVariation, values ...Value) Header {
	objs := make([]Object, len(values))
	for i, v := range values {
		objs[i] = Object{Index: uint32(i), Value: v}
	}
	return Header{GV: gv, Qualifier: CountQualifier(len(values)), Count: uint32(len(values)), Objects: objs}
}

// FreeFormat returns a header carrying free-format objects, each preceded
// by a two-octet size (qualifier 0x5B), as used for file and
// authentication objects.
func FreeFormat(gv GroupVariation, values ...Value) Header {
	objs := make([]Object, len(values))
	for i, v := range values {
		objs[i] = Object{Index: uint32(i), Value: v}
	}
	return Header{GV: gv, Qualifier: Qual2ByteSizeFreeFormat, Count: uint32(len(values)), Objects: objs}
}

// OctetStringGV returns the variation of group g (110..113) for a string
// of n octets.
func OctetStringGV(g uint8, n int) GroupVariation { return GV(g, uint8(n)) }

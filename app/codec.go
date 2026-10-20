// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnknownFunction reports a fragment whose function code IEEE 1815-2012
// does not define. [Decode] returns the header of such a fragment with it,
// so that an outstation can answer with IIN2.0 (NO_FUNC_CODE_SUPPORT).
var ErrUnknownFunction = errors.New("app: unknown function code")

// Object is one object of a header with its index: the index prefix of an
// index-prefixed qualifier, the position in the range of a start-stop
// qualifier, or the position in the header for count and free-format
// qualifiers.
type Object struct {
	Index uint32
	Value Value
}

// Header is one object header and the objects that follow it.
type Header struct {
	GV        GroupVariation
	Qualifier Qualifier

	// Start and Stop are the range of a start-stop qualifier. When the
	// header has objects, the encoder takes the range from their indexes.
	Start, Stop uint32

	// Count is the count of a count, index-prefixed or free-format
	// qualifier for a header without objects, for example a READ of at
	// most Count events. With objects the encoder uses len(Objects).
	Count uint32

	// Objects is nil for a header that names points without values: the
	// headers of READ, freeze, assign class and unsolicited control
	// requests. When such a header names points by an index list
	// (qualifiers 0x17, 0x28, 0x39), Objects holds the indexes with a nil
	// Value.
	Objects []Object
}

// String returns a one-line description, for example "g30v1 q=0x00 [0..9] n=10".
func (h *Header) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s q=%s", h.GV, h.Qualifier)
	switch {
	case h.Qualifier.IsRange() && len(h.Objects) > 0:
		fmt.Fprintf(&sb, " [%d..%d]", h.Objects[0].Index, h.Objects[len(h.Objects)-1].Index)
	case h.Qualifier.IsRange():
		fmt.Fprintf(&sb, " [%d..%d]", h.Start, h.Stop)
	case h.Qualifier == QualAll:
		sb.WriteString(" all")
	case len(h.Objects) == 0:
		fmt.Fprintf(&sb, " count=%d", h.Count)
	}
	if len(h.Objects) > 0 {
		fmt.Fprintf(&sb, " n=%d", len(h.Objects))
	}
	return sb.String()
}

// Fragment is one application layer fragment: the request or response
// header and the object headers.
type Fragment struct {
	Control  Control
	Function FunctionCode
	// IIN are the internal indications; only responses carry them.
	IIN     IIN
	Headers []Header
}

// String returns a one-line description, for example
// "RESPONSE FIR FIN seq=3 iin=DEVICE_RESTART headers=2".
func (f *Fragment) String() string {
	s := fmt.Sprintf("%s %s", f.Function, f.Control)
	if f.Function.IsResponse() && f.IIN != 0 {
		s += " iin=" + f.IIN.String()
	}
	return fmt.Sprintf("%s headers=%d", s, len(f.Headers))
}

// HeaderLen returns the size of the fragment header: 2 for a request, 4
// for a response.
func (f *Fragment) HeaderLen() int {
	if f.Function.IsResponse() {
		return 4
	}
	return 2
}

// Encode returns the wire encoding of f.
func (f *Fragment) Encode() ([]byte, error) { return f.AppendEncode(nil) }

// AppendEncode appends the wire encoding of f to b.
func (f *Fragment) AppendEncode(b []byte) ([]byte, error) {
	b = append(b, f.Control.Byte(), byte(f.Function))
	if f.Function.IsResponse() {
		b = append(b, f.IIN.IIN1(), f.IIN.IIN2())
	}
	var c codecCtx
	for i := range f.Headers {
		var err error
		if b, err = f.Headers[i].appendEncode(b, &c); err != nil {
			return b, fmt.Errorf("header %d (%s): %w", i, f.Headers[i].GV, err)
		}
	}
	return b, nil
}

// EncodedLen returns the size of the encoding of h on its own, or an error
// when it cannot be encoded. A server uses it to decide whether a header
// still fits a fragment.
func (h *Header) EncodedLen() (int, error) {
	c := codecCtx{sizeOnly: true} // relative times are checked when the fragment is encoded
	b, err := h.appendEncode(nil, &c)
	return len(b), err
}

// Decode decodes one fragment. The objects are copies: nothing in the
// result aliases b.
//
// On error the returned fragment is still non-nil when b held the
// fragment header, with the headers decoded before the failure, so that an
// outstation can answer with the sequence number and function of the
// request. Errors wrap [ErrMalformed], [ErrUnknownObject],
// [ErrInvalidQualifier] or [ErrUnknownFunction].
func Decode(b []byte) (*Fragment, error) {
	if len(b) < 2 {
		return nil, truncated("fragment header: %d octets", len(b))
	}
	f := &Fragment{Control: ParseControl(b[0]), Function: FunctionCode(b[1])}
	b = b[2:]
	if f.Function.IsResponse() {
		if len(b) < 2 {
			return nil, truncated("response header: no IIN")
		}
		f.IIN = IIN(b[0]) | IIN(b[1])<<8
		b = b[2:]
	}
	if !f.Function.Defined() {
		return f, fmt.Errorf("%w: %d", ErrUnknownFunction, uint8(f.Function))
	}
	var c codecCtx
	for i := 0; len(b) > 0; i++ {
		h, n, err := decodeHeader(b, f.Function, &c)
		if err != nil {
			return f, fmt.Errorf("header %d: %w", i, err)
		}
		f.Headers = append(f.Headers, h)
		b = b[n:]
	}
	return f, nil
}

// objectsFollow reports whether objects follow a header with this
// qualifier in a fragment with function fc.
func objectsFollow(fc FunctionCode, gv GroupVariation, q Qualifier) bool {
	switch {
	case q == QualAll:
		return false
	case fc.IsResponse(), q.IsFreeFormat(), gv.Group() == 120:
		return true
	case gv.Group() == 50 && (fc == FuncFreezeAtTime || fc == FuncFreezeAtTimeNoAck):
		return true
	default:
		return fc.carriesObjects()
	}
}

func decodeHeader(b []byte, fc FunctionCode, c *codecCtx) (Header, int, error) {
	if len(b) < 3 {
		return Header{}, 0, truncated("object header: %d octets", len(b))
	}
	h := Header{GV: GV(b[0], b[1]), Qualifier: Qualifier(b[2])}
	q := h.Qualifier
	if !q.Valid() {
		return h, 0, fmt.Errorf("%w: %s for %s", ErrInvalidQualifier, q, h.GV)
	}
	p := 3
	w := q.rangeWidth()
	switch {
	case q.IsRange():
		if len(b) < p+2*w {
			return h, 0, truncated("range of %s", h.GV)
		}
		h.Start, h.Stop = getUint(b[p:], w), getUint(b[p+w:], w)
		p += 2 * w
		if h.Start > h.Stop {
			return h, 0, malformed("%s range %d..%d", h.GV, h.Start, h.Stop)
		}
	case q.IsCount():
		if len(b) < p+w {
			return h, 0, truncated("count of %s", h.GV)
		}
		h.Count = getUint(b[p:], w)
		p += w
	}

	d := lookup(h.GV)
	if !objectsFollow(fc, h.GV, q) || (d != nil && (d.fam == fNone || d.fam == fAny)) {
		if q.IsIndexed() && h.Count > 0 {
			// An index list without values.
			pw := q.prefixWidth()
			if uint64(h.Count)*uint64(pw) > uint64(len(b)-p) {
				return h, 0, truncated("index list of %s: %d indexes", h.GV, h.Count)
			}
			h.Objects = make([]Object, h.Count)
			for i := range h.Objects {
				h.Objects[i].Index = getUint(b[p:], pw)
				p += pw
			}
		}
		return h, p, nil
	}
	if d == nil {
		return h, 0, fmt.Errorf("%w: %s", ErrUnknownObject, h.GV)
	}
	n, err := d.decodeObjects(&h, b[p:], c)
	return h, p + n, err
}

// decodeObjects decodes the objects of h from b and returns the octets
// consumed. Every count is checked against the octets left before
// anything is allocated for it.
func (d *desc) decodeObjects(h *Header, b []byte, c *codecCtx) (int, error) {
	q, gv := h.Qualifier, h.GV
	size := d.size(gv)
	if bits := d.bits(); bits > 0 {
		if !q.IsRange() {
			return 0, fmt.Errorf("%w: %s for packed %s", ErrInvalidQualifier, q, gv)
		}
		n := uint64(h.Stop-h.Start) + 1
		nb := (n*uint64(bits) + 7) / 8
		if uint64(len(b)) < nb {
			return 0, truncated("%s: %d objects need %d octets, %d left", gv, n, nb, len(b))
		}
		h.Objects = make([]Object, n)
		for i := range h.Objects {
			bit := uint64(i) * uint64(bits)
			x := b[bit/8] >> (bit % 8)
			o := &h.Objects[i]
			o.Index = h.Start + uint32(i)
			if bits == 1 {
				o.Value = Binary{Value: x&1 != 0}
			} else {
				o.Value = DoubleBitBinary{Value: DoubleBit(x & 3)}
			}
		}
		return int(nb), nil
	}

	if d.freeFormat(gv) && !q.IsFreeFormat() {
		return 0, fmt.Errorf("%w: %s for free-format %s", ErrInvalidQualifier, q, gv)
	}

	var n uint64
	switch {
	case q.IsRange():
		n = uint64(h.Stop-h.Start) + 1
	default:
		n = uint64(h.Count)
	}
	// The least each object occupies, to bound n before allocating.
	least := uint64(max(size, 1)) + uint64(q.prefixWidth())
	if d.selfSized() {
		least = 2 + uint64(q.prefixWidth())
	}
	if n*least > uint64(len(b)) {
		return 0, truncated("%s: %d objects in %d octets", gv, n, len(b))
	}
	if !d.selfSized() && size == 0 && !q.IsFreeFormat() {
		return 0, fmt.Errorf("%w: %s for %s", ErrInvalidQualifier, q, gv)
	}

	h.Objects = make([]Object, 0, n)
	p := 0
	pw := q.prefixWidth()
	for i := uint64(0); i < n; i++ {
		var idx uint32
		var objLen int
		switch {
		case q.IsRange():
			idx = h.Start + uint32(i)
		case q.IsIndexed():
			if len(b)-p < pw {
				return p, truncated("%s: index prefix", gv)
			}
			idx = getUint(b[p:], pw)
			p += pw
		case q.IsFreeFormat():
			idx = uint32(i)
			if len(b)-p < pw {
				return p, truncated("%s: size prefix", gv)
			}
			l := getUint(b[p:], pw)
			p += pw
			if uint64(l) > uint64(len(b)-p) {
				return p, truncated("%s: object of %d octets, %d left", gv, l, len(b)-p)
			}
			objLen = int(l)
			if size > 0 && objLen != size {
				return p, malformed("%s: object size %d, want %d", gv, objLen, size)
			}
		default:
			idx = uint32(i)
		}

		var v Value
		var err error
		switch {
		case d.selfSized() && !q.IsFreeFormat():
			var a Attribute
			a, objLen, err = decodeAttribute(b[p:])
			v = a
		default:
			if !q.IsFreeFormat() {
				objLen = size
			}
			if len(b)-p < objLen {
				return p, truncated("%s: object %d", gv, i)
			}
			if d.selfSized() {
				var a Attribute
				var m int
				a, m, err = decodeAttribute(b[p : p+objLen])
				if err == nil && m != objLen {
					err = malformed("%s: attribute of %d octets in object of %d", gv, m, objLen)
				}
				v = a
			} else {
				v, err = d.decodeValue(gv, b[p:p+objLen], c)
			}
		}
		if err != nil {
			return p, fmt.Errorf("%s object %d: %w", gv, i, err)
		}
		p += objLen
		h.Objects = append(h.Objects, Object{Index: idx, Value: v})
	}
	return p, nil
}

func (h *Header) appendEncode(b []byte, c *codecCtx) ([]byte, error) {
	q := h.Qualifier
	if !q.Valid() {
		return b, fmt.Errorf("%w: %s", ErrInvalidQualifier, q)
	}
	d := lookup(h.GV)
	b = append(b, h.GV.Group(), h.GV.Variation(), byte(q))
	w := q.rangeWidth()
	limit := uint64(1)<<(8*w) - 1

	if len(h.Objects) == 0 {
		switch {
		case q.IsRange():
			if h.Start > h.Stop || uint64(h.Stop) > limit {
				return b, invalid("range %d..%d with qualifier %s", h.Start, h.Stop, q)
			}
			b = putUint(putUint(b, h.Start, w), h.Stop, w)
		case q.IsCount():
			if uint64(h.Count) > limit {
				return b, invalid("count %d with qualifier %s", h.Count, q)
			}
			b = putUint(b, h.Count, w)
		}
		return b, nil
	}

	if indexOnly(h.Objects) {
		if !q.IsIndexed() {
			return b, invalid("objects without values need an index-prefixed qualifier, not %s", q)
		}
		if uint64(len(h.Objects)) > limit {
			return b, invalid("%d indexes with qualifier %s", len(h.Objects), q)
		}
		b = putUint(b, uint32(len(h.Objects)), w)
		pw := q.prefixWidth()
		plimit := uint64(1)<<(8*pw) - 1
		for _, o := range h.Objects {
			if uint64(o.Index) > plimit {
				return b, invalid("index %d with qualifier %s", o.Index, q)
			}
			b = putUint(b, o.Index, pw)
		}
		return b, nil
	}

	switch {
	case d == nil:
		return b, fmt.Errorf("%w: %s", ErrUnknownObject, h.GV)
	case d.fam == fNone || d.fam == fAny:
		return b, invalid("%s carries no objects", h.GV)
	case q == QualAll:
		return b, invalid("qualifier %s with objects", q)
	case d.freeFormat(h.GV) && !q.IsFreeFormat():
		return b, fmt.Errorf("%w: %s for free-format %s", ErrInvalidQualifier, q, h.GV)
	}
	n := len(h.Objects)
	pw := q.prefixWidth()

	if q.IsRange() {
		start := h.Objects[0].Index
		stop := uint64(start) + uint64(n) - 1
		if stop > limit {
			return b, invalid("range %d..%d with qualifier %s", start, stop, q)
		}
		for i, o := range h.Objects {
			if o.Index != start+uint32(i) {
				return b, invalid("indexes not contiguous: %d at position %d of a range from %d", o.Index, i, start)
			}
		}
		b = putUint(putUint(b, start, w), uint32(stop), w)
	} else {
		if uint64(n) > limit {
			return b, invalid("%d objects with qualifier %s", n, q)
		}
		b = putUint(b, uint32(n), w)
	}

	if bits := d.bits(); bits > 0 {
		if !q.IsRange() {
			return b, fmt.Errorf("%w: %s for packed %s", ErrInvalidQualifier, q, h.GV)
		}
		packed := make([]byte, (n*bits+7)/8)
		for i, o := range h.Objects {
			var x byte
			switch v := o.Value.(type) {
			case Binary:
				if bits != 1 {
					return b, invalid("%T cannot be sent as %s", v, h.GV)
				}
				if v.Value {
					x = 1
				}
			case DoubleBitBinary:
				if bits != 2 {
					return b, invalid("%T cannot be sent as %s", v, h.GV)
				}
				x = byte(v.Value & 3)
			default:
				return b, invalid("%T cannot be sent as %s", o.Value, h.GV)
			}
			bit := i * bits
			packed[bit/8] |= x << (bit % 8)
		}
		return append(b, packed...), nil
	}

	size := d.size(h.GV)
	if size == 0 && !d.selfSized() && !q.IsFreeFormat() {
		return b, fmt.Errorf("%w: %s for %s", ErrInvalidQualifier, q, h.GV)
	}
	plimit := uint64(1)<<(8*pw) - 1
	for _, o := range h.Objects {
		if q.IsIndexed() {
			if uint64(o.Index) > plimit {
				return b, invalid("index %d with qualifier %s", o.Index, q)
			}
			b = putUint(b, o.Index, pw)
		}
		if q.IsFreeFormat() {
			at := len(b)
			b = putUint(b, 0, pw) // size, filled in below
			var err error
			if b, err = d.encodeValue(b, h.GV, o.Value, c); err != nil {
				return b, err
			}
			l := len(b) - at - pw
			if uint64(l) > plimit {
				return b, invalid("object of %d octets with qualifier %s", l, q)
			}
			setUint(b[at:], uint32(l), pw)
			continue
		}
		var err error
		if b, err = d.encodeValue(b, h.GV, o.Value, c); err != nil {
			return b, err
		}
	}
	return b, nil
}

// indexOnly reports whether every object is an index without a value.
func indexOnly(objs []Object) bool {
	for _, o := range objs {
		if o.Value != nil {
			return false
		}
	}
	return len(objs) > 0
}

// AppendObjectValue appends the encoding of one object of gv without any
// header, prefix or size: the octets a free-format object carries. Secure
// authentication uses it to reproduce an object exactly, for example the
// key status message of a session key change. Relative-time variations
// are not supported: they need the CTO of their fragment.
func AppendObjectValue(b []byte, gv GroupVariation, v Value) ([]byte, error) {
	d := lookup(gv)
	if d == nil {
		return b, fmt.Errorf("%w: %s", ErrUnknownObject, gv)
	}
	if d.time == tRel {
		return b, invalid("%s carries a relative time", gv)
	}
	var c codecCtx
	return d.encodeValue(b, gv, v, &c)
}

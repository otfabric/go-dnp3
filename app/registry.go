// SPDX-License-Identifier: MIT

package app

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// GroupVariation identifies an object type: the group in the high octet
// and the variation in the low octet. The G<group>V<variation> constants
// name every variation this package knows.
type GroupVariation uint16

// GV returns the GroupVariation of group g and variation v.
func GV(g, v uint8) GroupVariation { return GroupVariation(g)<<8 | GroupVariation(v) }

// Group returns the object group.
func (gv GroupVariation) Group() uint8 { return uint8(gv >> 8) }

// Variation returns the variation.
func (gv GroupVariation) Variation() uint8 { return uint8(gv) }

// String returns, for example, "g30v5".
func (gv GroupVariation) String() string { return fmt.Sprintf("g%dv%d", gv.Group(), gv.Variation()) }

// Name returns the name of the object in IEEE 1815-2012, for example
// "Analog Input - Single-precision With Flag", or "" for an unknown one.
func (gv GroupVariation) Name() string {
	if d := lookup(gv); d != nil {
		return d.name
	}
	return ""
}

// Known reports whether this package can encode and decode gv.
func (gv GroupVariation) Known() bool { return lookup(gv) != nil }

// IsEvent reports whether gv is an event variation (or "any variation" of
// an event group).
func (gv GroupVariation) IsEvent() bool {
	d := lookup(gv)
	return d != nil && d.event
}

// Size returns the encoded size in octets of one object of gv, and false
// when the size is not fixed: packed variations, free-format and
// self-sized objects, and headers that carry no objects.
func (gv GroupVariation) Size() (int, bool) {
	d := lookup(gv)
	if d == nil {
		return 0, false
	}
	n := d.size(gv)
	return n, n > 0
}

type family uint8

const (
	fNone family = iota // never carries objects: class data, g0v254
	fAny                // variation 0: requests only
	fBinaryPacked
	fBinary
	fDoubleBitPacked
	fDoubleBit
	fBinaryCommandEvent
	fCROB
	fCounter
	fAnalog
	fDeadband
	fAnalogOutput
	fAnalogCommandEvent
	fTime
	fTimeInterval
	fTimeIntervalUnits
	fCTO
	fDelayCoarse
	fDelayFine
	fOctets
	fBCD
	fUint8
	fSecStat
	fAttribute
	fRaw
	fFileAuth
	fFileCommand
	fFileCommandStatus
	fFileTransport
	fFileTransportStatus
	fFileDescriptor
	fFileSpec
	fAuth
)

type numKind uint8

const (
	nNone numKind = iota
	nI16
	nI32
	nU16
	nU32
	nF32
	nF64
)

func (n numKind) size() int {
	switch n {
	case nI16, nU16:
		return 2
	case nI32, nU32, nF32:
		return 4
	case nF64:
		return 8
	default:
		return 0
	}
}

type timeKind uint8

const (
	tNone timeKind = iota
	tAbs           // 48-bit absolute time
	tRel           // 16-bit time relative to the preceding CTO
)

func (t timeKind) size() int {
	switch t {
	case tAbs:
		return 6
	case tRel:
		return 2
	default:
		return 0
	}
}

// desc describes one variation.
type desc struct {
	name  string
	fam   family
	num   numKind
	flags bool
	time  timeKind
	event bool
}

var (
	descAttribute = &desc{name: "Device Attributes", fam: fAttribute}
	descAllAttrs  = &desc{name: "Device Attributes - Non-specific All Attributes Request", fam: fNone}
	descAnyAttr   = &desc{name: "Device Attributes - Any Variation", fam: fAny}
	descOctets    = map[uint8]*desc{
		110: {name: "Octet String", fam: fOctets},
		111: {name: "Octet String Event", fam: fOctets, event: true},
		112: {name: "Virtual Terminal Output Block", fam: fOctets},
		113: {name: "Virtual Terminal Event Data", fam: fOctets, event: true},
	}
	descOctetsAny = map[uint8]*desc{
		110: {name: "Octet String - Any Variation", fam: fAny},
		111: {name: "Octet String Event - Any Variation", fam: fAny, event: true},
		112: {name: "Virtual Terminal Output Block - Any Variation", fam: fAny},
		113: {name: "Virtual Terminal Event Data - Any Variation", fam: fAny, event: true},
	}
)

func lookup(gv GroupVariation) *desc {
	if d, ok := table[gv]; ok {
		return d
	}
	g, v := gv.Group(), gv.Variation()
	switch {
	case g == 0 && v == AttrAllAttributes:
		return descAllAttrs
	case g == 0 && v == 0:
		return descAnyAttr
	case g == 0:
		return descAttribute
	case g >= 110 && g <= 113 && v == 0:
		return descOctetsAny[g]
	case g >= 110 && g <= 113:
		return descOctets[g]
	}
	return nil
}

// size returns the fixed size of one object in octets, 0 when it is not
// fixed. Packed variations report 0; see bits.
func (d *desc) size(gv GroupVariation) int {
	switch d.fam {
	case fBinary, fDoubleBit:
		return 1 + d.time.size()
	case fBinaryCommandEvent:
		return 1 + d.time.size()
	case fCROB:
		return 11
	case fCounter, fAnalog:
		f := 0
		if d.flags {
			f = 1
		}
		return f + d.num.size() + d.time.size()
	case fDeadband:
		return d.num.size()
	case fAnalogOutput:
		return d.num.size() + 1
	case fAnalogCommandEvent:
		return 1 + d.num.size() + d.time.size()
	case fTime, fCTO:
		return 6
	case fTimeInterval:
		return 10
	case fTimeIntervalUnits:
		return 11
	case fDelayCoarse, fDelayFine:
		return 2
	case fOctets:
		return int(gv.Variation())
	case fBCD:
		return 2 << (gv.Variation() - 1) // 2, 4, 8
	case fUint8:
		return 1
	case fSecStat:
		return 7 + d.time.size()
	case fAuth:
		switch gv.Variation() {
		case 3:
			return 6
		case 4:
			return 2
		}
	default:
	}
	return 0
}

// bits returns the bits per object of a packed variation, 0 otherwise.
func (d *desc) bits() int {
	switch d.fam {
	case fBinaryPacked:
		return 1
	case fDoubleBitPacked:
		return 2
	default:
		return 0
	}
}

// selfSized reports whether each object carries its own length.
func (d *desc) selfSized() bool { return d.fam == fAttribute }

// freeFormat reports whether objects of this variation are only sent with
// a free-format qualifier (each object preceded by its size).
func (d *desc) freeFormat(gv GroupVariation) bool {
	switch d.fam {
	case fRaw, fFileAuth, fFileCommand, fFileCommandStatus, fFileTransport,
		fFileTransportStatus, fFileDescriptor, fFileSpec:
		return true
	case fAuth:
		return d.size(gv) == 0
	default:
		return false
	}
}

// codecCtx is the state carried from header to header within a fragment:
// the common time of occurrence of the relative-time variations.
type codecCtx struct {
	cto      Timestamp
	ctoValid bool
	// sizeOnly skips the checks of relative times: the encoding is only
	// measured.
	sizeOnly bool
}

// decodeValue decodes one object of a fixed-size, free-format or
// self-sized variation from exactly the octets of the object.
func (d *desc) decodeValue(gv GroupVariation, b []byte, c *codecCtx) (Value, error) {
	r := reader{b: b}
	switch d.fam {
	case fBinary:
		f := r.u8()
		t, err := d.readTime(&r, c)
		if err != nil {
			return nil, err
		}
		return Binary{Value: f&0x80 != 0, Flags: Flags(f & 0x7F), Time: t}, r.done()
	case fDoubleBit:
		f := r.u8()
		t, err := d.readTime(&r, c)
		if err != nil {
			return nil, err
		}
		return DoubleBitBinary{Value: DoubleBit(f >> 6), Flags: Flags(f & 0x3F), Time: t}, r.done()
	case fBinaryCommandEvent:
		s := r.u8()
		t, _ := d.readTime(&r, c)
		return BinaryCommandEvent{Value: s&0x80 != 0, Status: CommandStatus(s & 0x7F), Time: t}, r.done()
	case fCROB:
		var v CROB
		v.setCode(r.u8())
		v.Count, v.OnTime, v.OffTime, v.Status = r.u8(), r.u32(), r.u32(), CommandStatus(r.u8())
		return v, r.done()
	case fCounter:
		var v Counter
		if d.flags {
			v.Flags = Flags(r.u8())
		}
		if d.num == nU16 {
			v.Value = uint32(r.u16())
		} else {
			v.Value = r.u32()
		}
		v.Time, _ = d.readTime(&r, c)
		return v, r.done()
	case fAnalog:
		var v Analog
		if d.flags {
			v.Flags = Flags(r.u8())
		}
		v.Value = readNum(&r, d.num)
		v.Time, _ = d.readTime(&r, c)
		return v, r.done()
	case fDeadband:
		return AnalogDeadband{Value: readNum(&r, d.num)}, r.done()
	case fAnalogOutput:
		v := AnalogOutput{Value: readNum(&r, d.num)}
		v.Status = CommandStatus(r.u8() & 0x7F)
		return v, r.done()
	case fAnalogCommandEvent:
		v := AnalogCommandEvent{Status: CommandStatus(r.u8() & 0x7F)}
		v.Value = readNum(&r, d.num)
		v.Time, _ = d.readTime(&r, c)
		return v, r.done()
	case fTime:
		return AbsoluteTime{Time: r.time()}, r.done()
	case fTimeInterval:
		return AbsoluteTime{Time: r.time(), Interval: r.u32()}, r.done()
	case fTimeIntervalUnits:
		return AbsoluteTime{Time: r.time(), Interval: r.u32(), Units: IntervalUnit(r.u8())}, r.done()
	case fCTO:
		v := CTO{Time: r.time()}
		if err := r.done(); err != nil {
			return nil, err
		}
		c.cto, c.ctoValid = v.Time, true
		return v, nil
	case fDelayCoarse:
		return TimeDelay{Delay: time.Duration(r.u16()) * time.Second}, r.done()
	case fDelayFine:
		return TimeDelay{Delay: time.Duration(r.u16()) * time.Millisecond}, r.done()
	case fOctets:
		return OctetString{Data: clone(b)}, nil
	case fBCD:
		return decodeBCD(b)
	case fUint8:
		return UnsignedInteger{Value: r.u8()}, r.done()
	case fSecStat:
		v := SecurityStatistic{Flags: Flags(r.u8()), Association: r.u16(), Value: r.u32()}
		v.Time, _ = d.readTime(&r, c)
		return v, r.done()
	case fRaw:
		return Raw{Data: clone(b)}, nil
	case fFileAuth:
		return decFileAuth(b)
	case fFileCommand:
		return decFileCommand(b)
	case fFileCommandStatus:
		return decFileCommandStatus(b)
	case fFileTransport:
		return decFileTransport(b)
	case fFileTransportStatus:
		return decFileTransportStatus(b)
	case fFileDescriptor:
		return decFileDescriptor(b)
	case fFileSpec:
		return FileSpecification{Name: string(b)}, nil
	case fAuth:
		return decAuth(gv.Variation(), b)
	default:
		return nil, fmt.Errorf("%w: %s carries no objects", ErrMalformed, gv)
	}
}

func (d *desc) readTime(r *reader, c *codecCtx) (Timestamp, error) {
	switch d.time {
	case tAbs:
		return r.time(), nil
	case tRel:
		rel := r.u16()
		if r.err != nil {
			return 0, r.err
		}
		if !c.ctoValid {
			return 0, malformed("relative time without a preceding CTO (g51)")
		}
		return c.cto + Timestamp(rel), nil
	default:
		return 0, nil
	}
}

func readNum(r *reader, n numKind) float64 {
	switch n {
	case nI16:
		return float64(int16(r.u16()))
	case nI32:
		return float64(int32(r.u32()))
	case nU16:
		return float64(r.u16())
	case nU32:
		return float64(r.u32())
	case nF32:
		return float64(math.Float32frombits(r.u32()))
	case nF64:
		return math.Float64frombits(r.u64())
	default:
		return 0
	}
}

// encodeValue appends one object of a fixed-size, free-format or
// self-sized variation.
func (d *desc) encodeValue(b []byte, gv GroupVariation, v Value, c *codecCtx) ([]byte, error) {
	mismatch := func() ([]byte, error) {
		return b, invalid("%T cannot be sent as %s", v, gv)
	}
	switch d.fam {
	case fBinary:
		o, ok := v.(Binary)
		if !ok {
			return mismatch()
		}
		f := byte(o.Flags & 0x7F)
		if o.Value {
			f |= 0x80
		}
		return d.writeTime(append(b, f), o.Time, c)
	case fDoubleBit:
		o, ok := v.(DoubleBitBinary)
		if !ok {
			return mismatch()
		}
		return d.writeTime(append(b, byte(o.Flags&0x3F)|byte(o.Value&3)<<6), o.Time, c)
	case fBinaryCommandEvent:
		o, ok := v.(BinaryCommandEvent)
		if !ok {
			return mismatch()
		}
		s := byte(o.Status & 0x7F)
		if o.Value {
			s |= 0x80
		}
		return d.writeTime(append(b, s), o.Time, c)
	case fCROB:
		o, ok := v.(CROB)
		if !ok {
			return mismatch()
		}
		b = append(b, o.Code(), o.Count)
		b = le32(b, o.OnTime)
		b = le32(b, o.OffTime)
		return append(b, byte(o.Status)), nil
	case fCounter:
		o, ok := v.(Counter)
		if !ok {
			return mismatch()
		}
		if d.flags {
			b = append(b, byte(o.Flags))
		}
		if d.num == nU16 {
			b = le16(b, uint16(o.Value))
		} else {
			b = le32(b, o.Value)
		}
		return d.writeTime(b, o.Time, c)
	case fAnalog:
		o, ok := v.(Analog)
		if !ok {
			return mismatch()
		}
		raw, over := toNum(o.Value, d.num)
		if d.flags {
			f := o.Flags
			if over {
				f |= FlagOverRange
			}
			b = append(b, byte(f))
		}
		return d.writeTime(appendNum(b, raw, d.num), o.Time, c)
	case fDeadband:
		o, ok := v.(AnalogDeadband)
		if !ok {
			return mismatch()
		}
		raw, _ := toNum(o.Value, d.num)
		return appendNum(b, raw, d.num), nil
	case fAnalogOutput:
		o, ok := v.(AnalogOutput)
		if !ok {
			return mismatch()
		}
		raw, over := toNum(o.Value, d.num)
		if over {
			return b, invalid("set-point %v does not fit %s", o.Value, gv)
		}
		return append(appendNum(b, raw, d.num), byte(o.Status&0x7F)), nil
	case fAnalogCommandEvent:
		o, ok := v.(AnalogCommandEvent)
		if !ok {
			return mismatch()
		}
		raw, _ := toNum(o.Value, d.num)
		b = appendNum(append(b, byte(o.Status&0x7F)), raw, d.num)
		return d.writeTime(b, o.Time, c)
	case fTime, fTimeInterval, fTimeIntervalUnits:
		o, ok := v.(AbsoluteTime)
		if !ok {
			return mismatch()
		}
		b = le48(b, o.Time)
		if d.fam != fTime {
			b = le32(b, o.Interval)
		}
		if d.fam == fTimeIntervalUnits {
			b = append(b, byte(o.Units))
		}
		return b, nil
	case fCTO:
		o, ok := v.(CTO)
		if !ok {
			return mismatch()
		}
		c.cto, c.ctoValid = o.Time, true
		return le48(b, o.Time), nil
	case fDelayCoarse, fDelayFine:
		o, ok := v.(TimeDelay)
		if !ok {
			return mismatch()
		}
		unit := time.Millisecond
		if d.fam == fDelayCoarse {
			unit = time.Second
		}
		n := o.Delay / unit
		if n < 0 || n > 0xFFFF {
			return b, invalid("time delay %v does not fit %s", o.Delay, gv)
		}
		return le16(b, uint16(n)), nil
	case fOctets:
		o, ok := v.(OctetString)
		if !ok {
			return mismatch()
		}
		if len(o.Data) != int(gv.Variation()) {
			return b, invalid("octet string of %d octets sent as %s", len(o.Data), gv)
		}
		return append(b, o.Data...), nil
	case fBCD:
		o, ok := v.(BCD)
		if !ok {
			return mismatch()
		}
		return encodeBCD(b, o.Value, d.size(gv))
	case fUint8:
		o, ok := v.(UnsignedInteger)
		if !ok {
			return mismatch()
		}
		return append(b, o.Value), nil
	case fSecStat:
		o, ok := v.(SecurityStatistic)
		if !ok {
			return mismatch()
		}
		b = append(b, byte(o.Flags))
		b = le16(b, o.Association)
		b = le32(b, o.Value)
		return d.writeTime(b, o.Time, c)
	case fAttribute:
		o, ok := v.(Attribute)
		if !ok {
			return mismatch()
		}
		return encodeAttribute(b, o)
	case fRaw:
		o, ok := v.(Raw)
		if !ok {
			return mismatch()
		}
		return append(b, o.Data...), nil
	case fFileAuth:
		o, ok := v.(FileAuthentication)
		if !ok {
			return mismatch()
		}
		return encFileAuth(b, o)
	case fFileCommand:
		o, ok := v.(FileCommand)
		if !ok {
			return mismatch()
		}
		return encFileCommand(b, o)
	case fFileCommandStatus:
		o, ok := v.(FileCommandStatus)
		if !ok {
			return mismatch()
		}
		return encFileCommandStatus(b, o), nil
	case fFileTransport:
		o, ok := v.(FileTransport)
		if !ok {
			return mismatch()
		}
		return encFileTransport(b, o)
	case fFileTransportStatus:
		o, ok := v.(FileTransportStatus)
		if !ok {
			return mismatch()
		}
		return encFileTransportStatus(b, o)
	case fFileDescriptor:
		o, ok := v.(FileDescriptor)
		if !ok {
			return mismatch()
		}
		return encFileDescriptor(b, o)
	case fFileSpec:
		o, ok := v.(FileSpecification)
		if !ok {
			return mismatch()
		}
		return append(b, o.Name...), nil
	case fAuth:
		if want := authVariation(v); want != gv.Variation() {
			return mismatch()
		}
		return encAuth(b, v)
	default:
		return b, invalid("%s carries no objects", gv)
	}
}

func (d *desc) writeTime(b []byte, t Timestamp, c *codecCtx) ([]byte, error) {
	switch d.time {
	case tAbs:
		return le48(b, t), nil
	case tRel:
		if c.sizeOnly {
			return le16(b, 0), nil
		}
		if !c.ctoValid {
			return b, invalid("relative time variation without a preceding CTO header")
		}
		if t < c.cto || t-c.cto > 0xFFFF {
			return b, invalid("time %s is not within 65535 ms after the CTO %s", t, c.cto)
		}
		return le16(b, uint16(t-c.cto)), nil
	default:
		return b, nil
	}
}

// toNum converts v to the raw value of an integer or floating-point
// variation and reports whether it had to be clamped.
func toNum(v float64, n numKind) (float64, bool) {
	lo, hi := 0.0, 0.0
	switch n {
	case nI16:
		lo, hi = math.MinInt16, math.MaxInt16
	case nI32:
		lo, hi = math.MinInt32, math.MaxInt32
	case nU16:
		lo, hi = 0, math.MaxUint16
	case nU32:
		lo, hi = 0, math.MaxUint32
	case nF32:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return v, false
		}
		if math.Abs(v) > math.MaxFloat32 {
			return math.Copysign(math.MaxFloat32, v), true
		}
		return v, false
	default:
		return v, false
	}
	if math.IsNaN(v) {
		return 0, true
	}
	r := math.Round(v)
	switch {
	case r < lo:
		return lo, true
	case r > hi:
		return hi, true
	}
	return r, false
}

func appendNum(b []byte, v float64, n numKind) []byte {
	switch n {
	case nI16:
		return le16(b, uint16(int16(v)))
	case nI32:
		return le32(b, uint32(int32(v)))
	case nU16:
		return le16(b, uint16(v))
	case nU32:
		return le32(b, uint32(v))
	case nF32:
		return f32(b, float32(v))
	case nF64:
		return f64(b, v)
	default:
		return b
	}
}

func decodeBCD(b []byte) (Value, error) {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		hi, lo := b[i]>>4, b[i]&0x0F
		if hi > 9 || lo > 9 {
			return nil, malformed("BCD digit above 9 in % x", b)
		}
		v = v*100 + uint64(hi)*10 + uint64(lo)
	}
	return BCD{Value: v}, nil
}

func encodeBCD(b []byte, v uint64, size int) ([]byte, error) {
	out := make([]byte, size)
	for i := range size {
		out[i] = byte(v%10) | byte(v/10%10)<<4
		v /= 100
	}
	if v != 0 {
		return b, invalid("BCD value has more than %d digits", 2*size)
	}
	return append(b, out...), nil
}

func authVariation(v Value) uint8 {
	switch v.(type) {
	case AuthChallenge:
		return 1
	case AuthReply:
		return 2
	case AuthAggressiveMode:
		return 3
	case AuthSessionKeyStatusRequest:
		return 4
	case AuthSessionKeyStatus:
		return 5
	case AuthSessionKeyChange:
		return 6
	case AuthError:
		return 7
	case AuthUserCertificate:
		return 8
	case AuthMAC:
		return 9
	case AuthUserStatusChange:
		return 10
	case AuthUpdateKeyChangeRequest:
		return 11
	case AuthUpdateKeyChangeReply:
		return 12
	case AuthUpdateKeyChange:
		return 13
	case AuthUpdateKeyChangeSignature:
		return 14
	case AuthUpdateKeyChangeConfirmation:
		return 15
	default:
		return 0
	}
}

// putUint writes v in w octets, little endian.
func putUint(b []byte, v uint32, w int) []byte {
	switch w {
	case 1:
		return append(b, byte(v))
	case 2:
		return le16(b, uint16(v))
	default:
		return le32(b, v)
	}
}

// getUint reads w octets little endian.
func getUint(b []byte, w int) uint32 {
	switch w {
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(b))
	default:
		return binary.LittleEndian.Uint32(b)
	}
}

// setUint overwrites the first w octets of b with v, little endian.
func setUint(b []byte, v uint32, w int) {
	switch w {
	case 1:
		b[0] = byte(v)
	case 2:
		binary.LittleEndian.PutUint16(b, uint16(v))
	default:
		binary.LittleEndian.PutUint32(b, v)
	}
}

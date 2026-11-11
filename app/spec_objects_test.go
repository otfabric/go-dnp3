// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"testing"
)

// TestSpecA_8_1_CROBStatus: the CROB is a control code, a count, the on
// and off times as UINT32 and a UINT7 status whose bit 7 is reserved, sent
// as 0 by master and outstation (IEEE 1815-2012 A.8.1.2.2, printed
// p505..507). The codec does not read the reserved bit.
func TestSpecA_8_1_CROBStatus(t *testing.T) {
	vector(t, "g12v1", "C0 81 00 00 0C 01 17 01 03 41 01 64 00 00 00 C8 00 00 00 04",
		Header{GV: G12V1, Qualifier: 0x17, Count: 1, Objects: []Object{{3, CROB{
			Op: OpPulseOn, TripClose: TCCClose, Count: 1, OnTime: 100, OffTime: 200, Status: StatusNotSupported}}}})

	f, err := Decode(unhex(t, "C0 81 00 00 0C 01 17 01 03 41 01 64 00 00 00 C8 00 00 00 85"))
	if err != nil {
		t.Fatal(err)
	}
	if s := f.Headers[0].Objects[0].Value.(CROB).Status; s != 5 {
		t.Fatalf("status with the reserved bit set: %d", s)
	}
	f, err = Decode(unhex(t, "C0 05 0C 01 17 01 03 41 01 64 00 00 00 C8 00 00 00 80"))
	if err != nil || f.Headers[0].Objects[0].Value.(CROB).Status != StatusSuccess {
		t.Fatalf("request with the reserved bit set: %v, %v", f, err)
	}
	b := mustEncode(t, &Fragment{Function: FuncResponse, Headers: []Header{Indexed(G12V1, Object{0, CROB{Op: OpPulseOn, Status: 0x85}})}})
	if b[len(b)-1] != 0x05 {
		t.Fatalf("status 0x85 sent as %#x", b[len(b)-1])
	}
}

// TestSpecA_20_1_AnalogOutputStatus: the analog output block carries the
// value and a UINT8 control status, all eight bits of it (IEEE 1815-2012
// A.20.1.2.2, A.20.2.2.2, A.20.3.2.2, A.20.4.2.2, printed p615..618).
func TestSpecA_20_1_AnalogOutputStatus(t *testing.T) {
	vector(t, "g41v1", "C0 81 00 00 29 01 17 01 02 A0 86 01 00 85",
		Header{GV: G41V1, Qualifier: 0x17, Count: 1, Objects: []Object{{2, AnalogOutput{Value: 100000, Status: 133}}}})
	vector(t, "g41v2", "C0 81 00 00 29 02 17 01 02 10 AA 7F",
		Header{GV: G41V2, Qualifier: 0x17, Count: 1, Objects: []Object{{2, AnalogOutput{Value: -22000, Status: 127}}}})
	vector(t, "g41v3", "C0 81 00 00 29 03 17 01 02 39 5E 11 C5 FF",
		Header{GV: G41V3, Qualifier: 0x17, Count: 1, Objects: []Object{{2, AnalogOutput{Value: float64(float32(-2325.8890344337706)), Status: 255}}}})
	vector(t, "g41v4", "C0 81 00 00 29 04 17 01 02 20 74 85 2F C7 2B A2 C0 00",
		Header{GV: G41V4, Qualifier: 0x17, Count: 1, Objects: []Object{{2, AnalogOutput{Value: -2325.8890344337706, Status: StatusSuccess}}}})
}

// TestSpecA_29_1_BufferFillStatus: g81v1 is a UINT7 fill percentage, 0 to
// 100, the BSTR1 overflow state in bit 7, and the group and variation of
// the buffer (IEEE 1815-2012 A.29.1.2.2, printed p688). The object is not
// recommended for new implementations (A.29.1.2.3); the codec decodes it.
func TestSpecA_29_1_BufferFillStatus(t *testing.T) {
	vector(t, "g81v1", "C0 81 00 00 51 01 00 00 01 B2 02 01 64 20 03",
		Header{GV: G81V1, Qualifier: 0x00, Start: 0, Stop: 1, Objects: []Object{
			{0, BufferFillStatus{Fill: 50, Overflow: true, Buffer: G2V1}},
			{1, BufferFillStatus{Fill: 100, Buffer: GV(32, 3)}},
		}})
	if n, ok := G81V1.Size(); !ok || n != 3 {
		t.Fatalf("size %d, %v", n, ok)
	}
	f := &Fragment{Function: FuncResponse, Headers: []Header{Ranged(G81V1, 0, BufferFillStatus{Fill: 128})}}
	if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("fill 128: %v", err)
	}
	if _, err := AppendObjectValue(nil, G81V1, Binary{}); err == nil {
		t.Fatal("g81v1 encoded a binary input")
	}
	if _, err := Decode(unhex(t, "C0 81 00 00 51 01 00 00 00 B2 02")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short g81v1: %v", err)
	}
}

// TestSpecA_30_1_DeviceProfile: g82v1 is a variable-size object, a BSTR64
// of function codes, a UINT16 count and that many object headers
// (IEEE 1815-2012 A.30.1.2.2, printed p690); the codec carries its octets
// in a free-format header.
func TestSpecA_30_1_DeviceProfile(t *testing.T) {
	data := unhex(t, "03 00 00 00 00 00 00 00 01 00 01 02 06")
	vector(t, "g82v1", "C0 81 80 00 52 01 5B 01 0D 00 03 00 00 00 00 00 00 00 01 00 01 02 06",
		Header{GV: G82V1, Qualifier: 0x5B, Count: 1, Objects: []Object{{0, Raw{Data: data}}}})
}

// TestSpecEX5_9_DataSetEvent: EX 5-9 (IEEE 1815-2012 5.4, printed p148)
// returns an electrical fault data set event as one g88v1 object of 38
// octets in qualifier 0x5B.
func TestSpecEX5_9_DataSetEvent(t *testing.T) {
	data := unhex(t, "02 00 00 06 F5 7C 38 01 F7 00 04 5C 1F A6 44 04 C3 15 D2 43 04 C3 0D 83 44 04 9A 79 AB 43 01 0B 03 41 43 47 01 8D")
	vector(t, "EX 5-9", "E8 81 00 00 58 01 5B 01 26 00 02 00 00 06 F5 7C 38 01 F7 00 04 5C 1F A6 44 04 C3 15 D2 43 04 C3 0D 83 44 04 9A 79 AB 43 01 0B 03 41 43 47 01 8D",
		Header{GV: GV(88, 1), Qualifier: 0x5B, Count: 1, Objects: []Object{{0, Raw{Data: data}}}})
}

// TestSpecA_40_SmallInteger: g102v1 is a UINT8 (IEEE 1815-2012 A.40.1,
// printed p714).
func TestSpecA_40_SmallInteger(t *testing.T) {
	vector(t, "g102v1", "C0 81 00 00 66 01 00 00 01 00 FF",
		Header{GV: GV(102, 1), Qualifier: 0x00, Start: 0, Stop: 1, Objects: []Object{
			{0, UnsignedInteger{Value: 0}}, {1, UnsignedInteger{Value: 255}}}})
}

// TestSpecA_3_3_RelativeTimeEvents: g2v3 and g4v3 carry the flags octet
// (the binary state in bit 7, the double-bit state in bits 6..7) and a
// UINT16 time in milliseconds after the CTO that precedes them
// (IEEE 1815-2012 A.3.3.2.2, printed p492; A.5.3.2.2, p497).
func TestSpecA_3_3_RelativeTimeEvents(t *testing.T) {
	const cto = Timestamp(1_000_000) // 40 42 0F 00 00 00
	vector(t, "g51v1 g2v3 g4v3", "C0 81 00 00 33 01 07 01 40 42 0F 00 00 00 02 03 17 01 05 81 0A 00 04 03 17 01 06 81 00 01",
		Header{GV: G51V1, Qualifier: 0x07, Count: 1, Objects: []Object{{0, CTO{Time: cto}}}},
		Header{GV: G2V3, Qualifier: 0x17, Count: 1, Objects: []Object{{5, Binary{Value: true, Flags: FlagOnline, Time: cto + 10}}}},
		Header{GV: GV(4, 3), Qualifier: 0x17, Count: 1, Objects: []Object{{6, DoubleBitBinary{Value: DoubleBitOn, Flags: FlagOnline, Time: cto + 256}}}})
}

// TestSpecAnnexA_Layouts: byte vectors of the field order of IEEE
// 1815-2012 Annex A, for the variations the round trip alone does not
// pin down. Times are DNP3TIME 0x010203040506; the values are those of
// EX 11-1 and EX 11-2 (11.3.4, 11.3.5, printed p309..311).
//
//   - g2v2, g4v1, g4v2: flags, then the time (A.3.2, A.5.1, A.5.2, p491..496).
//   - g11v1, g11v2: flags with the state in bit 7 (A.7.1, A.7.2, p501..503).
//   - g13v1, g13v2: a UINT7 status and the commanded state in bit 7
//     (A.9.1.2.2, A.9.2.2.2, p514..516).
//   - g43v1..v8: a UINT7 status, a reserved bit 7, then the value and the
//     time (A.22.1..A.22.8, p634..646).
//   - g21v5, g21v6: flags, UINT32 or UINT16, time (A.11.5, A.11.6, p529..531).
//   - g33v7, g33v8: flags, FLT32 or FLT64, time (A.17.7, A.17.8, p602..604).
//   - g34v1..v3: UINT16, UINT32, FLT32 (A.18.1..A.18.3, p606..608).
func TestSpecAnnexA_Layouts(t *testing.T) {
	const tm = Timestamp(0x010203040506)
	const ts = "06 05 04 03 02 01"
	f64 := -2325.8890344337706   // 20 74 85 2F C7 2B A2 C0
	f32 := float64(float32(f64)) // 39 5E 11 C5
	one := func(gv GroupVariation, q Qualifier, idx uint32, v Value) Header {
		h := Header{GV: gv, Qualifier: q, Objects: []Object{{idx, v}}}
		if q == 0x17 {
			h.Count = 1
		} else {
			h.Start, h.Stop = idx, idx
		}
		return h
	}
	for _, c := range []struct {
		hx string
		h  Header
	}{
		{"02 02 17 01 01 01 " + ts, one(G2V2, 0x17, 1, Binary{Flags: FlagOnline, Time: tm})},
		{"04 01 17 01 03 C1", one(GV(4, 1), 0x17, 3, DoubleBitBinary{Value: DoubleBitIndeterminate, Flags: FlagOnline})},
		{"04 02 17 01 02 41 " + ts, one(GV(4, 2), 0x17, 2, DoubleBitBinary{Value: DoubleBitOff, Flags: FlagOnline, Time: tm})},
		{"0B 01 17 01 04 81", one(GV(11, 1), 0x17, 4, Binary{Value: true, Flags: FlagOnline})},
		{"0B 02 17 01 04 01 " + ts, one(GV(11, 2), 0x17, 4, Binary{Flags: FlagOnline, Time: tm})},
		{"0D 01 17 01 07 84", one(GV(13, 1), 0x17, 7, BinaryCommandEvent{Value: true, Status: StatusNotSupported})},
		{"0D 02 17 01 07 00 " + ts, one(GV(13, 2), 0x17, 7, BinaryCommandEvent{Time: tm})},
		{"2B 01 17 01 08 00 A0 86 01 00", one(GV(43, 1), 0x17, 8, AnalogCommandEvent{Value: 100000})},
		{"2B 02 17 01 08 01 10 AA", one(GV(43, 2), 0x17, 8, AnalogCommandEvent{Value: -22000, Status: StatusTimeout})},
		{"2B 03 17 01 08 02 A0 86 01 00 " + ts, one(GV(43, 3), 0x17, 8, AnalogCommandEvent{Value: 100000, Status: StatusNoSelect, Time: tm})},
		{"2B 04 17 01 08 03 10 AA " + ts, one(GV(43, 4), 0x17, 8, AnalogCommandEvent{Value: -22000, Status: StatusFormatError, Time: tm})},
		{"2B 05 17 01 08 04 39 5E 11 C5", one(GV(43, 5), 0x17, 8, AnalogCommandEvent{Value: f32, Status: StatusNotSupported})},
		{"2B 06 17 01 08 05 20 74 85 2F C7 2B A2 C0", one(GV(43, 6), 0x17, 8, AnalogCommandEvent{Value: f64, Status: 5})},
		{"2B 07 17 01 08 06 39 5E 11 C5 " + ts, one(GV(43, 7), 0x17, 8, AnalogCommandEvent{Value: f32, Status: 6, Time: tm})},
		{"2B 08 17 01 08 07 20 74 85 2F C7 2B A2 C0 " + ts, one(GV(43, 8), 0x17, 8, AnalogCommandEvent{Value: f64, Status: 7, Time: tm})},
		{"15 05 00 09 09 01 00 28 6B EE " + ts, one(GV(21, 5), 0x00, 9, Counter{Value: 4_000_000_000, Flags: FlagOnline, Time: tm})},
		{"15 06 00 09 09 01 FF FF " + ts, one(GV(21, 6), 0x00, 9, Counter{Value: 65535, Flags: FlagOnline, Time: tm})},
		{"21 07 17 01 0A 01 39 5E 11 C5 " + ts, one(GV(33, 7), 0x17, 10, Analog{Value: f32, Flags: FlagOnline, Time: tm})},
		{"21 08 17 01 0A 01 20 74 85 2F C7 2B A2 C0 " + ts, one(GV(33, 8), 0x17, 10, Analog{Value: f64, Flags: FlagOnline, Time: tm})},
		{"22 01 00 00 00 FF FF", one(GV(34, 1), 0x00, 0, AnalogDeadband{Value: 65535})},
		{"22 02 00 00 00 00 28 6B EE", one(GV(34, 2), 0x00, 0, AnalogDeadband{Value: 4_000_000_000})},
		{"22 03 00 00 00 39 5E 11 C5", one(GV(34, 3), 0x00, 0, AnalogDeadband{Value: f32})},
	} {
		vector(t, c.h.GV.String(), "C0 81 00 00 "+c.hx, c.h)
	}

	// The reserved bit 7 of the g43 status is "Always 0" (A.22.1.2.2): it is
	// not read.
	f, err := Decode(unhex(t, "C0 81 00 00 2B 02 17 01 08 81 10 AA"))
	if err != nil || f.Headers[0].Objects[0].Value.(AnalogCommandEvent).Status != StatusTimeout {
		t.Fatalf("g43 status with bit 7 set: %v, %v", f, err)
	}
}

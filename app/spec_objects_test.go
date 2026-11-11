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

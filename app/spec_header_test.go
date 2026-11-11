// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"testing"
)

// TestSpec4_2_2_4_ControlOctet: the application control octet carries FIR
// in bit 7, FIN in bit 6, CON in bit 5, UNS in bit 4 and the sequence
// number in bits 0..3 (IEEE 1815-2012 4.2.2.4, Figure 4-5, printed
// p21–22). Every octet decodes and encodes back unchanged.
func TestSpec4_2_2_4_ControlOctet(t *testing.T) {
	for _, c := range []struct {
		b    byte
		want Control
	}{
		{0x80, Control{FIR: true}},
		{0x40, Control{FIN: true}},
		{0x20, Control{CON: true}},
		{0x10, Control{UNS: true}},
		{0x0F, Control{Seq: 15}},
		{0xC0, Control{FIR: true, FIN: true}},
		{0xF5, Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: 5}},
	} {
		if got := ParseControl(c.b); got != c.want {
			t.Errorf("ParseControl(%#02x) = %+v, want %+v", c.b, got, c.want)
		}
		if got := c.want.Byte(); got != c.b {
			t.Errorf("%+v.Byte() = %#02x, want %#02x", c.want, got, c.b)
		}
	}
	for b := range 256 {
		if got := ParseControl(byte(b)).Byte(); got != byte(b) {
			t.Fatalf("control %#02x encodes as %#02x", b, got)
		}
	}
	// The sequence number is four bits: Byte keeps only those.
	if (Control{Seq: 0x1F}).Byte() != 0x0F || SingleControl(0x13) != (Control{FIR: true, FIN: true, Seq: 3}) {
		t.Fatal("sequence number wider than four bits")
	}
}

// TestSpec4_2_2_4_2_SequenceWraps: the sequence number increments modulo
// 16, from 15 to 0 (IEEE 1815-2012 4.2.2.4.2, printed p22, and 4.3 Rule 14,
// p39).
func TestSpec4_2_2_4_2_SequenceWraps(t *testing.T) {
	for s := range uint8(16) {
		if got, want := NextSeq(s), (s+1)%16; got != want {
			t.Errorf("NextSeq(%d) = %d, want %d", s, got, want)
		}
	}
}

// TestSpecTable4_2_FunctionCodes: IEEE 1815-2012 Table 4-2 (printed
// p24–27) defines the request codes 0..33 and the response codes 129..131,
// and reserves 34..128 and 132..255. The outstation sends no response to
// CONFIRM, the _NR functions and AUTH_REQ_NO_ACK. Responses carry the IIN
// octets (4.2.2.6, p28).
func TestSpecTable4_2_FunctionCodes(t *testing.T) {
	names := map[FunctionCode]string{
		0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE",
		6: "DIRECT_OPERATE_NR", 7: "IMMED_FREEZE", 8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR",
		10: "FREEZE_CLEAR_NR", 11: "FREEZE_AT_TIME", 12: "FREEZE_AT_TIME_NR", 13: "COLD_RESTART",
		14: "WARM_RESTART", 15: "INITIALIZE_DATA", 16: "INITIALIZE_APPL", 17: "START_APPL",
		18: "STOP_APPL", 19: "SAVE_CONFIG", 20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
		22: "ASSIGN_CLASS", 23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME", 25: "OPEN_FILE",
		26: "CLOSE_FILE", 27: "DELETE_FILE", 28: "GET_FILE_INFO", 29: "AUTHENTICATE_FILE",
		30: "ABORT_FILE", 31: "ACTIVATE_CONFIG", 32: "AUTHENTICATE_REQ", 33: "AUTH_REQ_NO_ACK",
		129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP",
	}
	noAck := map[FunctionCode]bool{0: true, 6: true, 8: true, 10: true, 12: true, 33: true}
	for c := range 256 {
		f := FunctionCode(c)
		name, defined := names[f]
		if f.Defined() != defined {
			t.Errorf("%d: Defined() = %v", c, f.Defined())
		}
		if defined && f.String() != name {
			t.Errorf("%d: String() = %q, want %q", c, f.String(), name)
		}
		if f.NoAck() != noAck[f] {
			t.Errorf("%d: NoAck() = %v", c, f.NoAck())
		}
		if want := c >= 129; f.IsResponse() != want {
			t.Errorf("%d: IsResponse() = %v", c, f.IsResponse())
		}
	}
	// An undefined function decodes to its header with ErrUnknownFunction,
	// so that an outstation can answer IIN2.0 (4.5.9, p84).
	for _, c := range []byte{34, 128} {
		f, err := Decode([]byte{0xC4, c, 0x3C, 0x02, 0x06})
		if !errors.Is(err, ErrUnknownFunction) || f == nil || f.Control.Seq != 4 || f.Function != FunctionCode(c) {
			t.Errorf("function %d: %v, %v", c, f, err)
		}
	}
}

// TestSpecTable4_3_IINBits: IIN1 is sent before IIN2, and bit b of octet x
// is IINx.b with the names of IEEE 1815-2012 Table 4-3 (4.2.2.6, printed
// p28–29). Group 80 numbers them 0..15 (A.28, p686).
func TestSpecTable4_3_IINBits(t *testing.T) {
	bits := []struct {
		bit  IIN
		name string
	}{
		{IINBroadcast, "BROADCAST"}, {IINClass1Events, "CLASS_1_EVENTS"},
		{IINClass2Events, "CLASS_2_EVENTS"}, {IINClass3Events, "CLASS_3_EVENTS"},
		{IINNeedTime, "NEED_TIME"}, {IINLocalControl, "LOCAL_CONTROL"},
		{IINDeviceTrouble, "DEVICE_TROUBLE"}, {IINDeviceRestart, "DEVICE_RESTART"},
		{IINNoFuncCodeSupport, "NO_FUNC_CODE_SUPPORT"}, {IINObjectUnknown, "OBJECT_UNKNOWN"},
		{IINParameterError, "PARAMETER_ERROR"}, {IINEventBufferOverflow, "EVENT_BUFFER_OVERFLOW"},
		{IINAlreadyExecuting, "ALREADY_EXECUTING"}, {IINConfigCorrupt, "CONFIG_CORRUPT"},
		{IINReserved2, "RESERVED_2"}, {IINReserved1, "RESERVED_1"},
	}
	for i, b := range bits {
		iin1, iin2 := byte(0), byte(0)
		if i < 8 {
			iin1 = 1 << i
		} else {
			iin2 = 1 << (i - 8)
		}
		if b.bit.IIN1() != iin1 || b.bit.IIN2() != iin2 || b.bit.String() != b.name || IINBit(b.bit) != uint32(i) {
			t.Errorf("IIN%d.%d: octets %02X %02X, name %q, index %d", i/8+1, i%8, b.bit.IIN1(), b.bit.IIN2(), b.bit.String(), IINBit(b.bit))
		}
		resp := []byte{0xC0, 0x81, iin1, iin2}
		f, err := Decode(resp)
		if err != nil || f.IIN != b.bit {
			t.Errorf("IIN%d.%d: decoded %v, %v", i/8+1, i%8, f, err)
			continue
		}
		if got := mustEncode(t, f); !bytes.Equal(got, resp) {
			t.Errorf("IIN%d.%d: encoded % X", i/8+1, i%8, got)
		}
	}
	if IINBit(IINNeedTime|IINDeviceRestart) != 0 || IIN(0).String() != "" {
		t.Error("IINBit or String of no single bit")
	}
}

// TestSpecTable4_8_ResponseHeaders: a response names its objects with
// specific groups, variations and indexes. Qualifier 0x06 is "not
// permitted in a response" (IEEE 1815-2012 Table 4-8, printed p35; 4.4.2
// NOTE 1, p43); only master requests use group 60 (4.2.2.7.1.1, p30–31,
// "the outstation's response shall contain specific group identifiers")
// and variation 0 (4.2.2.7.2.1, p31). The encoder refuses these headers in
// RESPONSE, UNSOLICITED_RESPONSE and AUTHENTICATE_RESP, and the decoder
// refuses them as malformed: the objects of a class or variation 0 header
// have no size, so nothing after them could be parsed.
func TestSpecTable4_8_ResponseHeaders(t *testing.T) {
	for _, fc := range []string{"81", "82", "83"} {
		for _, c := range []struct {
			name, hex string
			want      error
		}{
			{"qualifier 0x06", "1E 01 06", ErrInvalidQualifier},
			{"variation 0, qualifier 0x06", "1E 00 06", ErrInvalidQualifier},
			{"class 0, qualifier 0x06", "3C 01 06", ErrInvalidQualifier},
			{"variation 0 with a range", "1E 00 00 00 00 01 E8 03 00 00", ErrMalformed},
			{"variation 0 with a count", "02 00 07 01 01", ErrMalformed},
			{"class 1 with a count", "3C 02 07 01", ErrMalformed},
			{"unknown class variation", "3C 09 07 01", ErrMalformed},
			{"all attributes request", "00 FE 00 00 00", ErrMalformed},
			{"any attribute", "00 00 00 00 00", ErrMalformed},
			{"octet string of any length", "6E 00 00 00 00", ErrMalformed},
		} {
			f, err := Decode(unhex(t, "C0 "+fc+" 00 00 "+c.hex))
			if !errors.Is(err, c.want) {
				t.Errorf("%s %s: err = %v, want %v", fc, c.name, err, c.want)
			}
			if f == nil || len(f.Headers) != 0 {
				t.Errorf("%s %s: fragment %v", fc, c.name, f)
			}
		}
	}
	// The headers before the refused one are returned (4.5.10, p85: the
	// master keeps what it parsed).
	f, err := Decode(unhex(t, "C0 81 00 00 1E 01 00 00 00 01 E8 03 00 00 3C 01 06"))
	if !errors.Is(err, ErrInvalidQualifier) || f == nil || len(f.Headers) != 1 || f.Headers[0].GV != G30V1 {
		t.Fatalf("partial response: %v, %v", f, err)
	}

	for _, fc := range []FunctionCode{FuncResponse, FuncUnsolicitedResponse, FuncAuthResponse} {
		for _, c := range []struct {
			name string
			h    Header
			want error
		}{
			{"qualifier 0x06", AllObjects(G30V1), ErrInvalidQualifier},
			{"class 0", AllObjects(G60V1), ErrInvalidQualifier},
			{"class with a count", CountOf(G60V2, 1), ErrInvalidValue},
			{"variation 0 with a range", IndexRange(G30V0, 0, 0), ErrInvalidValue},
			{"variation 0 with objects", Header{GV: G30V0, Qualifier: Qual1ByteStartStop, Objects: []Object{{0, Analog{}}}}, ErrInvalidValue},
			{"all attributes request", IndexRange(GV(0, AttrAllAttributes), 0, 0), ErrInvalidValue},
		} {
			f := &Fragment{Control: SingleControl(0), Function: fc, Headers: []Header{c.h}}
			if _, err := f.Encode(); !errors.Is(err, c.want) {
				t.Errorf("%s %s: err = %v, want %v", fc, c.name, err, c.want)
			}
		}
	}
	// Requests keep them: an integrity poll and a READ of variation 0.
	req := &Fragment{Control: SingleControl(0), Function: FuncRead,
		Headers: append(ClassHeaders(1, 2, 3, 0), IndexRange(G30V0, 0, 0), AllObjects(GV(0, AttrAllAttributes)))}
	if _, err := Decode(mustEncode(t, req)); err != nil {
		t.Fatalf("request: %v", err)
	}
}

// TestSpec4_3_Rule2_TwoOctetFragment: a fragment may be as short as two
// octets, the application control and the function code (IEEE 1815-2012
// 4.3 Rule 2, printed p38), for example DELAY_MEASURE or CONFIRM.
func TestSpec4_3_Rule2_TwoOctetFragment(t *testing.T) {
	for _, b := range [][]byte{{0xC1, 0x17}, {0xC2, 0x00}, {0xD3, 0x00}} {
		f, err := Decode(b)
		if err != nil || len(f.Headers) != 0 {
			t.Fatalf("% X: %v, %v", b, f, err)
		}
		if re := mustEncode(t, f); !bytes.Equal(re, b) {
			t.Fatalf("% X re-encoded as % X", b, re)
		}
	}
}

// TestSpec4_5_10_UnknownObjectAfterCTO: an object the master does not know
// stops the parse of a response (its size is unknown); the headers before
// it, a CTO and its relative-time events here, are returned (IEEE 1815-2012
// 4.5.10 and Table 4-14, printed p85).
func TestSpec4_5_10_UnknownObjectAfterCTO(t *testing.T) {
	b := unhex(t, "C0 81 00 00 33 01 07 01 00 00 00 00 00 00 02 03 17 01 01 81 0A 00 C8 01 07 01 00")
	f, err := Decode(b)
	if !errors.Is(err, ErrUnknownObject) {
		t.Fatalf("err = %v, want ErrUnknownObject", err)
	}
	if f == nil || len(f.Headers) != 2 || f.Headers[0].GV != G51V1 || f.Headers[1].GV != G2V3 {
		t.Fatalf("headers %v", f)
	}
	if v := f.Headers[1].Objects[0].Value.(Binary); !v.Value || v.Time != 10 {
		t.Fatalf("event %+v", v)
	}
}

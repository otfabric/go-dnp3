// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEncode(t testing.TB, f *Fragment) []byte {
	t.Helper()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIntegrityPollVector(t *testing.T) {
	f := &Fragment{Control: SingleControl(0), Function: FuncRead, Headers: ClassHeaders(1, 2, 3, 0)}
	got := mustEncode(t, f)
	want := unhex(t, "C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06")
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % X, want % X", got, want)
	}
	d, err := Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Headers) != 4 || d.Headers[3].GV != G60V1 || d.Headers[0].Objects != nil {
		t.Fatalf("decoded %v", d)
	}
}

func TestResponseVector(t *testing.T) {
	// Response, IIN DEVICE_RESTART, g1v2 indexes 0..1, g30v1 index 5.
	b := unhex(t, "C3 81 80 00  01 02 00 00 01 81 01  1E 01 00 05 05 01 E8 03 00 00")
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.IIN != IINDeviceRestart || f.Control.Seq != 3 || !f.Control.FIR || !f.Control.FIN {
		t.Fatalf("header %v", f)
	}
	want := []Header{
		{GV: G1V2, Qualifier: Qual1ByteStartStop, Start: 0, Stop: 1, Objects: []Object{
			{0, Binary{Value: true, Flags: FlagOnline}},
			{1, Binary{Value: false, Flags: FlagOnline}},
		}},
		{GV: G30V1, Qualifier: Qual1ByteStartStop, Start: 5, Stop: 5, Objects: []Object{
			{5, Analog{Value: 1000, Flags: FlagOnline}},
		}},
	}
	if !reflect.DeepEqual(f.Headers, want) {
		t.Fatalf("headers\n%#v\nwant\n%#v", f.Headers, want)
	}
	if re := mustEncode(t, f); !bytes.Equal(re, b) {
		t.Fatalf("re-encode % X", re)
	}
	if s := f.String(); s != "RESPONSE FIR FIN seq=3 iin=DEVICE_RESTART headers=2" {
		t.Fatalf("String %q", s)
	}
}

// TestDataSetCharacteristicsVector: g86v2 is one octet per data set
// (IEEE 1815-2012 A.47.2), sent with a range, not free-format.
func TestDataSetCharacteristicsVector(t *testing.T) {
	// Response, g86v2 data sets 1..2: RD|ST|EV, then RD|WR|DF.
	b := unhex(t, "C1 81 00 00  56 02 00 01 02 0D 13")
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Header{{GV: G86V2, Qualifier: Qual1ByteStartStop, Start: 1, Stop: 2, Objects: []Object{
		{1, DataSetCharacteristics{Flags: DataSetReadable | DataSetStatic | DataSetEvents}},
		{2, DataSetCharacteristics{Flags: DataSetReadable | DataSetWritable | DataSetMasterDefined}},
	}}}
	if !reflect.DeepEqual(f.Headers, want) {
		t.Fatalf("headers\n%#v\nwant\n%#v", f.Headers, want)
	}
	if re := mustEncode(t, f); !bytes.Equal(re, b) {
		t.Fatalf("re-encode % X", re)
	}
	if n, ok := G86V2.Size(); !ok || n != 1 {
		t.Fatalf("size %d, %v", n, ok)
	}
	if s := (DataSetReadable | DataSetMasterDefined | 1<<7).String(); s != "RD|DF|BIT7" {
		t.Fatalf("String %q", s)
	}
}

func TestDirectOperateCROBVector(t *testing.T) {
	// DIRECT_OPERATE, g12v1 qualifier 0x28 count 1 index 3, LATCH_ON count 1 on 100 off 0.
	want := unhex(t, "C5 05 0C 01 28 01 00 03 00 03 01 64 00 00 00 00 00 00 00 00")
	f := &Fragment{Control: SingleControl(5), Function: FuncDirectOperate, Headers: []Header{
		{GV: G12V1, Qualifier: Qual2ByteIndexCount, Objects: []Object{{3, CROB{Op: OpLatchOn, Count: 1, OnTime: 100}}}},
	}}
	if got := mustEncode(t, f); !bytes.Equal(got, want) {
		t.Fatalf("encode % X\nwant   % X", got, want)
	}
	d, err := Decode(want)
	if err != nil {
		t.Fatal(err)
	}
	c := d.Headers[0].Objects[0].Value.(CROB)
	if c.String() != "LATCH_ON count=1 on=100ms off=0ms SUCCESS" {
		t.Fatal(c.String())
	}
	trip := CROB{Op: OpPulseOn, TripClose: TCCTrip, Queue: true, Clear: true}
	var back CROB
	back.setCode(trip.Code())
	if back != trip || trip.Code() != 0xB1 {
		t.Fatalf("code %#x -> %+v", trip.Code(), back)
	}
}

// sample returns a value of the family of gv that survives a round trip
// through the variation unchanged.
func sample(gv GroupVariation, d *desc, i int) Value {
	ts := Timestamp(1_700_000_000_000 + i)
	if d.time == tNone {
		ts = 0
	}
	fl := Flags(0)
	if d.flags {
		fl = FlagOnline | FlagRestart
	}
	switch d.fam {
	case fBinaryPacked:
		return Binary{Value: i%2 == 0}
	case fBinary:
		return Binary{Value: i%2 == 1, Flags: fl | FlagChatterFilter, Time: ts}
	case fDoubleBitPacked:
		return DoubleBitBinary{Value: DoubleBit(i % 4)}
	case fDoubleBit:
		return DoubleBitBinary{Value: DoubleBit(i % 4), Flags: fl, Time: ts}
	case fBinaryCommandEvent:
		return BinaryCommandEvent{Value: true, Status: StatusLocal, Time: ts}
	case fCROB:
		return CROB{Op: OpPulseOn, TripClose: TCCClose, Count: 2, OnTime: 1000, OffTime: 500, Status: StatusSuccess}
	case fCounter:
		v := uint32(70000 + i)
		if d.num == nU16 {
			v = uint32(4000 + i)
		}
		return Counter{Value: v, Flags: fl, Time: ts}
	case fAnalog:
		v := -1234.0 - float64(i)
		switch d.num {
		case nF32:
			v = 12.5
		case nF64:
			v = math.Pi
		default:
		}
		return Analog{Value: v, Flags: fl, Time: ts}
	case fDeadband:
		if d.num == nF32 {
			return AnalogDeadband{Value: 0.25}
		}
		return AnalogDeadband{Value: 7}
	case fAnalogOutput:
		return AnalogOutput{Value: 300, Status: StatusSuccess}
	case fAnalogCommandEvent:
		return AnalogCommandEvent{Value: -5, Status: StatusOutOfRange, Time: ts}
	case fTime:
		return AbsoluteTime{Time: 1_700_000_000_123}
	case fTimeInterval:
		return AbsoluteTime{Time: 1_700_000_000_123, Interval: 60000}
	case fTimeIntervalUnits:
		return AbsoluteTime{Time: 1_700_000_000_123, Interval: 15, Units: UnitMinutes}
	case fCTO:
		return CTO{Time: 1_700_000_000_000}
	case fDelayCoarse:
		return TimeDelay{Delay: 3 * time.Second}
	case fDelayFine:
		return TimeDelay{Delay: 250 * time.Millisecond}
	case fOctets:
		return OctetString{Data: bytes.Repeat([]byte{'x'}, int(gv.Variation()))}
	case fBCD:
		return BCD{Value: 1234}
	case fUint8:
		return UnsignedInteger{Value: 200}
	case fDataSetChars:
		return DataSetCharacteristics{Flags: DataSetReadable | DataSetStatic | DataSetEvents}
	case fSecStat:
		return SecurityStatistic{Flags: FlagOnline, Association: 1, Value: 99, Time: ts}
	case fAttribute:
		return StringAttribute("go-dnp3")
	case fRaw:
		return Raw{Data: []byte{1, 2, 3}}
	case fFileAuth:
		return FileAuthentication{UserName: "user", Password: "secret", AuthKey: 0xDEADBEEF}
	case fFileCommand:
		return FileCommand{Name: "/log/events.csv", Created: 1_700_000_000_000, Permissions: PermOwnerRead | PermOwnerWrite,
			AuthKey: 7, Size: 4096, Mode: FileModeRead, MaxBlockSize: 1024, RequestID: 3}
	case fFileCommandStatus:
		return FileCommandStatus{Handle: 0x1234, Size: 4096, MaxBlockSize: 1024, RequestID: 3, Status: FileSuccess, Text: "ok"}
	case fFileTransport:
		return FileTransport{Handle: 0x1234, Block: 7, Last: true, Data: []byte("data")}
	case fFileTransportStatus:
		return FileTransportStatus{Handle: 0x1234, Block: 7, Last: true, Status: FileBlockSequence}
	case fFileDescriptor:
		return FileDescriptor{Name: "events.csv", Type: FileTypeSimple, Size: 4096, Created: 5, Permissions: 0o644, RequestID: 3}
	case fFileSpec:
		return FileSpecification{Name: "config.xml"}
	case fAuth:
		switch gv.Variation() {
		case 1:
			return AuthChallenge{CSQ: 1, User: 1, MAC: MACHMACSHA256Trunc16, Reason: ReasonCritical, Data: []byte{1, 2, 3, 4}}
		case 2:
			return AuthReply{CSQ: 1, User: 1, MAC: bytes.Repeat([]byte{9}, 16)}
		case 3:
			return AuthAggressiveMode{CSQ: 5, User: 1}
		case 4:
			return AuthSessionKeyStatusRequest{User: 1}
		case 5:
			return AuthSessionKeyStatus{KSQ: 2, User: 1, KeyWrap: KeyWrapAES256, Status: KeyStatusOK, MAC: MACHMACSHA256Trunc16,
				Challenge: []byte{1, 2, 3, 4}, MACValue: bytes.Repeat([]byte{7}, 16)}
		case 6:
			return AuthSessionKeyChange{KSQ: 2, User: 1, WrappedKeys: bytes.Repeat([]byte{5}, 40)}
		case 7:
			return AuthError{CSQ: 3, User: 1, Association: 2, Code: AuthErrAuthenticationFailed, Time: 77, Text: []byte("bad")}
		case 8:
			return AuthUserCertificate{KeyChangeMethod: 4, CertificateType: 1, Certificate: []byte{0x30, 0x82}}
		case 9:
			return AuthMAC{MAC: bytes.Repeat([]byte{3}, 16)}
		case 10:
			return AuthUserStatusChange{KeyChangeMethod: 3, Operation: 1, SCS: 9, Role: 2, RoleExpiry: 30,
				UserName: "op", PublicKey: []byte{1}, Certification: []byte{2, 3}}
		case 11:
			return AuthUpdateKeyChangeRequest{KeyChangeMethod: 3, UserName: "op", Challenge: []byte{1, 2}}
		case 12:
			return AuthUpdateKeyChangeReply{KSQ: 4, User: 2, Challenge: []byte{3, 4}}
		case 13:
			return AuthUpdateKeyChange{KSQ: 4, User: 2, EncryptedKey: []byte{5, 6, 7}}
		case 14:
			return AuthUpdateKeyChangeSignature{Signature: []byte{8}}
		case 15:
			return AuthUpdateKeyChangeConfirmation{MAC: []byte{9, 9}}
		}
	default:
	}
	return nil
}

// allVariations returns every registered variation plus representatives
// of the open-ended groups.
func allVariations() []GroupVariation {
	var out []GroupVariation
	for gv := range table {
		out = append(out, gv)
	}
	return append(out, GV(0, AttrManufacturerName), GV(0, AttrNumBinaryInputs), GV(110, 5), GV(111, 1), GV(112, 255), GV(113, 3))
}

func roundTrip(t *testing.T, fc FunctionCode, hs ...Header) *Fragment {
	t.Helper()
	f := &Fragment{Control: SingleControl(1), Function: fc, IIN: IINNeedTime, Headers: hs}
	b, err := f.Encode()
	if err != nil {
		t.Fatalf("encode %v: %v", hs[len(hs)-1].String(), err)
	}
	d, err := Decode(b)
	if err != nil {
		t.Fatalf("decode %v: %v\n% X", hs[len(hs)-1].String(), err, b)
	}
	if !reflect.DeepEqual(d.Headers, f.Headers) {
		t.Fatalf("round trip of %s\n got %#v\nwant %#v", hs[len(hs)-1].GV, d.Headers, f.Headers)
	}
	if re := mustEncode(t, d); !bytes.Equal(re, b) {
		t.Fatalf("re-encode differs for %s", hs[len(hs)-1].GV)
	}
	return d
}

func TestRoundTripEveryVariation(t *testing.T) {
	cto := Counted(G51V1, CTO{Time: 1_700_000_000_000})
	for _, gv := range allVariations() {
		d := lookup(gv)
		if d.fam == fNone || d.fam == fAny {
			continue
		}
		if gv.Name() == "" {
			t.Errorf("%s has no name", gv)
		}
		vals := []Value{sample(gv, d, 0), sample(gv, d, 1), sample(gv, d, 2)}
		var pre []Header
		if d.time == tRel {
			pre = []Header{cto}
		}
		with := func(h Header) []Header { return append(append([]Header(nil), pre...), h) }

		// Normalise headers the way the decoder fills them in.
		norm := func(h Header) Header {
			if h.Qualifier.IsRange() {
				h.Start, h.Stop = h.Objects[0].Index, h.Objects[len(h.Objects)-1].Index
			}
			if h.Qualifier.IsCount() {
				h.Count = uint32(len(h.Objects))
			}
			return h
		}
		switch {
		case d.freeFormat(gv):
			roundTrip(t, FuncResponse, with(norm(FreeFormat(gv, vals...)))...)
			h := FreeFormat(gv, vals[0])
			h.Qualifier = Qual1ByteSizeFreeFormat
			roundTrip(t, FuncWrite, with(norm(h))...)
		case d.bits() > 0:
			roundTrip(t, FuncResponse, with(norm(Ranged(gv, 3, vals...)))...)
			roundTrip(t, FuncWrite, with(norm(Ranged(gv, 300, vals...)))...)
		default:
			roundTrip(t, FuncResponse, with(norm(Ranged(gv, 10, vals...)))...)
			roundTrip(t, FuncResponse, with(norm(Ranged(gv, 70000, vals...)))...)
			objs := []Object{{9, vals[0]}, {2, vals[1]}, {40000, vals[2]}}
			roundTrip(t, FuncResponse, with(norm(Indexed(gv, objs...)))...)
			roundTrip(t, FuncResponse, with(norm(Indexed(gv, objs[:2]...)))...)
			roundTrip(t, FuncResponse, with(norm(Counted(gv, vals...)))...)
			if !d.selfSized() {
				roundTrip(t, FuncResponse, with(norm(FreeFormat(gv, vals...)))...)
			}
		}
	}
}

func TestRequestHeadersWithoutObjects(t *testing.T) {
	hs := []Header{
		AllObjects(G1V0),
		IndexRange(G30V5, 0, 9),
		IndexRange(G20V1, 0, 300),
		IndexRange(G21V1, 0, 70000),
		CountOf(G2V0, 5),
		CountOf(G32V0, 1000),
		{GV: G2V1, Qualifier: Qual2ByteIndexCount, Count: 0},
		AllObjects(GV(0, AttrAllAttributes)),
		AllObjects(GV(110, 0)),
		IndexList(G30V0, 3, 5, 9),
		IndexList(G1V2, 1000),
	}
	roundTrip(t, FuncRead, hs...)
	roundTrip(t, FuncAssignClass, AllObjects(G60V2), IndexRange(G1V0, 0, 3))
	roundTrip(t, FuncEnableUnsolicited, ClassHeaders(1, 2, 3)...)
	// FREEZE_AT_TIME carries its time object, then names the counters.
	roundTrip(t, FuncFreezeAtTime, Counted(G50V2, AbsoluteTime{Time: 99, Interval: 1000}), AllObjects(G20V0))
	// Aggressive mode objects travel inside a READ.
	roundTrip(t, FuncRead, Counted(G120V3, AuthAggressiveMode{CSQ: 1, User: 1}), ClassHeaders(0)[0],
		FreeFormat(G120V9, AuthMAC{MAC: []byte{1, 2}}))
}

func TestRelativeTime(t *testing.T) {
	base := Timestamp(1_700_000_000_000)
	h := Indexed(G2V3, Object{1, Binary{Value: true, Time: base + 10}}, Object{2, Binary{Time: base + 65535}})
	roundTrip(t, FuncResponse, Counted(G51V2, CTO{Time: base}), h)

	f := &Fragment{Function: FuncResponse, Headers: []Header{h}}
	if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("no CTO: %v", err)
	}
	f.Headers = []Header{Counted(G51V1, CTO{Time: base}), Indexed(G2V3, Object{1, Binary{Time: base + 70000}})}
	if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("out of range: %v", err)
	}
	if _, err := Decode(unhex(t, "C0 81 00 00 02 03 17 01 01 01 0A 00")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("decode without CTO: %v", err)
	}
}

func TestAnalogClamping(t *testing.T) {
	cases := []struct {
		gv    GroupVariation
		in    float64
		out   float64
		flags Flags
	}{
		{G30V2, 40000, 32767, FlagOnline | FlagOverRange},
		{G30V2, -40000, -32768, FlagOnline | FlagOverRange},
		{G30V1, 1.6, 2, FlagOnline},
		{G30V1, math.NaN(), 0, FlagOnline | FlagOverRange},
		{G30V5, 1e40, math.MaxFloat32, FlagOnline | FlagOverRange},
		{G30V5, math.Inf(-1), math.Inf(-1), FlagOnline},
		{G30V4, 1e12, math.MaxInt16, 0},
	}
	for _, c := range cases {
		f := &Fragment{Function: FuncResponse, Headers: []Header{Ranged(c.gv, 0, Analog{Value: c.in, Flags: FlagOnline})}}
		d, err := Decode(mustEncode(t, f))
		if err != nil {
			t.Fatal(err)
		}
		got := d.Headers[0].Objects[0].Value.(Analog)
		want := c.flags
		if c.gv == G30V4 {
			want = 0 // no flags in this variation
		}
		if (got.Value != c.out && !(math.IsInf(c.out, 0) && got.Value == c.out)) || got.Flags != want {
			t.Errorf("%s %v: got %v %s, want %v %s", c.gv, c.in, got.Value, got.Flags, c.out, want)
		}
	}
	// A set-point that does not fit is refused rather than clamped.
	f := &Fragment{Function: FuncDirectOperate, Headers: []Header{Indexed(G41V2, Object{0, AnalogOutput{Value: 1e6}})}}
	if _, err := f.Encode(); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("set-point: %v", err)
	}
	// 16-bit counters carry the low 16 bits.
	f = &Fragment{Function: FuncResponse, Headers: []Header{Ranged(G20V2, 0, Counter{Value: 0x12345})}}
	d, _ := Decode(mustEncode(t, f))
	if v := d.Headers[0].Objects[0].Value.(Counter).Value; v != 0x2345 {
		t.Fatalf("16-bit counter %#x", v)
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"one octet", "C0", ErrMalformed},
		{"response without IIN", "C0 81 00", ErrMalformed},
		{"unknown function", "C0 63", ErrUnknownFunction},
		{"short header", "C0 01 3C 02", ErrMalformed},
		{"reserved qualifier bit", "C0 01 3C 02 86", ErrInvalidQualifier},
		{"reserved range code", "C0 01 3C 02 0A", ErrInvalidQualifier},
		{"prefix with range", "C0 01 01 02 10 00 01", ErrInvalidQualifier},
		{"start after stop", "C0 01 01 02 00 05 01", ErrMalformed},
		{"short range", "C0 01 01 02 01 00", ErrMalformed},
		{"short count", "C0 01 02 00 08 01", ErrMalformed},
		{"unknown object", "C0 81 00 00 C8 01 00 00 00 FF", ErrUnknownObject},
		{"huge range", "C0 81 00 00 1E 01 02 00 00 00 00 FF FF FF FF", ErrMalformed},
		{"huge count", "C0 81 00 00 1E 01 39 FF FF FF FF 01 00 00 00", ErrMalformed},
		{"packed indexed", "C0 81 00 00 01 01 17 01 00 01", ErrInvalidQualifier},
		{"free-format without size", "C0 81 00 00 46 05 17 01 00 01", ErrInvalidQualifier},
		{"short object", "C0 81 00 00 1E 01 00 00 00 01 02", ErrMalformed},
		{"short free-format size", "C0 81 00 00 46 05 5B 01 10 00 01", ErrMalformed},
		{"free-format wrong fixed size", "C0 20 78 04 5B 01 03 00 01 00 00", ErrMalformed},
		{"bad BCD", "C0 81 00 00 65 01 07 01 AB 00", ErrMalformed},
		{"bad file offset", "C0 81 00 00 46 07 5B 01 14 00 13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", ErrMalformed},
		{"short index list", "C0 01 1E 01 17 03 01 02", ErrMalformed},
		{"attribute too short", "C0 81 00 00 00 FC 00 00 00 01 05 41", ErrMalformed},
	}
	for _, c := range cases {
		_, err := Decode(unhex(t, c.hex))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// The header of an undecodable fragment is still returned.
	f, err := Decode(unhex(t, "C7 02 1E 01 00 00 00"))
	if err == nil || f == nil || f.Control.Seq != 7 || f.Function != FuncWrite {
		t.Fatalf("partial fragment %v, %v", f, err)
	}
}

func TestEncodeErrors(t *testing.T) {
	cases := []struct {
		name string
		h    Header
		want error
	}{
		{"wrong type", Ranged(G30V1, 0, Binary{}), ErrInvalidValue},
		{"gap in range", Header{GV: G30V1, Qualifier: Qual1ByteStartStop, Objects: []Object{{0, Analog{}}, {2, Analog{}}}}, ErrInvalidValue},
		{"range too wide", Header{GV: G30V1, Qualifier: Qual1ByteStartStop, Objects: []Object{{255, Analog{}}, {256, Analog{}}}}, ErrInvalidValue},
		{"index too large", Header{GV: G30V1, Qualifier: Qual1ByteIndexCount, Objects: []Object{{256, Analog{}}}}, ErrInvalidValue},
		{"packed indexed", Header{GV: G1V1, Qualifier: Qual1ByteIndexCount, Objects: []Object{{1, Binary{}}}}, ErrInvalidQualifier},
		{"packed wrong type", Ranged(G1V1, 0, DoubleBitBinary{}), ErrInvalidValue},
		{"class with objects", Ranged(G60V1, 0, Binary{}), ErrInvalidValue},
		{"all with objects", Header{GV: G30V1, Qualifier: QualAll, Objects: []Object{{0, Analog{}}}}, ErrInvalidValue},
		{"file without free format", Indexed(G70V5, Object{0, FileTransport{}}), ErrInvalidQualifier},
		{"invalid qualifier", Header{GV: G30V1, Qualifier: 0x0C}, ErrInvalidQualifier},
		{"unknown with objects", Header{GV: GV(200, 1), Qualifier: Qual1ByteCount, Objects: []Object{{0, Raw{}}}}, ErrUnknownObject},
		{"octet string length", Ranged(GV(110, 4), 0, OctetString{Data: []byte{1}}), ErrInvalidValue},
		{"bcd digits", Counted(G101V1, BCD{Value: 123456}), ErrInvalidValue},
		{"delay range", Counted(G52V2, TimeDelay{Delay: time.Hour}), ErrInvalidValue},
		{"block number", FreeFormat(G70V5, FileTransport{Block: lastBlockBit}), ErrInvalidValue},
		{"auth variation", FreeFormat(G120V1, AuthReply{}), ErrInvalidValue},
		{"bad range", Header{GV: G1V0, Qualifier: Qual1ByteStartStop, Start: 5, Stop: 1}, ErrInvalidValue},
		{"count too large", Header{GV: G2V0, Qualifier: Qual1ByteCount, Count: 300}, ErrInvalidValue},
		{"free-format too large", Header{GV: G70V5, Qualifier: Qual1ByteSizeFreeFormat, Objects: []Object{{0, FileTransport{Data: make([]byte, 300)}}}}, ErrInvalidValue},
		{"index list with range qualifier", Header{GV: G30V1, Qualifier: Qual1ByteStartStop, Objects: []Object{{Index: 1}}}, ErrInvalidValue},
		{"index list index too large", Header{GV: G30V1, Qualifier: Qual1ByteIndexCount, Objects: []Object{{Index: 300}}}, ErrInvalidValue},
		{"attribute too long", Ranged(GV(0, 250), 0, Attribute{Type: AttrVisibleString, Data: make([]byte, 256)}), ErrInvalidValue},
	}
	for _, c := range cases {
		f := &Fragment{Function: FuncResponse, Headers: []Header{c.h}}
		if _, err := f.Encode(); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestStringsAndHelpers(t *testing.T) {
	if FuncDirectOperate.String() != "DIRECT_OPERATE" || FunctionCode(99).String() != "FUNCTION(99)" {
		t.Error("FunctionCode.String")
	}
	if !FuncDirectOperateNoAck.NoAck() || FuncRead.NoAck() || !FuncUnsolicitedResponse.IsResponse() {
		t.Error("FunctionCode predicates")
	}
	iin := IINDeviceRestart | IINNeedTime | IINObjectUnknown
	if iin.String() != "NEED_TIME|DEVICE_RESTART|OBJECT_UNKNOWN" || !iin.Has(IINNeedTime) || iin.IIN1() != 0x90 || iin.IIN2() != 0x02 {
		t.Errorf("IIN %s %x %x", iin, iin.IIN1(), iin.IIN2())
	}
	if IINBit(IINDeviceRestart) != 7 || IINBit(IINConfigCorrupt) != 13 {
		t.Error("IINBit")
	}
	c := Control{FIR: true, CON: true, UNS: true, Seq: 9}
	if ParseControl(c.Byte()) != c || c.String() != "FIR CON UNS seq=9" || NextSeq(15) != 0 {
		t.Errorf("Control %s", c)
	}
	if G30V5.String() != "g30v5" || G30V5.Name() != "Analog Input - Single-precision With Flag" {
		t.Errorf("GV %s %q", G30V5, G30V5.Name())
	}
	if n, ok := G30V5.Size(); !ok || n != 5 {
		t.Error("Size")
	}
	if _, ok := G1V1.Size(); ok {
		t.Error("packed size")
	}
	if !G32V0.IsEvent() || G30V1.IsEvent() || !GV(111, 4).IsEvent() || GV(200, 1).Known() {
		t.Error("IsEvent/Known")
	}
	if GV(0, 0).Name() == "" || GV(110, 0).Name() == "" || GV(0, 254).Name() == "" {
		t.Error("open-ended names")
	}
	if Flags(0x23).String() != "ONLINE|RESTART|BIT5" || DoubleBitOn.String() != "DETERMINED_ON" {
		t.Error("flag strings")
	}
	if StatusNoSelect.String() != "NO_SELECT" || CommandStatus(50).String() != "STATUS(50)" {
		t.Error("CommandStatus")
	}
	if Permissions(0o754).String() != "rwxr-xr--" || FileNotFound.String() != "FILE_NOT_FOUND" {
		t.Error("file strings")
	}
	ts := TimestampOf(time.Date(2024, 1, 2, 3, 4, 5, 6e6, time.UTC))
	if ts.String() != "2024-01-02T03:04:05.006Z" || TimestampOf(time.Unix(-5, 0)) != 0 {
		t.Errorf("Timestamp %s", ts)
	}
	if Now() == 0 {
		t.Error("Now")
	}
	if MACHMACSHA256Trunc16.Len() != 16 || MACAESGMAC.String() != "AES-GMAC" || KeyStatusOK.String() != "OK" {
		t.Error("auth enums")
	}
	h := IndexRange(G30V1, 0, 9)
	if h.String() != "g30v1 q=0x00 [0..9]" {
		t.Errorf("Header.String %q", h.String())
	}
	if n, err := h.EncodedLen(); err != nil || n != 5 {
		t.Errorf("EncodedLen %d %v", n, err)
	}
	if OctetStringGV(110, 12) != GV(110, 12) {
		t.Error("OctetStringGV")
	}
}

func TestAttributes(t *testing.T) {
	for _, c := range []struct {
		a    Attribute
		want any
	}{
		{UintAttribute(7), uint32(7)}, {UintAttribute(700), uint32(700)}, {UintAttribute(70000), uint32(70000)},
		{IntAttribute(-5), int32(-5)}, {FloatAttribute(2.5), 2.5},
	} {
		var got any
		var err error
		switch c.a.Type {
		case AttrUnsignedInt:
			got, err = c.a.Uint()
		case AttrSignedInt:
			got, err = c.a.Int()
		case AttrFloat:
			got, err = c.a.Float()
		default:
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %v %v", c.a.Type, got, err)
		}
	}
	entries := make([]AttributeListEntry, 200)
	for i := range entries {
		entries[i] = AttributeListEntry{Variation: uint8(i), Writable: i%3 == 0}
	}
	l := ListAttribute(entries...)
	if l.Type != AttrExtList {
		t.Fatal("expected extended list")
	}
	d := roundTrip(t, FuncResponse, Ranged(GV(0, AttrListOfVariations), 0, l))
	got, err := d.Headers[0].Objects[0].Value.(Attribute).List()
	if err != nil || !reflect.DeepEqual(got, entries) {
		t.Fatal("list round trip")
	}
	roundTrip(t, FuncResponse, Ranged(GV(0, AttrDeviceLatitude), 0, FloatAttribute(51.2)))
	roundTrip(t, FuncWrite, Ranged(GV(0, AttrUserLocation), 0, TimeAttribute(5)))
	if StringAttribute("x").Text() != "x" || AttrVisibleString.String() != "VSTR" {
		t.Error("Text")
	}
	if _, err := StringAttribute("x").Uint(); !errors.Is(err, ErrInvalidValue) {
		t.Error("Uint of string")
	}
}

func FuzzDecode(f *testing.F) {
	seeds := []string{
		"C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06",
		"C3 81 80 00 01 02 00 00 01 81 01 1E 01 00 05 05 01 E8 03 00 00",
		"C5 05 0C 01 28 01 00 03 00 03 01 64 00 00 00 00 00 00 00 00",
		"C0 81 00 00 33 01 07 01 00 00 00 00 00 00 02 03 17 01 01 01 0A 00",
		"C0 81 00 00 46 05 5B 01 0C 00 34 12 00 00 07 00 00 80 64 61 74 61",
		"C0 81 00 00 00 FF 00 00 00 FE 04 01 00 02 01",
	}
	for _, s := range seeds {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Decode(b)
		if err != nil {
			return
		}
		e1, err := fr.Encode()
		if err != nil {
			t.Fatalf("decoded fragment does not encode: %v\n%v", err, fr)
		}
		fr2, err := Decode(e1)
		if err != nil {
			t.Fatalf("re-encoded fragment does not decode: %v", err)
		}
		e2, err := fr2.Encode()
		if err != nil || !bytes.Equal(e1, e2) {
			t.Fatalf("encoding not stable:\n% X\n% X", e1, e2)
		}
	})
}

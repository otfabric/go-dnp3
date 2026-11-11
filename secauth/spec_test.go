// SPDX-License-Identifier: MIT

package secauth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

// Spec tests of the Secure Authentication primitives (IEEE 1815-2012
// clause 7, A.45). Page numbers are the printed ones.

// The golden vectors below were computed outside this library, with
// Python's hmac module and checked with "openssl dgst -sha256 -mac HMAC",
// from octet strings written out by hand:
//
// Key: the 32 ASCII octets "pre-shared session key 32 octets".
//
// Challenge (outstation to master, AUTHENTICATE_RESP):
//
//	C3          AC: FIR FIN, sequence 3
//	83          FC: AUTHENTICATE_RESP
//	00 00       IIN
//	78 01 5B 01 0C 00   g120v1, qualifier 0x5B, count 1, size 12
//	07 00 00 00 CSQ 7
//	00 00       USR 0
//	04          MAL 4: HMAC-SHA-256 truncated to 16 octets
//	01          reason 1: CRITICAL
//	01 02 03 04 challenge data
//
// Aggressive mode DIRECT_OPERATE (master to outstation), every octet
// before the MAC value:
//
//	C4          AC: FIR FIN, sequence 4
//	05          FC: DIRECT_OPERATE
//	78 03 07 01 g120v3, qualifier 0x07, count 1
//	08 00 00 00 CSQ 8: the challenge's plus one (clause 7.5.2.3.3 d)
//	01 00       USR 1
//	0C 01 17 01 00      g12v1, qualifier 0x17, count 1, index 0
//	03 01 00000000 00000000 00   CROB: LATCH_ON, count 1, on 0, off 0, status 0
//	78 09 5B 01 10 00   g120v9, qualifier 0x5B, count 1, size 16
//
// MAC value: HMAC-SHA-256(key, challenge || request octets above), the
// leftmost 16 octets.
const (
	goldenKey       = "pre-shared session key 32 octets"
	goldenChallenge = "c383000078015b010c00070000000000040101020304"
	goldenAggrPre   = "c405780307010800000001000c01170100030100000000000000000078095b011000"
	goldenAggrMAC   = "4466436ed22af51512d682638f8f7689"
	// goldenLegacyMAC is the MAC over the request up to, not including,
	// the g120v9 object header: what earlier go-dnp3 releases computed.
	goldenLegacyMAC = "a167c08094e5b67f84dd8c77a479b977"
	// goldenCritical is a DIRECT_OPERATE (AC C3, FC 05) with the same
	// CROB; goldenReplyMAC is HMAC-SHA-256(key, challenge || critical)
	// truncated to 16 octets, goldenReplySHA1 the HMAC-SHA-1 of the same
	// input truncated to 10.
	goldenCritical  = "c3050c011701000301000000000000000000"
	goldenReplyMAC  = "3385b75b25b1c09872e181b48dd62a65"
	goldenReplySHA1 = "a747af6fd54852280dbf"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSpecTableA_9_AggressiveModeMAC: IEEE 1815-2012 A.45.9 and Table A-9,
// p.742 and p.784: the MAC of an aggressive mode request is computed over
// the last challenge received and the whole aggressive mode fragment, from
// the application control octet to the octet before the MAC value: the
// g120v9 object header and size prefix are included. A.45.3.2.3, p.725:
// g120v3 first, qualifier 0x07 count 1; A.45.9.1, p.741: g120v9 last,
// qualifier 0x5B.
func TestSpecTableA_9_AggressiveModeMAC(t *testing.T) {
	key, ch, pre := []byte(goldenKey), unhex(t, goldenChallenge), unhex(t, goldenAggrPre)
	mac, err := MAC(app.MACHMACSHA256Trunc16, key, AuthData(ch, pre))
	if err != nil || hex.EncodeToString(mac) != goldenAggrMAC {
		t.Fatalf("aggressive mode MAC %x, want %s (%v)", mac, goldenAggrMAC, err)
	}
	legacy, _ := MAC(app.MACHMACSHA256Trunc16, key, AuthData(ch, pre[:len(pre)-6]))
	if hex.EncodeToString(legacy) != goldenLegacyMAC || bytes.Equal(legacy, mac) {
		t.Fatalf("legacy MAC %x", legacy)
	}
	// The library's encoding of the same request has these octets.
	f := &app.Fragment{Control: app.SingleControl(4), Function: app.FuncDirectOperate, Headers: []app.Header{
		app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: 8, User: 1}),
		app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}}),
		app.FreeFormat(app.G120V9, app.AuthMAC{MAC: mac}),
	}}
	b, err := f.Encode()
	if err != nil || !bytes.Equal(b, append(slices.Clone(pre), mac...)) {
		t.Fatalf("encoding %x, want %s%s (%v)", b, goldenAggrPre, goldenAggrMAC, err)
	}
	// The challenge decodes as written.
	cf, err := app.Decode(ch)
	if err != nil {
		t.Fatal(err)
	}
	if v := cf.Headers[0].Objects[0].Value.(app.AuthChallenge); v.CSQ != 7 || v.User != 0 || v.MAC != app.MACHMACSHA256Trunc16 || v.Reason != app.ReasonCritical {
		t.Fatalf("challenge %+v", v)
	}
}

// TestSpecTableA_3_ReplyMAC: A.45.2 and Table A-3, p.723: the MAC of a
// challenge reply is computed over the challenge message and the critical
// fragment, each exactly as sent, in that order; clause 7.6.1.1, p.241:
// HMAC-SHA-256 truncated to 16 (or 8 on serial links) and HMAC-SHA-1
// truncated to 10.
func TestSpecTableA_3_ReplyMAC(t *testing.T) {
	key, ch, critical := []byte(goldenKey), unhex(t, goldenChallenge), unhex(t, goldenCritical)
	for alg, want := range map[app.MACAlgorithm]string{
		app.MACHMACSHA256Trunc16: goldenReplyMAC,
		app.MACHMACSHA256Trunc8:  goldenReplyMAC[:16],
		app.MACHMACSHA1Trunc10:   goldenReplySHA1,
	} {
		mac, err := MAC(alg, key, AuthData(ch, critical))
		if err != nil || hex.EncodeToString(mac) != want {
			t.Errorf("%s reply MAC %x, want %s (%v)", alg, mac, want, err)
		}
	}
	// The order matters.
	swapped, _ := MAC(app.MACHMACSHA256Trunc16, key, AuthData(critical, ch))
	if hex.EncodeToString(swapped) == goldenReplyMAC {
		t.Fatal("reply MAC independent of the order")
	}
}

// TestSpec7_6_1_1_1_HMACSHA1: clause 7.6.1.1.1, p.241: HMAC-SHA-1 truncated
// to the leftmost 8 or 10 octets (the 4-octet truncation of earlier
// versions is obsolete). RFC 2202 test case 2.
func TestSpec7_6_1_1_1_HMACSHA1(t *testing.T) {
	const full = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
	for alg, n := range map[app.MACAlgorithm]int{app.MACHMACSHA1Trunc4: 4, app.MACHMACSHA1Trunc8: 8, app.MACHMACSHA1Trunc10: 10} {
		mac, err := MAC(alg, []byte("Jefe"), []byte("what do ya want for nothing?"))
		if err != nil || hex.EncodeToString(mac) != full[:2*n] {
			t.Errorf("%s = %x, want %s (%v)", alg, mac, full[:2*n], err)
		}
	}
}

// TestSpecTable7_6_DefaultThresholds: Table 7-6, p.206: the default event
// threshold of each security statistic, by index.
func TestSpecTable7_6_DefaultThresholds(t *testing.T) {
	want := []uint16{3, 5, 5, 3, 3, 100, 100, 100, 100, 10, 2, 10, 100, 10, 5, 1, 1, 3}
	if len(want) != int(NumStatistics) {
		t.Fatalf("%d statistics", NumStatistics)
	}
	for i, w := range want {
		if got := Statistic(i).DefaultThreshold(); got != w {
			t.Errorf("%s: threshold %d, want %d", Statistic(i), got, w)
		}
	}
	if NumStatistics.DefaultThreshold() != 0 {
		t.Fatal("threshold of a statistic past the table")
	}
}

// TestSpecTable7_7_MandatoryCritical: Table 7-7, p.209 and clause
// 7.5.2.3.2 a), p.208: the function codes marked MANDATORY shall be
// critical; DefaultCritical includes them all.
func TestSpecTable7_7_MandatoryCritical(t *testing.T) {
	want := []app.FunctionCode{2, 3, 4, 5, 6, 13, 14, 16, 17, 18, 19, 20, 21, 24, 25, 26, 27, 28, 29, 30, 31}
	got := slices.Clone(MandatoryCritical)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("mandatory critical %v, want %v", got, want)
	}
	for _, fc := range MandatoryCritical {
		if !slices.Contains(DefaultCritical, fc) {
			t.Errorf("DefaultCritical lacks %s", fc)
		}
	}
	for _, fc := range []app.FunctionCode{app.FuncRead, app.FuncConfirm, app.FuncAuthRequest, app.FuncAuthRequestNoAck} {
		if slices.Contains(DefaultCritical, fc) {
			t.Errorf("DefaultCritical has %s", fc)
		}
	}
}

// TestSpecTableA_7_KeyWrapData: A.45.6, Tables A-5 and A-7, p.731: the key
// wrap input is the session key length (2 octets, little-endian), the
// control and the monitoring direction session keys, the key status
// message most recently received, KSQ first, without its MAC, and zero
// padding to a multiple of 8 octets. With 128-bit keys and 4 octets of
// challenge data that is 2+16+16+15+7 = 56 octets, and the AES key wrap
// output 64.
func TestSpecTableA_7_KeyWrapData(t *testing.T) {
	st := app.AuthSessionKeyStatus{KSQ: 1, User: 1, KeyWrap: app.KeyWrapAES128, Status: app.KeyStatusNotInit, Challenge: []byte{1, 2, 3, 4}}
	msg, err := app.AppendObjectValue(nil, app.G120V5, st)
	if err != nil || len(msg) != 15 || binary.LittleEndian.Uint32(msg) != 1 {
		t.Fatalf("key status message %x (%v)", msg, err)
	}
	control, monitoring := bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)
	plain, err := KeyChangeData(control, monitoring, msg)
	if err != nil || len(plain) != 56 {
		t.Fatalf("key wrap data of %d octets (%v)", len(plain), err)
	}
	if binary.LittleEndian.Uint16(plain) != 16 || !bytes.Equal(plain[2:18], control) || !bytes.Equal(plain[18:34], monitoring) ||
		!bytes.Equal(plain[34:49], msg) || !bytes.Equal(plain[49:], make([]byte, 7)) {
		t.Fatalf("key wrap data layout %x", plain)
	}
	wrapped, err := KeyWrap(bytes.Repeat([]byte{0x33}, 16), plain)
	if err != nil || len(wrapped) != 64 {
		t.Fatalf("wrapped key data of %d octets (%v)", len(wrapped), err)
	}
}

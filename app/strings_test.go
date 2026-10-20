// SPDX-License-Identifier: MIT

package app

import (
	"strings"
	"testing"
)

// TestEnumStrings checks every named value of the enumerations has a
// name, and unnamed values a numeric fallback.
func TestEnumStrings(t *testing.T) {
	type stringer interface{ String() string }
	check := func(kind string, named []stringer, unnamed stringer, prefix string) {
		t.Helper()
		seen := map[string]bool{}
		for _, v := range named {
			s := v.String()
			if s == "" || strings.HasPrefix(s, prefix) || seen[s] {
				t.Errorf("%s: %q", kind, s)
			}
			seen[s] = true
		}
		if s := unnamed.String(); !strings.HasPrefix(s, prefix) {
			t.Errorf("%s fallback: %q", kind, s)
		}
	}
	var dbits []stringer
	for _, d := range []DoubleBit{DoubleBitIntermediate, DoubleBitOff, DoubleBitOn, DoubleBitIndeterminate} {
		dbits = append(dbits, d)
	}
	if DoubleBit(7).String() != "INDETERMINATE" || len(dbits) != 4 {
		t.Error("DoubleBit")
	}
	var ops, tccs, modes, fstat, mac, keys, errs, attrs []stringer
	for _, o := range []OpType{OpNul, OpPulseOn, OpPulseOff, OpLatchOn, OpLatchOff} {
		ops = append(ops, o)
	}
	check("OpType", ops, OpType(9), "OP(")
	for _, v := range []TripClose{TCCNul, TCCClose, TCCTrip} {
		tccs = append(tccs, v)
	}
	check("TripClose", tccs, TripClose(3), "TCC(")
	for _, v := range []FileMode{FileModeNull, FileModeRead, FileModeWrite, FileModeAppend} {
		modes = append(modes, v)
	}
	check("FileMode", modes, FileMode(9), "MODE(")
	for v := range fileStatusNames {
		fstat = append(fstat, v)
	}
	check("FileStatus", fstat, FileStatus(77), "FILE_STATUS(")
	for _, v := range []MACAlgorithm{MACNone, MACHMACSHA1Trunc4, MACHMACSHA1Trunc10, MACHMACSHA256Trunc8, MACHMACSHA256Trunc16, MACHMACSHA1Trunc8, MACAESGMAC} {
		mac = append(mac, v)
	}
	check("MACAlgorithm", mac, MACAlgorithm(99), "MAC(")
	for _, v := range []KeyStatus{KeyStatusOK, KeyStatusNotInit, KeyStatusCommFail, KeyStatusAuthFail} {
		keys = append(keys, v)
	}
	check("KeyStatus", keys, KeyStatus(9), "KEY_STATUS(")
	for _, v := range []AuthErrorCode{AuthErrAuthenticationFailed, AuthErrAggressiveModeNotSupported, AuthErrMACNotSupported,
		AuthErrKeyWrapNotSupported, AuthErrAuthorizationFailed, AuthErrUpdateKeyMethodNotPermitted, AuthErrInvalidSignature,
		AuthErrInvalidCertification, AuthErrUnknownUser, AuthErrMaxSessionKeyStatusRequests} {
		errs = append(errs, v)
	}
	check("AuthErrorCode", errs, AuthErrorCode(99), "AUTH_ERROR(")
	for _, v := range []AttrType{AttrVisibleString, AttrUnsignedInt, AttrSignedInt, AttrFloat, AttrOctetString, AttrBitString, AttrTime, AttrList, AttrExtList} {
		attrs = append(attrs, v)
	}
	check("AttrType", attrs, AttrType(99), "ATTR_TYPE(")
	for _, m := range []MACAlgorithm{MACNone, 99} {
		if m.Len() != 0 {
			t.Error("MAC length of unknown algorithm")
		}
	}
	if (&Fragment{Function: FuncResponse}).HeaderLen() != 4 || (&Fragment{Function: FuncRead}).HeaderLen() != 2 {
		t.Error("HeaderLen")
	}
	if !FuncRead.Defined() || FunctionCode(99).Defined() {
		t.Error("Defined")
	}
	if s := (CROB{Op: OpLatchOn, TripClose: TCCTrip, Queue: true, Clear: true}).String(); !strings.Contains(s, "TRIP/LATCH_ON queue clear") {
		t.Errorf("CROB string %q", s)
	}
}

// TestValueMarkers touches every implementation of the closed Value
// interface.
func TestValueMarkers(t *testing.T) {
	for _, v := range []Value{
		Binary{}, DoubleBitBinary{}, BinaryCommandEvent{}, CROB{}, Counter{}, Analog{}, AnalogDeadband{}, AnalogOutput{},
		AnalogCommandEvent{}, AbsoluteTime{}, CTO{}, TimeDelay{}, OctetString{}, BCD{}, UnsignedInteger{}, SecurityStatistic{},
		Raw{}, Attribute{}, FileAuthentication{}, FileCommand{}, FileCommandStatus{}, FileTransport{}, FileTransportStatus{},
		FileDescriptor{}, FileSpecification{}, AuthChallenge{}, AuthReply{}, AuthAggressiveMode{}, AuthSessionKeyStatusRequest{},
		AuthSessionKeyStatus{}, AuthSessionKeyChange{}, AuthError{}, AuthUserCertificate{}, AuthMAC{}, AuthUserStatusChange{},
		AuthUpdateKeyChangeRequest{}, AuthUpdateKeyChangeReply{}, AuthUpdateKeyChange{}, AuthUpdateKeyChangeSignature{},
		AuthUpdateKeyChangeConfirmation{},
	} {
		v.isValue()
	}
	if _, err := (Attribute{Type: AttrSignedInt, Data: []byte{0xFF}}).Int(); err != nil {
		t.Error("1-octet INT")
	}
	if v, _ := (Attribute{Type: AttrSignedInt, Data: []byte{0xFE, 0xFF}}).Int(); v != -2 {
		t.Error("2-octet INT")
	}
	if _, err := (Attribute{Type: AttrSignedInt, Data: []byte{1, 2, 3}}).Int(); err == nil {
		t.Error("3-octet INT accepted")
	}
	if v, _ := (Attribute{Type: AttrFloat, Data: []byte{0, 0, 0x80, 0x3F}}).Float(); v != 1 {
		t.Error("4-octet FLT")
	}
	if _, err := (Attribute{Type: AttrUnsignedInt, Data: []byte{1, 2, 3}}).Uint(); err == nil {
		t.Error("3-octet UINT accepted")
	}
	if _, err := StringAttribute("x").Float(); err == nil {
		t.Error("Float of string")
	}
	if _, err := StringAttribute("x").Int(); err == nil {
		t.Error("Int of string")
	}
	if _, err := StringAttribute("x").List(); err == nil {
		t.Error("List of string")
	}
	if _, err := (Attribute{Type: AttrList, Data: []byte{1}}).List(); err == nil {
		t.Error("odd list accepted")
	}
	if _, err := DecodeFileDescriptors([]byte{1, 2}); err == nil {
		t.Error("short descriptor accepted")
	}
	if _, err := DecodeFileDescriptors(make([]byte, 20)); err == nil {
		t.Error("descriptor with offset 0 accepted")
	}
}

func TestAppendObjectValue(t *testing.T) {
	ks := AuthSessionKeyStatus{KSQ: 7, User: 1, KeyWrap: KeyWrapAES128, Status: KeyStatusNotInit, Challenge: []byte{1, 2, 3, 4}}
	b, err := AppendObjectValue(nil, G120V5, ks)
	if err != nil || len(b) != 4+2+3+2+4 {
		t.Fatalf("%x %v", b, err)
	}
	// Identical to the object inside an encoded fragment.
	f := Fragment{Function: FuncAuthResponse, Headers: []Header{FreeFormat(G120V5, ks)}}
	enc, _ := f.Encode()
	if string(enc[len(enc)-len(b):]) != string(b) {
		t.Fatal("differs from the encoding in a fragment")
	}
	if _, err := AppendObjectValue(nil, GV(200, 1), ks); err == nil {
		t.Fatal("unknown object accepted")
	}
	if _, err := AppendObjectValue(nil, G2V3, Binary{}); err == nil {
		t.Fatal("relative time accepted")
	}
}

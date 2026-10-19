// SPDX-License-Identifier: MIT

package secauth

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

// RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
const rfc4231Case2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

func TestMACVectors(t *testing.T) {
	full, _ := hex.DecodeString(rfc4231Case2)
	mac, err := MAC(app.MACHMACSHA256Trunc16, []byte("Jefe"), []byte("what do ya want for nothing?"))
	if err != nil || !bytes.Equal(mac, full[:16]) {
		t.Fatalf("HMAC-SHA-256-16 = %x, want %x (%v)", mac, full[:16], err)
	}
	mac8, _ := MAC(app.MACHMACSHA256Trunc8, []byte("Jefe"), []byte("what do ya want for nothing?"))
	if !bytes.Equal(mac8, full[:8]) {
		t.Fatal("HMAC-SHA-256-8 truncation")
	}
	// RFC 2202 test case 2 for HMAC-SHA-1.
	sha1Full, _ := hex.DecodeString("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
	m1, err := MAC(app.MACHMACSHA1Trunc10, []byte("Jefe"), []byte("what do ya want for nothing?"))
	if err != nil || !bytes.Equal(m1, sha1Full[:10]) {
		t.Fatalf("HMAC-SHA-1-10 = %x", m1)
	}
	if _, err := MAC(app.MACAESGMAC, []byte("k"), nil); err == nil {
		t.Fatal("AES-GMAC should be unsupported")
	}
	if !Equal(mac, full[:16]) || Equal(mac, mac8) {
		t.Fatal("Equal")
	}
}

func TestAuthDataAndUser(t *testing.T) {
	if got := AuthData([]byte{1, 2}, []byte{3}); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("AuthData %v", got)
	}
	u := User{Number: 1, Key: []byte("0123456789abcdef")}
	if u.Algorithm() != app.MACHMACSHA256Trunc16 || u.Validate() != nil {
		t.Fatal("default user")
	}
	if (User{Number: 1}).Validate() == nil {
		t.Fatal("user without key accepted")
	}
	if (User{Key: []byte("k"), MAC: 99}).Validate() == nil {
		t.Fatal("unknown algorithm accepted")
	}
}

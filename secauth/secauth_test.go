// SPDX-License-Identifier: MIT

package secauth

import (
	"bytes"
	"encoding/hex"
	"errors"
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

func TestKeyWrapRFC3394(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	cases := []struct{ kek, key, wrapped string }{
		// RFC 3394 4.1: 128-bit key data with a 128-bit KEK.
		{"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		// RFC 3394 4.6: 256-bit key data with a 256-bit KEK.
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	}
	for _, c := range cases {
		w, err := KeyWrap(h(c.kek), h(c.key))
		if err != nil || !bytes.Equal(w, h(c.wrapped)) {
			t.Fatalf("wrap %x, want %s (%v)", w, c.wrapped, err)
		}
		p, err := KeyUnwrap(h(c.kek), w)
		if err != nil || !bytes.Equal(p, h(c.key)) {
			t.Fatalf("unwrap %x (%v)", p, err)
		}
		w[3] ^= 1
		if _, err := KeyUnwrap(h(c.kek), w); !errors.Is(err, ErrKeyWrap) {
			t.Fatalf("damaged data: %v", err)
		}
	}
	if _, err := KeyWrap(make([]byte, 16), make([]byte, 12)); err == nil {
		t.Fatal("unaligned plaintext wrapped")
	}
	if _, err := KeyWrap(make([]byte, 5), make([]byte, 16)); err == nil {
		t.Fatal("bad KEK accepted")
	}
	if _, err := KeyUnwrap(make([]byte, 16), make([]byte, 20)); !errors.Is(err, ErrKeyWrap) {
		t.Fatal("unaligned wrapped data accepted")
	}
}

func TestKeyChangeData(t *testing.T) {
	ctrl, mon := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	status := []byte{9, 9, 9, 9, 1, 0, 1, 2, 0, 4, 0, 7, 7, 7, 7}
	withMAC := append(append([]byte(nil), status...), bytes.Repeat([]byte{5}, 16)...)
	plain, err := KeyChangeData(ctrl, mon, status)
	if err != nil || len(plain)%8 != 0 {
		t.Fatalf("plaintext %d octets: %v", len(plain), err)
	}
	c, m, err := ParseKeyChangeData(plain, withMAC, status)
	if err != nil || !bytes.Equal(c, ctrl) || !bytes.Equal(m, mon) {
		t.Fatalf("parse: %v", err)
	}
	// The form with the MAC is accepted too.
	plain2, _ := KeyChangeData(ctrl, mon, withMAC)
	if _, _, err := ParseKeyChangeData(plain2, withMAC, status); err != nil {
		t.Fatalf("with MAC: %v", err)
	}
	// A different status message, non-zero padding, bad lengths.
	if _, _, err := ParseKeyChangeData(plain, []byte{1, 2, 3}); !errors.Is(err, ErrKeyWrap) {
		t.Fatal("wrong status accepted")
	}
	bad := append([]byte(nil), plain...)
	bad[len(bad)-1] = 1
	if _, _, err := ParseKeyChangeData(bad, status); !errors.Is(err, ErrKeyWrap) {
		t.Fatal("non-zero padding accepted")
	}
	if _, _, err := ParseKeyChangeData([]byte{1}, status); !errors.Is(err, ErrKeyWrap) {
		t.Fatal("short data accepted")
	}
	if _, _, err := ParseKeyChangeData([]byte{8, 0, 1, 2}, status); !errors.Is(err, ErrKeyWrap) {
		t.Fatal("short key accepted")
	}
	if _, err := KeyChangeData(ctrl, mon[:15], status); err == nil {
		t.Fatal("unequal keys accepted")
	}
	u := User{UpdateKey: make([]byte, 32)}
	if u.KeyWrapAlgorithm() != app.KeyWrapAES256 || u.SessionKeyLen() != 32 || u.Validate() != nil {
		t.Fatal("AES-256 user")
	}
	if (User{UpdateKey: make([]byte, 16)}).KeyWrapAlgorithm() != app.KeyWrapAES128 || (User{UpdateKey: make([]byte, 20)}).Validate() == nil {
		t.Fatal("update key lengths")
	}
}

func TestKeyWrapEdges(t *testing.T) {
	// A KEK AES cannot use, with data of a valid length.
	if _, err := KeyUnwrap(make([]byte, 5), make([]byte, 24)); err == nil || errors.Is(err, ErrKeyWrap) {
		t.Fatalf("bad KEK: %v", err)
	}
	// A key status message longer than what follows the keys.
	plain, _ := KeyChangeData(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), []byte{7})
	if _, _, err := ParseKeyChangeData(plain, bytes.Repeat([]byte{7}, 40)); !errors.Is(err, ErrKeyWrap) {
		t.Fatalf("long key status: %v", err)
	}
	// A key status message of the right length with other content.
	plain2, _ := KeyChangeData(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{7}, 8))
	if _, _, err := ParseKeyChangeData(plain2, bytes.Repeat([]byte{8}, 8)); !errors.Is(err, ErrKeyWrap) {
		t.Fatalf("other key status: %v", err)
	}
	if (User{UpdateKey: make([]byte, 16)}).SessionKeyLen() != 16 {
		t.Fatal("AES-128 session key length")
	}
	if (User{Key: []byte("k"), MAC: app.MACAESGMAC}).Validate() == nil {
		t.Fatal("AES-GMAC accepted although MAC cannot compute it")
	}
}

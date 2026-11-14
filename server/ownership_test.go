// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// TestCallerSlicesAreCopied: the server keeps its own copy of every slice
// a caller gives it, and gives out copies: changing the caller's slice
// afterwards, or the one Get returned, changes nothing the server holds.
func TestCallerSlicesAreCopied(t *testing.T) {
	updateKey := []byte("0123456789abcdef")
	sessionKey := []byte("fedcba9876543210")
	attr := []byte("vendor")
	set1 := []byte("set one")
	srv, err := New(
		WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: updateKey, Key: sessionKey}}),
		WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: {Type: app.AttrVisibleString, Data: attr}}),
		WithAttributeSet(1, map[uint8]app.Attribute{10: {Type: app.AttrVisibleString, Data: set1}}, 10))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	clear(updateKey)
	clear(sessionKey)
	attr[0] = 'X'
	set1[0] = 'X'
	if got := srv.opts.auth.User.UpdateKey; !bytes.Equal(got, []byte("0123456789abcdef")) {
		t.Errorf("update key after the caller cleared its slice: % x", got)
	}
	if got := srv.opts.auth.User.Key; !bytes.Equal(got, []byte("fedcba9876543210")) {
		t.Errorf("session key after the caller cleared its slice: % x", got)
	}
	if got := srv.opts.attributes[0].attrs[app.AttrManufacturerName].Data; string(got) != "vendor" {
		t.Errorf("attribute after the caller changed its slice: %q", got)
	}
	if got := srv.opts.attributes[1].attrs[10].Data; string(got) != "set one" {
		t.Errorf("attribute of set 1 after the caller changed its slice: %q", got)
	}

	db := srv.Database()
	for _, tc := range []struct {
		name   string
		add    func(data []byte) error
		update func(data []byte) error
	}{
		{"Add and Update",
			func(d []byte) error { return db.Add(OctetString, 0, PointConfig{Class: 1}, app.OctetString{Data: d}) },
			func(d []byte) error { return db.Update(OctetString, 0, app.OctetString{Data: d}, EventOnChange) }},
		{"AddOctetString and UpdateOctetString",
			func(d []byte) error { return db.AddOctetString(0, PointConfig{Class: 1}, d) },
			func(d []byte) error { return db.UpdateOctetString(0, d) }},
	} {
		value := func() string {
			v, ok := db.Get(OctetString, 0)
			if !ok {
				t.Fatalf("%s: no point", tc.name)
			}
			return string(v.(app.OctetString).Data)
		}
		buf := []byte("abc")
		if err := tc.add(buf); err != nil {
			t.Fatal(err)
		}
		buf[0] = 'X'
		if got := value(); got != "abc" {
			t.Errorf("%s: point after the caller changed the slice it added: %q", tc.name, got)
		}
		buf = []byte("def")
		if err := tc.update(buf); err != nil {
			t.Fatal(err)
		}
		buf[0] = 'X'
		if got := value(); got != "def" {
			t.Errorf("%s: point after the caller changed the slice it updated with: %q", tc.name, got)
		}
		v, _ := db.Get(OctetString, 0)
		v.(app.OctetString).Data[1] = 'Y'
		if got := value(); got != "def" {
			t.Errorf("%s: point after the caller changed the slice Get returned: %q", tc.name, got)
		}
	}
}

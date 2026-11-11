// SPDX-License-Identifier: MIT

package client

import (
	"crypto/tls"
	"errors"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// TestSpec7_8_8_TLSDefaultPort: IEEE 1815-2012 clause 7.8.8 (printed page
// 258): "DNP3 implementations using TLS shall use the TCP port number
// 19 999 by default to initiate secure connections", and those without
// TLS "shall continue to use port 20 000 by default" (clause 13.2.2.2,
// p. 378). An explicit port is kept.
func TestSpec7_8_8_TLSDefaultPort(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, tc := range []struct {
		addr string
		opts []Option
		want string
	}{
		{"h", []Option{WithTLS(cfg)}, "h:19999"},
		{"h", nil, "h:20000"},
		{"h:1234", []Option{WithTLS(cfg)}, "h:1234"},
		{"::1", []Option{WithTLS(cfg)}, "[::1]:19999"},
	} {
		c, err := New(tc.addr, tc.opts...)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Addr(); got != tc.want {
			t.Errorf("New(%q, %d options).Addr() = %q, want %q", tc.addr, len(tc.opts), got, tc.want)
		}
	}
	if DefaultTLSPort != 19999 || DefaultPort != 20000 {
		t.Fatalf("DefaultTLSPort %d, DefaultPort %d", DefaultTLSPort, DefaultPort)
	}
}

// TestSpec4_5_13_AlreadyExecuting: clause 4.5.13 (p. 87): IIN2.4 "is set
// when the requested operation was not performed or initiated because
// execution was in progress". The request fails with a *dnp3.IINError
// that carries the bit.
func TestSpec4_5_13_AlreadyExecuting(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, app.IINAlreadyExecuting)} })
	c := specDial(t, o, quiet...)
	_, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
	var ie *dnp3.IINError
	if !errors.As(err, &ie) || !ie.IIN.Has(app.IINAlreadyExecuting) {
		t.Fatalf("response with IIN2.4: %v", err)
	}
}

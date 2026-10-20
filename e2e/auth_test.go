// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

var authKey = []byte("0123456789abcdef0123456789abcdef")

func TestSecureAuthentication(t *testing.T) {
	r := &relay{}
	sa := server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: authKey}})

	// Matching key: the control is challenged, answered and executed.
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r), sa},
		client.WithSecureAuthentication(secauth.User{Number: 1, Key: authKey}))
	st, err := p.c.Operate(ctx(t), client.SelectBeforeOperate, client.CROB(2, app.OpLatchOn, 0, 0))
	if err != nil || st[0] != app.StatusSuccess {
		t.Fatalf("authenticated SBO: %v %v", st, err)
	}
	if _, op, _ := r.snapshot(); len(op) != 1 {
		t.Fatalf("%d operates executed", len(op))
	}
	// Reads are not critical: no challenge, and they work.
	if _, err := p.c.IntegrityPoll(ctx(t)); err != nil {
		t.Fatal(err)
	}
	// Writes are critical too.
	if err := p.c.ClearRestart(ctx(t)); err != nil {
		t.Fatalf("authenticated write: %v", err)
	}

	// Wrong key: authentication error, nothing executed.
	q := newPair(t, fullDatabase, []server.Option{server.WithHandler(r), sa},
		client.WithSecureAuthentication(secauth.User{Number: 1, Key: []byte("wrong key wrong key wrong key!!!")}))
	_, err = q.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOff, 0, 0))
	var ae *dnp3.AuthError
	if !errors.As(err, &ae) || ae.Code != app.AuthErrAuthenticationFailed || !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, op, _ := r.snapshot(); len(op) != 1 {
		t.Fatal("control executed with a wrong key")
	}

	// A master without secure authentication.
	n := newPair(t, fullDatabase, []server.Option{server.WithHandler(r), sa})
	if _, err := n.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOff, 0, 0)); !errors.Is(err, dnp3.ErrAuthentication) {
		t.Fatalf("unconfigured master: %v", err)
	}

	// Session key status request.
	res, err := p.c.Request(ctx(t), app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if ks, ok := res.Headers()[0].Objects[0].Value.(app.AuthSessionKeyStatus); !ok || ks.Status != app.KeyStatusOK {
		t.Fatalf("key status %v", res.Headers())
	}
}

var updateKey = []byte("0123456789abcdef") // AES-128

func TestSessionKeyChange(t *testing.T) {
	r := &relay{}
	sa := server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: updateKey}})

	// The key change runs at connect; controls are then authenticated with
	// the negotiated control direction session key.
	p := newPair(t, fullDatabase, []server.Option{server.WithHandler(r), sa},
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey}),
		client.WithKeyChangeInterval(150*time.Millisecond))
	if _, err := p.c.Operate(ctx(t), client.SelectBeforeOperate, client.CROB(2, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("after key change: %v", err)
	}
	// Periodic key changes (the second and later ones carry a key status
	// with a MAC) keep controls working.
	time.Sleep(500 * time.Millisecond)
	for range 3 {
		if _, err := p.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOff, 0, 0)); err != nil {
			t.Fatalf("after periodic key changes: %v", err)
		}
	}
	if _, op, _ := r.snapshot(); len(op) != 4 {
		t.Fatalf("%d operates executed", len(op))
	}

	// AES-256 update keys.
	key256 := bytes.Repeat([]byte{7}, 32)
	q := newPair(t, fullDatabase, []server.Option{server.WithHandler(r),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: key256}})},
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: key256}))
	if _, err := q.c.Operate(ctx(t), client.DirectOperate, client.CROB(2, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatalf("AES-256: %v", err)
	}
}

func TestSessionKeyChangeWrongUpdateKey(t *testing.T) {
	srv, err := server.New(server.WithMasters(1), server.WithHandler(&relay{}),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, UpdateKey: updateKey}}))
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()
	_, err = client.Dial(ctx(t), l.Addr().String(), client.WithResponseTimeout(2*time.Second),
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: []byte("not-the-key-1234")}))
	var ae *dnp3.AuthError
	if !errors.As(err, &ae) || ae.Code != app.AuthErrAuthenticationFailed {
		t.Fatalf("wrong update key: %v", err)
	}
}

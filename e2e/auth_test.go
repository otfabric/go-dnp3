// SPDX-License-Identifier: MIT

package e2e

import (
	"errors"
	"testing"

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

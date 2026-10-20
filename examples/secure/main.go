// SPDX-License-Identifier: MIT

// Command secure shows Secure Authentication version 5: both ends share an
// update key; the master wraps fresh session keys with it when it
// connects; the outstation then challenges every critical request and the
// master answers with an HMAC-SHA-256 MAC. A master with the wrong update
// key is refused.
//
//	go run ./examples/secure
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

func main() {
	// In production: 32 random octets, kept out of source control.
	updateKey := []byte("an AES-256 update key, 32 octets")[:32]
	user := secauth.User{Number: 1, UpdateKey: updateKey}

	accept := server.HandlerFunc(func(_ context.Context, c server.Command, op server.OperateType) app.CommandStatus {
		fmt.Printf("outstation: executing %s on index %d (%s)\n", c.Value, c.Index, op)
		return app.StatusSuccess
	})
	srv, err := server.New(server.WithHandler(accept), server.WithSecureAuthentication(server.SecureAuth{User: user}))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	good, err := client.Dial(ctx, ln.Addr().String(), client.WithSecureAuthentication(user))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = good.Close() }()
	if _, err := good.Operate(ctx, client.SelectBeforeOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("master with the right update key: session keys changed, SELECT and OPERATE challenged and answered")

	// The wrong update key: the session key change is refused, so the
	// master cannot connect.
	_, err = client.Dial(ctx, ln.Addr().String(), client.WithAddresses(2, 10),
		client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: []byte("not the update key, 32 octets!!!")}))
	var ae *dnp3.AuthError
	if errors.As(err, &ae) {
		fmt.Printf("master with the wrong update key: refused with %s\n", ae.Code)
	}
}

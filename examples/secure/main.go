// SPDX-License-Identifier: MIT

// Command secure shows Secure Authentication version 5 with a pre-shared
// session key: the outstation challenges every critical request, the
// master answers with an HMAC-SHA-256 MAC, and a master with the wrong key
// is refused.
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
	key := []byte("a 32 octet pre-shared session key")[:32]
	user := secauth.User{Number: 1, Key: key}

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
	fmt.Println("master with the right key: both SELECT and OPERATE were challenged and answered")

	bad, err := client.Dial(ctx, ln.Addr().String(), client.WithAddresses(2, 10),
		client.WithSecureAuthentication(secauth.User{Number: 1, Key: []byte("not the key not the key not the!")}))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	_, err = bad.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOff, 0, 0))
	var ae *dnp3.AuthError
	if errors.As(err, &ae) {
		fmt.Printf("master with the wrong key: refused with %s\n", ae.Code)
	}
}

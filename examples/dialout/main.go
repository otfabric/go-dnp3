// SPDX-License-Identifier: MIT

// Command dialout shows the dual end point of IEEE 1815-2012:
// the outstation, behind a firewall that only lets it connect out,
// establishes the TCP connection to its master and re-establishes it when
// it is lost. The master waits for it with client.Accept.
//
//	go run ./examples/dialout
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

func main() {
	// The master listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// The outstation connects out to it, and again whenever the
	// connection ends.
	srv, err := server.New()
	if err != nil {
		log.Fatal(err)
	}
	_ = srv.Database().AddAnalogInput(0, server.PointConfig{}, app.Analog{Value: 21, Flags: app.FlagOnline})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = srv.DialAndServe(ctx, ln.Addr().String(), server.Redial{MinDelay: 100 * time.Millisecond}) }()
	defer func() { _ = srv.Close() }()

	c, err := client.Dial(ctx, "outstation", client.WithStream(client.Accept(ln)),
		client.WithReconnect(client.Reconnect{MinDelay: 50 * time.Millisecond}))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	read := func() {
		for {
			res, err := c.Read(ctx, app.AllObjects(app.G30V0))
			if err == nil {
				fmt.Printf("master: analog input 0 = %v, %s\n", res.Measurements()[0].Value.(app.Analog).Value, c.State())
				return
			}
			if ctx.Err() != nil {
				log.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	read()

	// The connection is lost; the outstation dials again.
	srv.CloseConnections()
	fmt.Println("connection lost: the outstation reconnects")
	read()
}

// SPDX-License-Identifier: MIT

// Command quickstart is the smallest complete program: an outstation with a
// few points and a master that runs an integrity poll against it, in one
// process, over a real TCP connection on loopback.
//
//	go run ./examples/quickstart
package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

func main() {
	// --- The outstation (server) -----------------------------------------
	srv, err := server.New(server.WithAddress(10))
	if err != nil {
		log.Fatal(err)
	}
	db := srv.Database()
	_ = db.AddBinaryInput(0, server.PointConfig{Class: 1}, app.Binary{Value: true, Flags: app.FlagOnline})
	_ = db.AddAnalogInput(0, server.PointConfig{Class: 2, StaticVariation: 5}, app.Analog{Value: 49.98, Flags: app.FlagOnline})
	_ = db.AddCounter(0, server.PointConfig{Class: 3}, app.Counter{Value: 1234, Flags: app.FlagOnline})

	ln, err := net.Listen("tcp", "127.0.0.1:0") // production: srv.ListenAndServe(":20000")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// --- The master (client) ---------------------------------------------
	ctx := context.Background()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithAddresses(1, 10))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// An integrity poll reads the events of classes 1..3, then all static
	// data, and returns every fragment of the response.
	res, err := c.IntegrityPoll(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range res.Measurements() {
		switch v := m.Value.(type) {
		case app.Binary:
			fmt.Printf("%-6s index %d  %v\n", m.GV, m.Index, v.Value)
		case app.Analog:
			fmt.Printf("%-6s index %d  %.2f\n", m.GV, m.Index, v.Value)
		case app.Counter:
			fmt.Printf("%-6s index %d  %d\n", m.GV, m.Index, v.Value)
		}
	}
	fmt.Println("IIN:", res.IIN)
}

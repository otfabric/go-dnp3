// SPDX-License-Identifier: MIT

// Command events shows how changes reach the master: events per class,
// collected in a batch, reported unsolicited once the master enabled
// unsolicited responses, and confirmed. The handler receives them as they
// arrive.
//
//	go run ./examples/events
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
	srv, err := server.New(
		server.WithMasters(1), // events are buffered for master 1 even while it is away
		server.WithUnsolicited(server.Unsolicited{Enabled: true, HoldTime: 50 * time.Millisecond}),
	)
	if err != nil {
		log.Fatal(err)
	}
	db := srv.Database()
	_ = db.AddBinaryInput(0, server.PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddAnalogInput(0, server.PointConfig{Class: 2, Deadband: 0.5, EventVariation: 7}, app.Analog{Value: 20, Flags: app.FlagOnline})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	got := make(chan struct{}, 8)
	h := client.HandlerFunc(func(info client.ResponseInfo, ms []client.Measurement) {
		if !info.Unsolicited {
			return
		}
		for _, m := range ms {
			fmt.Printf("unsolicited %-6s index %d  %+v\n", m.GV, m.Index, m.Value)
		}
		got <- struct{}{}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The usual startup: disable unsolicited, integrity poll, enable it.
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithHandler(h),
		client.WithStartup(client.Startup{DisableUnsolicited: true, Integrity: true, EnableUnsolicited: []int{1, 2, 3}}))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// A batch: both events are reported in the same unsolicited response.
	_ = db.Batch(func(b *server.Batch) error {
		if err := b.Update(server.BinaryInput, 0, app.Binary{Value: true, Flags: app.FlagOnline}, server.EventOnChange); err != nil {
			return err
		}
		return b.Update(server.AnalogInput, 0, app.Analog{Value: 21.5, Flags: app.FlagOnline}, server.EventOnChange)
	})
	<-got
	// Within the deadband: no event.
	_ = db.UpdateAnalogInput(0, app.Analog{Value: 21.7, Flags: app.FlagOnline})
	select {
	case <-got:
		fmt.Println("unexpected event inside the deadband")
	case <-time.After(300 * time.Millisecond):
		fmt.Println("21.7 is within the deadband of 21.5: no event")
	}
}

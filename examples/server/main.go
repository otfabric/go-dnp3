// SPDX-License-Identifier: MIT

// Command server is a standalone outstation for trying the library against
// another master, a simulator or a test tool: binary and analog inputs, a
// counter, a controllable breaker and periodic updates, with unsolicited
// responses enabled.
//
//	go run ./examples/server -addr :20000 -address 10
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

func main() {
	addr := flag.String("addr", ":20000", "TCP listen address")
	address := flag.Uint("address", 10, "outstation link address")
	debug := flag.Bool("debug", false, "log every frame and fragment")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := dnp3.NewSlogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var srv *server.Server
	breaker := server.HandlerFunc(func(_ context.Context, c server.Command, _ server.OperateType) app.CommandStatus {
		crob, ok := c.Value.(app.CROB)
		if !ok || c.Index != 0 {
			return app.StatusNotSupported
		}
		closed := crob.Op == app.OpLatchOn || crob.TripClose == app.TCCClose
		_ = srv.Database().UpdateBinaryOutput(0, app.Binary{Value: closed, Flags: app.FlagOnline})
		return app.StatusSuccess
	})
	var err error
	srv, err = server.New(
		server.WithAddress(link.Address(*address)),
		server.WithHandler(breaker),
		server.WithLogger(logger),
		server.WithUnsolicited(server.Unsolicited{Enabled: true}),
		server.WithTimeSync(time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}
	db := srv.Database()
	for i := range uint32(4) {
		_ = db.AddBinaryInput(i, server.PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	}
	_ = db.AddBinaryOutput(0, server.PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddAnalogInput(0, server.PointConfig{Class: 2, StaticVariation: 5, EventVariation: 7, Deadband: 0.1},
		app.Analog{Flags: app.FlagOnline})
	_ = db.AddCounter(0, server.PointConfig{Class: 3}, app.Counter{Flags: app.FlagOnline})
	_ = db.AddFrozenCounter(0, server.PointConfig{Class: 3}, app.Counter{Flags: app.FlagOnline})

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for n := 0; ; n++ {
			<-t.C
			_ = db.Batch(func(b *server.Batch) error {
				_ = b.Update(server.AnalogInput, 0, app.Analog{Value: 50 + math.Sin(float64(n)/10), Flags: app.FlagOnline}, server.EventOnChange)
				_ = b.Update(server.Counter, 0, app.Counter{Value: uint32(n), Flags: app.FlagOnline}, server.EventOnChange)
				return b.Update(server.BinaryInput, uint32(n%4), app.Binary{Value: n%8 < 4, Flags: app.FlagOnline}, server.EventOnChange)
			})
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(*addr); err != nil {
		log.Fatal(err)
	}
}

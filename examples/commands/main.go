// SPDX-License-Identifier: MIT

// Command commands shows controls: select-before-operate and direct operate
// of a control relay output block, a set-point, a direct operate without
// acknowledgement, and how a refused control surfaces as a
// *dnp3.CommandError.
//
//	go run ./examples/commands
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// breaker is the outstation's control handler: binary output 0 is a
// breaker that can be opened and closed, analog output 0 a set-point. Any
// other point is refused.
type breaker struct {
	db     *server.Database
	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

func (b *breaker) Select(_ context.Context, c server.Command) app.CommandStatus {
	if c.Index != 0 {
		return app.StatusNotSupported
	}
	return app.StatusSuccess
}

func (b *breaker) Operate(_ context.Context, c server.Command, op server.OperateType) app.CommandStatus {
	defer func() {
		if op == server.DirectOperateNoAck {
			b.done <- struct{}{}
		}
	}()
	if c.Index != 0 {
		return app.StatusNotSupported
	}
	switch v := c.Value.(type) {
	case app.CROB:
		b.mu.Lock()
		b.closed = v.Op == app.OpLatchOn || v.TripClose == app.TCCClose
		closed := b.closed
		b.mu.Unlock()
		// The state of the output is reported back through the database.
		_ = b.db.UpdateBinaryOutput(0, app.Binary{Value: closed, Flags: app.FlagOnline})
		fmt.Printf("outstation: %s (%s) -> breaker closed=%v\n", v, op, closed)
	case app.AnalogOutput:
		_ = b.db.UpdateAnalogOutput(0, app.Analog{Value: v.Value, Flags: app.FlagOnline})
		fmt.Printf("outstation: set-point %.1f (%s)\n", v.Value, op)
	}
	return app.StatusSuccess
}

func main() {
	h := &breaker{done: make(chan struct{}, 1)}
	srv, err := server.New(server.WithHandler(h))
	if err != nil {
		log.Fatal(err)
	}
	h.db = srv.Database()
	_ = h.db.AddBinaryOutput(0, server.PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	// g40v3: the set-point is read back in single precision, not rounded.
	_ = h.db.AddAnalogOutput(0, server.PointConfig{Class: 1, StaticVariation: 3}, app.Analog{Flags: app.FlagOnline})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Select-before-operate: SELECT, then OPERATE with the next sequence
	// number, both checked against the echo.
	if _, err := c.Operate(ctx, client.SelectBeforeOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		log.Fatal(err)
	}
	// Direct operate: a trip.
	trip := client.Command{Index: 0, Value: app.CROB{Op: app.OpPulseOn, TripClose: app.TCCTrip, Count: 1, OnTime: 100}}
	if _, err := c.Operate(ctx, client.DirectOperate, trip); err != nil {
		log.Fatal(err)
	}
	// A set-point; 42.5 is sent as g41v3 (single precision).
	if _, err := c.Operate(ctx, client.DirectOperate, client.SetPoint(0, 42.5)); err != nil {
		log.Fatal(err)
	}
	// No acknowledgement: the outstation executes it and sends nothing.
	if _, err := c.Operate(ctx, client.DirectOperateNoAck, client.CROB(0, app.OpLatchOff, 0, 0)); err != nil {
		log.Fatal(err)
	}
	<-h.done

	// A point the handler refuses.
	_, err = c.Operate(ctx, client.SelectBeforeOperate, client.CROB(7, app.OpLatchOn, 0, 0))
	var ce *dnp3.CommandError
	if errors.As(err, &ce) {
		fmt.Printf("master: refused: index %d status %s\n", ce.Index, ce.Status)
	}

	res, err := c.Read(ctx, app.AllObjects(app.G10V0), app.AllObjects(app.G40V0))
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range res.Measurements() {
		switch v := m.Value.(type) {
		case app.Binary:
			fmt.Printf("master: %s index %d breaker closed=%v\n", m.GV, m.Index, v.Value)
		case app.Analog:
			fmt.Printf("master: %s index %d set-point %.1f\n", m.GV, m.Index, v.Value)
		}
	}
}

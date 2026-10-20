// SPDX-License-Identifier: MIT

// Command observability shows what a long-running program wires up: slog
// logging and metrics on both sides, a state handler, retries for reads,
// automatic reconnection, and periodic polls.
//
//	go run ./examples/observability
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// counters is a Metrics implementation that counts traffic; embed
// dnp3.NopMetrics to implement only what you need.
type counters struct {
	dnp3.NopMetrics
	framesSent, framesReceived, requests atomic.Int64
}

func (m *counters) OnFrameSent(net.Addr, *link.Frame, int)     { m.framesSent.Add(1) }
func (m *counters) OnFrameReceived(net.Addr, *link.Frame, int) { m.framesReceived.Add(1) }
func (m *counters) OnRequest(net.Addr, uint16, app.FunctionCode) {
	m.requests.Add(1)
}
func (m *counters) OnRequestDone(_ net.Addr, _ uint16, fc app.FunctionCode, d time.Duration, err error) {
	fmt.Printf("metrics: %s took %v (err=%v)\n", fc, d.Round(time.Microsecond), err)
}
func (m *counters) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) {}

func main() {
	logger := dnp3.NewSlogLogger(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := server.New(server.WithLogger(logger))
	if err != nil {
		log.Fatal(err)
	}
	_ = srv.Database().AddAnalogInput(0, server.PointConfig{Class: 2}, app.Analog{Value: 1, Flags: app.FlagOnline})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	m := &counters{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(),
		client.WithLogger(logger),
		client.WithMetrics(m),
		client.WithStateHandler(func(s dnp3.State, err error) { fmt.Printf("state: %s (%v)\n", s, err) }),
		client.WithResponseTimeout(2*time.Second),
		client.WithRetry(client.Retry{Attempts: 3}),
		client.WithReconnect(client.Reconnect{MinDelay: 100 * time.Millisecond}),
		client.WithPoll(client.Poll{Interval: 200 * time.Millisecond, Headers: app.ClassHeaders(1, 2, 3)}),
	)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.IntegrityPoll(ctx); err != nil {
		log.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // a few periodic event polls
	_ = c.Close()
	fmt.Printf("frames sent %d, received %d, requests %d\n", m.framesSent.Load(), m.framesReceived.Load(), m.requests.Load())
}

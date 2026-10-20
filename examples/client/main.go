// SPDX-License-Identifier: MIT

// Command client is a standalone master for trying the library against an
// outstation: it connects, runs the usual startup (disable unsolicited,
// integrity poll, enable unsolicited), synchronizes time when asked to,
// optionally operates a binary output, and prints everything the
// outstation reports until interrupted.
//
//	go run ./examples/client -addr 127.0.0.1:20000 -operate 0
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:20000", "outstation address")
	local := flag.Uint("local", 1, "master link address")
	remote := flag.Uint("remote", 10, "outstation link address")
	operate := flag.Int("operate", -1, "index of a binary output to latch on, -1 for none")
	debug := flag.Bool("debug", false, "log every frame and fragment")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := dnp3.NewSlogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	print := client.HandlerFunc(func(info client.ResponseInfo, ms []client.Measurement) {
		kind := "response"
		if info.Unsolicited {
			kind = "unsolicited"
		}
		for _, m := range ms {
			fmt.Printf("%s %-7s index %-4d %s\n", kind, m.GV, m.Index, describe(m))
		}
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	c, err := client.Dial(ctx, *addr,
		client.WithAddresses(link.Address(*local), link.Address(*remote)),
		client.WithHandler(print),
		client.WithLogger(logger),
		client.WithTimeSync(client.TimeSyncLAN),
		client.WithReconnect(client.Reconnect{}),
		client.WithRetry(client.Retry{Attempts: 3}),
		client.WithStartup(client.Startup{DisableUnsolicited: true, Integrity: true, EnableUnsolicited: []int{1, 2, 3}}),
		client.WithPoll(client.Poll{Interval: 30 * time.Second, Headers: app.ClassHeaders(1, 2, 3, 0)}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	if *operate >= 0 {
		st, err := c.Operate(ctx, client.SelectBeforeOperate, client.CROB(uint32(*operate), app.OpLatchOn, 0, 0))
		fmt.Printf("operate: %v %v\n", st, err)
	}
	<-ctx.Done()
}

// describe formats a measurement's value and flags, and its time stamp for
// events (static values carry none).
func describe(m client.Measurement) string {
	var s string
	var ts app.Timestamp
	switch v := m.Value.(type) {
	case app.Binary:
		s, ts = fmt.Sprintf("%v %s", v.Value, v.Flags), v.Time
	case app.DoubleBitBinary:
		s, ts = fmt.Sprintf("%s %s", v.Value, v.Flags), v.Time
	case app.Counter:
		s, ts = fmt.Sprintf("%d %s", v.Value, v.Flags), v.Time
	case app.Analog:
		s, ts = fmt.Sprintf("%g %s", v.Value, v.Flags), v.Time
	case app.OctetString:
		s = fmt.Sprintf("%q", v.Data)
	default:
		s = fmt.Sprintf("%+v", v)
	}
	if m.Event && ts != 0 {
		s += " at " + ts.String()
	}
	return s
}

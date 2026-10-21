// SPDX-License-Identifier: MIT

// Command dut is the device under test of the dnp3c conformance run: a
// go-dnp3 outstation with a fixed database, and a control port through
// which the dnp3c integration plugin performs the steps a tester would
// otherwise perform by hand (restarts, configuration changes, input changes)
// and checks what the outstation reported against what it holds.
//
// The control protocol: the plugin sends a request as one line of JSON,
// and the device answers with lines "log <text>", "index <n>", "flags <n>"
// and "error <text>", ended by "end".
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	dnp3Addr := flag.String("dnp3", "127.0.0.1:20000", "DNP3 TCP listen address")
	controlAddr := flag.String("control", "127.0.0.1:20099", "control listen address")
	level := flag.Int("level", 2, "DNP3 subset level the database is shaped to")
	doubleBit := flag.Bool("double-bit", false, "add double-bit inputs (3.1r1 has them at level 4; 2.7 at level 2)")
	debug := flag.Bool("debug", false, "log every frame and fragment")
	flag.Parse()

	logLevel := slog.LevelWarn
	if *debug {
		logLevel = slog.LevelDebug
	}
	setLevel(*level, *doubleBit)
	d := newDevice(*dnp3Addr, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))
	if err := d.reset(); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", *controlAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("dut: DNP3 on %s, control on %s", *dnp3Addr, l.Addr())
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serveControl(d, c)
	}
}

func serveControl(d *device, c net.Conn) {
	defer func() { _ = c.Close() }()
	in := bufio.NewScanner(c)
	in.Buffer(make([]byte, 1<<20), 16<<20)
	w := bufio.NewWriter(c)
	for in.Scan() {
		var req request
		var rep reply
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			rep.Error = fmt.Sprintf("bad request: %v", err)
		} else {
			rep = d.handle(&req)
		}
		writeReply(w, rep)
		if err := w.Flush(); err != nil {
			return
		}
	}
}

func writeReply(w *bufio.Writer, rep reply) {
	line := func(k, v string) { fmt.Fprintf(w, "%s %s\n", k, strings.ReplaceAll(v, "\n", " ")) }
	for _, l := range rep.Log {
		line("log", l)
	}
	if rep.Flags != nil {
		line("index", strconv.Itoa(rep.Index))
		line("flags", strconv.Itoa(*rep.Flags))
	}
	if rep.Error != "" {
		line("error", rep.Error)
	}
	fmt.Fprintln(w, "end")
}

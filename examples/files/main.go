// SPDX-License-Identifier: MIT

// Command files shows file transfer (group 70): an outstation that serves a
// directory tree read-only with server.FSFileServer, and a master that
// lists a directory, reads a file and asks for a file's descriptor.
//
//	go run ./examples/files
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"testing/fstest"
	"time"

	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

func main() {
	// Any fs.FS works: os.DirFS("/var/log/rtu") in a real outstation.
	fsys := fstest.MapFS{
		"logs/events.csv": {Data: []byte(strings.Repeat("2026-10-19T12:00:00Z,breaker,open\n", 100)), Mode: 0o644, ModTime: time.Now()},
		"logs/boot.log":   {Data: []byte("boot ok\n"), Mode: 0o600, ModTime: time.Now()},
	}
	srv, err := server.New(server.WithFileServer(server.FSFileServer{FS: fsys}))
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
	c, err := client.Dial(ctx, ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	entries, err := c.ListDirectory(ctx, "/logs", client.FileOptions{})
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		fmt.Printf("%s  %6d  %s\n", e.Permissions, e.Size, e.Name)
	}
	var buf bytes.Buffer
	n, err := c.ReadFile(ctx, "/logs/events.csv", &buf, client.FileOptions{MaxBlockSize: 512})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("read %d octets in blocks of 512; first line: %s", n, strings.SplitAfter(buf.String(), "\n")[0])
	info, err := c.FileInfo(ctx, "/logs/boot.log")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("info: %s %d octets, created %s\n", info.Name, info.Size, info.Created)
}

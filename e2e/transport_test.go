// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

func TestUDP(t *testing.T) {
	srv, err := server.New()
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeUDP(pc) }()
	defer func() { _ = srv.Close() }()

	addr := pc.LocalAddr().String()
	c, err := client.Dial(ctx(t), addr, client.WithStream(client.UDP(addr)), client.WithResponseTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	res, err := c.IntegrityPoll(ctx(t))
	if err != nil || len(res.Measurements()) != 15 {
		t.Fatalf("UDP integrity poll: %v %d", err, len(res.Measurements()))
	}
	if _, err := c.Operate(ctx(t), client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err == nil {
		t.Fatal("control without handler should fail")
	}
}

// TestStream runs the protocol over a plain byte stream, the way a serial
// port is used: the client opens it through WithStream, the server serves
// it with ServeConn.
func TestStream(t *testing.T) {
	srv, err := server.New(server.WithMasters(1))
	if err != nil {
		t.Fatal(err)
	}
	fullDatabase(srv.Database())
	defer func() { _ = srv.Close() }()
	a, b := net.Pipe() // stands in for the two ends of a serial line
	go func() { _ = srv.ServeConn(b, nil) }()
	opened := false
	c, err := client.Dial(ctx(t), "serial:/dev/ttyUSB0", client.WithStream(func(_ context.Context) (io.ReadWriteCloser, net.Addr, error) {
		opened = true
		return a, nil, nil
	}), client.WithResponseTimeout(2*time.Second), client.WithLink(client.Link{KeepAlive: -1}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if !opened || c.Addr() != "serial:/dev/ttyUSB0" {
		t.Fatal("stream opener not used")
	}
	if res, err := c.IntegrityPoll(ctx(t)); err != nil || len(res.Measurements()) != 15 {
		t.Fatalf("stream integrity poll: %v", err)
	}
}

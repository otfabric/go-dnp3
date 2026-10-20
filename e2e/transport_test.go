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

// TestUDPWithConfiguredMaster: with one configured master the association
// exists before any datagram, and its null unsolicited response is sent at
// once. It used to fail the socket ("no UDP peer yet") and end ServeUDP, so
// every later request was lost.
func TestUDPWithConfiguredMaster(t *testing.T) {
	for _, fixedPeer := range []bool{false, true} {
		srv, err := server.New(server.WithMasters(1), server.WithUnsolicited(server.Unsolicited{Enabled: true, RetryDelay: 100 * time.Millisecond}))
		if err != nil {
			t.Fatal(err)
		}
		fullDatabase(srv.Database())
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		// The master's socket, bound first so that its address is known.
		mpc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		errc := make(chan error, 1)
		go func() {
			if fixedPeer {
				errc <- srv.ServeUDPTo(pc, mpc.LocalAddr())
			} else {
				errc <- srv.ServeUDP(pc)
			}
		}()
		time.Sleep(200 * time.Millisecond)
		select {
		case err := <-errc:
			t.Fatalf("fixedPeer=%v: ServeUDP ended before any master spoke: %v", fixedPeer, err)
		default:
		}
		if fixedPeer {
			// The null unsolicited response reached the master unasked.
			_ = mpc.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 512)
			if _, _, err := mpc.ReadFrom(buf); err != nil {
				t.Fatalf("no datagram to the configured master: %v", err)
			}
		}
		_ = mpc.Close()
		addr := pc.LocalAddr().String()
		c, err := client.Dial(ctx(t), addr, client.WithStream(client.UDP(addr)), client.WithResponseTimeout(2*time.Second))
		if err != nil {
			t.Fatalf("fixedPeer=%v: %v", fixedPeer, err)
		}
		res, err := c.IntegrityPoll(ctx(t))
		if err != nil || len(res.Measurements()) != 15 {
			t.Fatalf("fixedPeer=%v: integrity poll over UDP: %v", fixedPeer, err)
		}
		_ = c.Close()
		_ = srv.Close()
	}
}

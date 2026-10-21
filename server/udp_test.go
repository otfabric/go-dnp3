// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// udpMaster is a scripted master on a UDP socket connected to addr.
func udpMaster(t *testing.T, conn net.Conn) (*channel.Session, chan *app.Fragment) {
	t.Helper()
	in := make(chan *app.Fragment, 16)
	ch := channel.New(conn, channel.Config{})
	sess := ch.AddSession(channel.SessionConfig{Local: 1, Remote: 10, Master: true, OnFragment: func(b []byte, _ link.Address) {
		if f, err := app.Decode(b); err == nil {
			in <- f
		}
	}})
	ch.Start()
	t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	return sess, in
}

func recvResponse(t *testing.T, in chan *app.Fragment) *app.Fragment {
	t.Helper()
	for {
		select {
		case f := <-in:
			if f.Function == app.FuncResponse {
				return f
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no response over UDP")
			return nil
		}
	}
}

// TestServeUDP: with one configured master the outstation sends its null
// unsolicited response before any datagram arrived. That must neither end
// the socket (ServeUDP drops it) nor be lost when the master's address is
// configured (ServeUDPTo delivers it).
func TestServeUDP(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		srv, err := New(WithMasters(1), WithUnsolicited(Unsolicited{Enabled: true}))
		if err != nil {
			t.Fatal(err)
		}
		_ = srv.Database().AddBinaryInput(0, PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		errc := make(chan error, 1)
		go func() {
			if fixed {
				errc <- srv.ServeUDPTo(pc, conn.LocalAddr())
			} else {
				errc <- srv.ServeUDP(pc)
			}
		}()
		sess, in := udpMaster(t, conn)
		if fixed {
			// The null unsolicited response arrives unasked.
			select {
			case f := <-in:
				if f.Function != app.FuncUnsolicitedResponse {
					t.Fatalf("first datagram %s", f)
				}
				// Confirmed, as a master does: until then a READ waits.
				b, _ := confirm(f.Control.Seq, true).Encode()
				if err := sess.Send(context.Background(), b); err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no unsolicited response to the configured master")
			}
		} else {
			time.Sleep(100 * time.Millisecond)
		}
		select {
		case err := <-errc:
			t.Fatalf("fixed=%v: serving ended: %v", fixed, err)
		default:
		}
		req := &app.Fragment{Control: app.SingleControl(1), Function: app.FuncRead, Headers: app.ClassHeaders(0)}
		b, _ := req.Encode()
		if err := sess.Send(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		if f := recvResponse(t, in); len(f.Headers) != 1 {
			t.Fatalf("fixed=%v: class 0 over UDP: %s", fixed, f)
		}
		_ = srv.Close()
	}
}

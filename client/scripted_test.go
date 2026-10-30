// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// scripted is an outstation that answers every request with the IIN and
// headers its answer function returns, without the server's logic: it stands in
// for outstations that answer what go-dnp3's never would.
type scripted struct {
	addr string
}

func newScripted(t *testing.T, answer func(req *app.Fragment) (app.IIN, []app.Header)) *scripted {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		reqs := make(chan *app.Fragment, 16)
		sess := ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1,
			OnFragment: func(b []byte, _ link.Address) {
				if f, err := app.Decode(b); err == nil && f.Function != app.FuncConfirm {
					reqs <- f
				}
			}})
		ch.Start()
		defer func() { ch.Close(nil); <-ch.Done() }()
		for {
			select {
			case r := <-reqs:
				iin, hs := answer(r)
				res := &app.Fragment{Control: app.SingleControl(r.Control.Seq), Function: app.FuncResponse, IIN: iin, Headers: hs}
				b, err := res.Encode()
				if err != nil {
					t.Errorf("scripted answer to %s: %v", r, err)
					continue
				}
				_ = sess.Send(context.Background(), b)
			case <-ch.Done():
				return
			}
		}
	}()
	return &scripted{addr: l.Addr().String()}
}

// dialScripted connects a client to a scripted outstation.
func dialScripted(t *testing.T, answer func(req *app.Fragment) (app.IIN, []app.Header)) *Client {
	t.Helper()
	s := newScripted(t, answer)
	c, err := Dial(testCtx(t), s.addr, WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestStartupSyncsTimeFirst: an outstation that needs the time has it
// synchronized before the startup integrity poll, and one that rejects
// DISABLE_UNSOLICITED (IIN2.0: no unsolicited responses) does not fail
// the startup sequence.
func TestStartupSyncsTimeFirst(t *testing.T) {
	var mu sync.Mutex
	var order []app.FunctionCode
	synced := false
	s := newScripted(t, func(r *app.Fragment) (app.IIN, []app.Header) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, r.Function)
		var iin app.IIN
		if r.Function == app.FuncWrite {
			synced = true
		}
		if !synced {
			iin |= app.IINNeedTime
		}
		if r.Function == app.FuncDisableUnsolicited {
			iin |= app.IINNoFuncCodeSupport
		}
		return iin, nil
	})
	c, err := New(s.addr, WithAutoIntegrity(false), WithTimeSync(TimeSyncLAN),
		WithStartup(Startup{DisableUnsolicited: true, Integrity: true}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Connect(testCtx(t)); err != nil {
		t.Fatalf("startup with a rejected DISABLE_UNSOLICITED: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []app.FunctionCode{app.FuncDisableUnsolicited, app.FuncRecordCurrentTime, app.FuncWrite, app.FuncRead}
	if len(order) < len(want) || !slices.Equal(order[:len(want)], want) {
		t.Fatalf("startup requests: %v", order)
	}
}

// TestUDPSurvivesPortUnreachable: an ICMP port unreachable, while the
// outstation is not listening yet, does not end a UDP client's socket.
func TestUDPSurvivesPortUnreachable(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close() // nobody listens: the first datagram draws a port unreachable
	rw, _, err := UDP(addr)(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rw.Close() }()
	if _, err := rw.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := rw.Write([]byte{1}); err != nil {
		t.Fatalf("write after a port unreachable: %v", err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := rw.Read(make([]byte, 4))
		read <- err
	}()
	select {
	case err := <-read:
		t.Fatalf("read after a port unreachable: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = rw.Close()
	if err := <-read; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read of a closed socket: %v", err)
	}
}

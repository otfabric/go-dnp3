// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net"
	"testing"

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

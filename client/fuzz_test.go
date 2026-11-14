// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// FuzzMaster puts the master against an outstation that answers every
// request with an application fragment whose body is the fuzz input, under
// the request's sequence number and under the next one. Whatever arrives,
// the master must neither panic nor hang: each request ends, with a result
// or an error, within its response timeout, and Close returns.
func FuzzMaster(f *testing.F) {
	seeds := []*app.Fragment{
		{Function: app.FuncResponse, Headers: []app.Header{
			app.Ranged(app.G1V2, 0, app.Binary{Value: true, Flags: app.FlagOnline}),
			app.Ranged(app.G30V5, 0, app.Analog{Value: 1.5, Flags: app.FlagOnline}),
			app.Indexed(app.G2V2, app.Object{Index: 3, Value: app.Binary{Flags: app.FlagOnline, Time: 1}}),
		}},
		{Function: app.FuncResponse, IIN: app.IINDeviceRestart | app.IINNeedTime},
		{Function: app.FuncResponse, Headers: []app.Header{
			app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1, Status: app.StatusSuccess}}),
		}},
		{Function: app.FuncResponse, Headers: []app.Header{
			app.Counted(app.G51V1, app.CTO{Time: 1000}),
			app.Indexed(app.G2V3, app.Object{Index: 1, Value: app.Binary{Flags: app.FlagOnline, Time: 1005}}),
		}},
		{Function: app.FuncResponse, Headers: []app.Header{
			app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 1, Size: 5, MaxBlockSize: 1024, RequestID: 1}),
		}},
		{Function: app.FuncAuthResponse, Headers: []app.Header{
			app.FreeFormat(app.G120V1, app.AuthChallenge{CSQ: 1, User: 1, MAC: app.MACHMACSHA256Trunc16, Reason: app.ReasonCritical, Data: make([]byte, 4)}),
		}},
		{Function: app.FuncAuthResponse, Headers: []app.Header{
			app.FreeFormat(app.G120V5, app.AuthSessionKeyStatus{KSQ: 1, User: 1, KeyWrap: app.KeyWrapAES128, Status: app.KeyStatusNotInit, MAC: app.MACHMACSHA256Trunc16, Challenge: make([]byte, 4)}),
		}},
		{Function: app.FuncResponse, Headers: []app.Header{
			app.Ranged(app.GV(0, 252), 0, app.StringAttribute("go-dnp3")),
		}},
	}
	for _, s := range seeds {
		b, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b[2:]) // without control and function: the outstation sets them
	}
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x01, 0x02, 0x00, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 2048 {
			return
		}
		// Everything the input starts ends with Close: the goroutines
		// come back to what they were.
		goroutines := runtime.NumGoroutine()
		masterEnd, outEnd := net.Pipe()
		done := make(chan struct{})
		go answerWith(outEnd, body, done)
		ended := false
		end := func() {
			if !ended {
				ended = true
				_ = outEnd.Close()
				<-done
			}
		}
		defer end()

		opened := false
		c, err := New("fuzz", WithStream(func(context.Context) (io.ReadWriteCloser, net.Addr, error) {
			if opened {
				return nil, nil, io.EOF
			}
			opened = true
			return masterEnd, &net.TCPAddr{}, nil
		}), WithAutoIntegrity(false), WithResponseTimeout(50*time.Millisecond),
			WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: make([]byte, 16)}))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			_ = c.Close()
			end()
			settles(t, goroutines)
			return
		}
		_, _ = c.Read(ctx, app.ClassHeaders(0, 1, 2, 3)...)
		_, _ = c.Operate(ctx, DirectOperate, CROB(0, app.OpLatchOn, 0, 0))
		_, _ = c.ReadAttributes(ctx, 0)
		if ctx.Err() != nil {
			t.Fatal("requests did not end within their response timeouts")
		}
		closed := make(chan struct{})
		go func() { _ = c.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not return")
		}
		end()
		settles(t, goroutines)
	})
}

// settles fails t unless the number of goroutines comes back to at most n
// within 5 seconds.
func settles(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, %d before:\n%s", runtime.NumGoroutine(), n, buf[:runtime.Stack(buf, true)])
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
}

// answerWith runs a raw outstation on conn: every request is answered with
// body under the request's sequence number, and again under the next one,
// so that a body read as a response, a continuation or an unsolicited
// fragment all reach the master.
func answerWith(conn net.Conn, body []byte, done chan<- struct{}) {
	defer close(done)
	ch := channel.New(conn, channel.Config{})
	reqs := make(chan app.Control, 16)
	sess := ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1,
		OnFragment: func(b []byte, _ link.Address) {
			if len(b) >= 2 && app.FunctionCode(b[1]) != app.FuncConfirm {
				select {
				case reqs <- app.ParseControl(b[0]):
				default:
				}
			}
		}})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	for {
		select {
		case c := <-reqs:
			for _, seq := range []uint8{c.Seq, (c.Seq + 1) & 0x0F} {
				fc := byte(app.FuncResponse)
				if len(body) > 0 && body[0]&1 == 1 {
					fc = byte(app.FuncAuthResponse)
				}
				frag := append([]byte{app.SingleControl(seq).Byte(), fc}, body...)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_ = sess.Send(ctx, frag)
				cancel()
			}
		case <-ch.Done():
			return
		}
	}
}

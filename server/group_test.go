// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// groupOf returns a group of outstations at the addresses, each with a
// binary input 0 whose value is its index in addrs being odd, and a
// counting handler.
func groupOf(t *testing.T, addrs ...link.Address) (*Group, []*countingHandler) {
	t.Helper()
	var servers []*Server
	var handlers []*countingHandler
	for i, a := range addrs {
		h := &countingHandler{}
		s, err := New(WithAddress(a), WithMasters(1), WithHandler(h))
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Database().AddBinaryInput(0, PointConfig{}, app.Binary{Value: i%2 == 1, Flags: app.FlagOnline})
		servers = append(servers, s)
		handlers = append(handlers, h)
	}
	g, err := NewGroup(servers...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g, handlers
}

// multidrop is a master with sessions to several outstations on one
// connection.
type multidrop struct {
	ch   *channel.Channel
	sess map[link.Address]*channel.Session
	in   map[link.Address]chan *app.Fragment
}

func newMultidrop(t *testing.T, addr string, outstations ...link.Address) *multidrop {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	m := &multidrop{ch: channel.New(conn, channel.Config{}), sess: map[link.Address]*channel.Session{}, in: map[link.Address]chan *app.Fragment{}}
	for _, o := range outstations {
		in := make(chan *app.Fragment, 16)
		m.in[o] = in
		m.sess[o] = m.ch.AddSession(channel.SessionConfig{Local: 1, Remote: o, Master: true, OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil && f.Function != app.FuncUnsolicitedResponse {
				in <- f
			}
		}})
	}
	m.ch.Start()
	t.Cleanup(func() { m.ch.Close(nil); <-m.ch.Done() })
	return m
}

func (m *multidrop) read(t *testing.T, o link.Address, seq uint8) (*app.Fragment, bool) {
	t.Helper()
	b, _ := req(seq, app.FuncRead, app.AllObjects(app.G1V0)).Encode()
	if err := m.sess[o].Send(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-m.in[o]:
		return f, true
	case <-time.After(500 * time.Millisecond):
		return nil, false
	}
}

// TestGroupMultidrop: one connection, several outstations, each answering
// for itself; a broadcast reaches all; an address nobody has is not
// answered.
func TestGroupMultidrop(t *testing.T) {
	g, handlers := groupOf(t, 10, 11, 12)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(l) }()
	m := newMultidrop(t, l.Addr().String(), 10, 11, 12, 13)
	for i, o := range []link.Address{10, 11, 12} {
		f, ok := m.read(t, o, uint8(i))
		if !ok {
			t.Fatalf("outstation %d did not answer", o)
		}
		if v := f.Headers[0].Objects[0].Value.(app.Binary).Value; v != (i%2 == 1) {
			t.Fatalf("outstation %d answered for another: %v", o, v)
		}
	}
	if _, ok := m.read(t, 13, 0); ok {
		t.Fatal("an address nobody has was answered")
	}
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	b, _ := req(5, app.FuncDirectOperateNoAck, crob).Encode()
	if err := m.sess[10].SendBroadcast(context.Background(), b, link.BroadcastNoConfirm); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, h := range handlers {
		for h.count() != 1 {
			if time.Now().After(deadline) {
				t.Fatal("the broadcast did not reach every outstation")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// A master the outstations do not know (they take master 1 only). Its
	// connection takes over the associations of master 1, so it comes last.
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	stranger := channel.New(conn, channel.Config{})
	in := make(chan []byte, 4)
	ss := stranger.AddSession(channel.SessionConfig{Local: 77, Remote: 10, Master: true, OnFragment: func(b []byte, _ link.Address) { in <- b }})
	stranger.Start()
	defer func() { stranger.Close(nil); <-stranger.Done() }()
	rb, _ := req(0, app.FuncRead, app.AllObjects(app.G1V0)).Encode()
	_ = ss.Send(context.Background(), rb)
	select {
	case <-in:
		t.Fatal("a master the outstations do not take was answered")
	case <-time.After(300 * time.Millisecond):
	}
	if len(g.Servers()) != 3 {
		t.Fatal("Servers")
	}
}

// TestGroupFirstBroadcast: a master's first frame on a connection is a
// broadcast; every outstation of the group carries it out.
func TestGroupFirstBroadcast(t *testing.T) {
	var servers []*Server
	var handlers []*countingHandler
	for _, a := range []link.Address{20, 21} {
		h := &countingHandler{}
		s, _ := New(WithAddress(a), WithHandler(h)) // any master: no session before it speaks
		servers, handlers = append(servers, s), append(handlers, h)
	}
	g, err := NewGroup(servers...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(l) }()
	m := newMultidrop(t, l.Addr().String(), 20)
	b, _ := req(0, app.FuncDirectOperateNoAck, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})).Encode()
	if err := m.sess[20].SendBroadcast(context.Background(), b, link.BroadcastNoConfirm); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, h := range handlers {
		for h.count() != 1 {
			if time.Now().After(deadline) {
				t.Fatal("a first broadcast did not reach every outstation")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestGroupServeAndLimits(t *testing.T) {
	if _, err := NewGroup(); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("empty group")
	}
	a, _ := New(WithAddress(5))
	b, _ := New(WithAddress(5))
	if _, err := NewGroup(a, b); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("two servers with one address")
	}
	if _, err := NewGroup(a, nil); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatal("nil server")
	}

	// The smallest connection limit of the servers.
	s1, _ := New(WithAddress(30), WithMaxConnections(1))
	s2, _ := New(WithAddress(31))
	g, _ := NewGroup(s1, s2)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(l) }()
	first := newMultidrop(t, l.Addr().String(), 30)
	if _, ok := first.read(t, 30, 0); !ok {
		t.Fatal("first connection")
	}
	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection past the limit was kept")
	}
	_ = c2.Close()

	// UDP and ListenAndServe, then Close ends them all.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp := make(chan error, 1)
	go func() { udp <- g.ServeUDP(pc) }()
	las := make(chan error, 1)
	go func() { las <- g.ListenAndServe("127.0.0.1:0") }()
	time.Sleep(50 * time.Millisecond)
	_ = g.Close()
	_ = g.Close()
	for name, c := range map[string]chan error{"ServeUDP": udp, "ListenAndServe": las} {
		select {
		case err := <-c:
			t.Logf("%s ended: %v", name, err)
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not end with Close", name)
		}
	}
	if err := g.Serve(l); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("Serve after Close: %v", err)
	}
	c, s := net.Pipe()
	defer func() { _ = s.Close() }()
	if err := g.ServeConn(c, nil); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("ServeConn after Close: %v", err)
	}
	// A server closed on its own refuses its share of a connection.
	s3, _ := New(WithAddress(40))
	s4, _ := New(WithAddress(41))
	_ = s4.Close()
	g2, _ := NewGroup(s3, s4)
	defer func() { _ = g2.Close() }()
	c, s = net.Pipe()
	defer func() { _ = s.Close() }()
	if err := g2.ServeConn(c, nil); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("ServeConn with a closed server: %v", err)
	}
}

// flakyListener fails Accept with a timeout once, then for good.
type flakyListener struct {
	net.Listener
	calls int
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "accept timed out" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (l *flakyListener) Accept() (net.Conn, error) {
	l.calls++
	switch l.calls {
	case 1:
		return nil, timeoutErr{}
	case 2:
		return nil, syscall.EMFILE
	}
	return nil, fmt.Errorf("listener broken: %w", net.ErrClosed)
}

func TestGroupListeners(t *testing.T) {
	g, _ := groupOf(t, 50)
	// A timeout and running out of file descriptors are waited out; a
	// closed listener ends Serve.
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	fl := &flakyListener{Listener: inner}
	if err := g.Serve(fl); !errors.Is(err, net.ErrClosed) || fl.calls != 3 {
		t.Fatalf("Serve on a failing listener: %v after %d accepts", err, fl.calls)
	}
	// An address that does not parse; the default address, which is free
	// or not on this host, either way returns once the group is closed.
	if err := g.ListenAndServe("127.0.0.1:not-a-port"); err == nil {
		t.Fatal("ListenAndServe on a bad address")
	}
	done := make(chan error, 1)
	go func() { done <- g.ListenAndServe("") }()
	time.Sleep(50 * time.Millisecond)

	// TLS from the first server's WithTLS.
	ts, err := New(WithAddress(51), WithTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	tg, err := NewGroup(ts)
	if err != nil {
		t.Fatal(err)
	}
	tdone := make(chan error, 1)
	go func() { tdone <- tg.ListenAndServe("127.0.0.1:0") }()
	time.Sleep(50 * time.Millisecond)
	_ = tg.Close()
	_ = g.Close()
	for _, c := range []chan error{done, tdone} {
		select {
		case err := <-c:
			t.Logf("ListenAndServe ended: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("ListenAndServe did not return after Close")
		}
	}
}

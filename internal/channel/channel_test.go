// SPDX-License-Identifier: MIT

package channel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

const (
	masterAddr     link.Address = 1
	outstationAddr link.Address = 10
)

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		acc <- c
	}()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-acc
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

type inbox struct {
	ch chan delivery
}

func newInbox() *inbox { return &inbox{ch: make(chan delivery, 16)} }

func (i *inbox) fn(frag []byte, dest link.Address) { i.ch <- delivery{frag, dest} }

func (i *inbox) next(t *testing.T) delivery {
	t.Helper()
	select {
	case d := <-i.ch:
		return d
	case <-time.After(3 * time.Second):
		t.Fatal("no fragment delivered")
		return delivery{}
	}
}

func (i *inbox) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case got := <-i.ch:
		t.Fatalf("unexpected fragment of %d octets", len(got.frag))
	case <-time.After(d):
	}
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

type pair struct {
	mch, och *Channel
	m, o     *Session
	min, oin *inbox
}

func newPair(t *testing.T, confirmed bool) *pair {
	t.Helper()
	a, b := tcpPair(t)
	p := &pair{min: newInbox(), oin: newInbox()}
	p.mch = New(a, Config{Remote: a.RemoteAddr()})
	p.och = New(b, Config{Remote: b.RemoteAddr()})
	p.m = p.mch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true, Confirmed: confirmed,
		ResponseTimeout: 500 * time.Millisecond, OnFragment: p.min.fn})
	p.o = p.och.AddSession(SessionConfig{Local: outstationAddr, Remote: masterAddr, Confirmed: confirmed,
		ResponseTimeout: 500 * time.Millisecond, OnFragment: p.oin.fn})
	p.mch.Start()
	p.och.Start()
	t.Cleanup(func() {
		p.mch.Close(nil)
		p.och.Close(nil)
		<-p.mch.Done()
		<-p.och.Done()
	})
	return p
}

func TestExchange(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		p := newPair(t, confirmed)
		ctx := context.Background()
		for _, n := range []int{2, 249, 250, 2048} {
			frag := payload(n)
			if err := p.m.Send(ctx, frag); err != nil {
				t.Fatal(err)
			}
			if d := p.oin.next(t); !bytes.Equal(d.frag, frag) || d.dest != outstationAddr {
				t.Fatalf("confirmed=%v n=%d: outstation got %d octets", confirmed, n, len(d.frag))
			}
			if err := p.o.Send(ctx, frag); err != nil {
				t.Fatal(err)
			}
			if d := p.min.next(t); !bytes.Equal(d.frag, frag) {
				t.Fatalf("confirmed=%v n=%d: master got %d octets", confirmed, n, len(d.frag))
			}
		}
		if p.m.Local() != masterAddr || p.m.Remote() != outstationAddr || p.m.Channel() != p.mch || len(p.mch.Sessions()) != 1 {
			t.Fatal("accessors")
		}
	}
}

func TestConcurrentSendsKeepFragmentsWhole(t *testing.T) {
	p := newPair(t, true)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.m.Send(context.Background(), bytes.Repeat([]byte{byte(i)}, 600)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	seen := map[byte]bool{}
	for range 8 {
		d := p.oin.next(t)
		if len(d.frag) != 600 || !bytes.Equal(d.frag, bytes.Repeat(d.frag[:1], 600)) {
			t.Fatal("interleaved fragment")
		}
		seen[d.frag[0]] = true
	}
	if len(seen) != 8 {
		t.Fatalf("%d distinct fragments", len(seen))
	}
}

// rawPeer is the far end of a channel, driven frame by frame.
type rawPeer struct {
	t    *testing.T
	conn net.Conn
	r    *link.Reader
}

func newRaw(t *testing.T, conn net.Conn) *rawPeer {
	return &rawPeer{t: t, conn: conn, r: link.NewReader(conn)}
}

func (p *rawPeer) write(f link.Frame) {
	p.t.Helper()
	b, err := f.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.conn.Write(b); err != nil {
		p.t.Fatal(err)
	}
}

func (p *rawPeer) read() link.Frame {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := p.r.ReadFrame()
	if err != nil {
		p.t.Fatal(err)
	}
	return f
}

func (p *rawPeer) silent(d time.Duration) {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(d))
	if f, err := p.r.ReadFrame(); err == nil {
		p.t.Fatalf("unexpected frame %s", f.String())
	}
}

func segmentOf(data []byte) []byte {
	return append([]byte{byte(transport.NewHeader(true, true, 0))}, data...)
}

// outstationWithRaw returns an outstation channel and a raw master.
func outstationWithRaw(t *testing.T, cfg SessionConfig) (*Session, *rawPeer, *inbox) {
	t.Helper()
	a, b := tcpPair(t)
	in := newInbox()
	ch := New(b, Config{Remote: b.RemoteAddr()})
	cfg.Local, cfg.Remote, cfg.OnFragment = outstationAddr, masterAddr, in.fn
	s := ch.AddSession(cfg)
	ch.Start()
	t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	return s, newRaw(t, a), in
}

func TestSecondaryProcedures(t *testing.T) {
	_, m, in := outstationWithRaw(t, SessionConfig{})
	pri := func(fn link.Function, fcb bool, data []byte) link.Frame {
		return link.Frame{Dir: true, Function: fn, FCB: fcb, FCV: fn.UsesFCB(), Dest: outstationAddr, Src: masterAddr, Data: data}
	}

	// Confirmed user data before a reset is ignored.
	m.write(pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1})))
	m.silent(200 * time.Millisecond)
	in.none(t, 50*time.Millisecond)

	// Request link status.
	m.write(pri(link.PrimaryRequestLinkStatus, false, nil))
	if f := m.read(); f.Function != link.SecondaryLinkStatus || f.Dir || f.Dest != masterAddr || f.Src != outstationAddr {
		t.Fatalf("link status reply %s", f.String())
	}
	// Test link states before reset: ignored.
	m.write(pri(link.PrimaryTestLinkStates, true, nil))
	m.silent(200 * time.Millisecond)

	// Reset, then data with FCB 1, a repeat of it, then FCB 0.
	m.write(pri(link.PrimaryResetLinkStates, false, nil))
	if f := m.read(); f.Function != link.SecondaryAck {
		t.Fatalf("reset reply %s", f.String())
	}
	m.write(pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1})))
	if f := m.read(); f.Function != link.SecondaryAck {
		t.Fatal(f.String())
	}
	m.write(pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1})))
	if f := m.read(); f.Function != link.SecondaryAck {
		t.Fatal(f.String())
	}
	m.write(pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{2})))
	m.read()
	if d := in.next(t); !bytes.Equal(d.frag, []byte{1}) {
		t.Fatalf("first %v", d.frag)
	}
	if d := in.next(t); !bytes.Equal(d.frag, []byte{2}) {
		t.Fatalf("second %v (repeat not discarded)", d.frag)
	}

	// Test link states with the expected FCB (1) toggles it.
	m.write(pri(link.PrimaryTestLinkStates, true, nil))
	if f := m.read(); f.Function != link.SecondaryAck {
		t.Fatal(f.String())
	}
	m.write(pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{3})))
	m.read()
	if d := in.next(t); !bytes.Equal(d.frag, []byte{3}) {
		t.Fatal("after test link states")
	}

	// A frame with the wrong DIR bit, and an invalid FCV, are ignored.
	bad := pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{4}))
	bad.Dir = false
	m.write(bad)
	bad = pri(link.PrimaryRequestLinkStatus, false, nil)
	bad.FCV = true
	m.write(bad)
	m.silent(200 * time.Millisecond)
	in.none(t, 50*time.Millisecond)

	// Broadcast user data is delivered with its destination and not
	// acknowledged; other broadcast functions are ignored.
	bc := pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{5}))
	bc.Dest = link.BroadcastConfirm
	m.write(bc)
	if d := in.next(t); d.dest != link.BroadcastConfirm {
		t.Fatalf("broadcast dest %d", d.dest)
	}
	bc = pri(link.PrimaryRequestLinkStatus, false, nil)
	bc.Dest = link.BroadcastNoConfirm
	m.write(bc)
	m.silent(200 * time.Millisecond)

	// A transport error is reported and the stream goes on.
	m.write(pri(link.PrimaryUnconfirmedUserData, false, []byte{byte(transport.NewHeader(false, true, 9)), 1}))
	m.write(pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{6})))
	if d := in.next(t); !bytes.Equal(d.frag, []byte{6}) {
		t.Fatal("after transport error")
	}

	// Frames for another address are dropped.
	other := pri(link.PrimaryRequestLinkStatus, false, nil)
	other.Dest = 99
	m.write(other)
	m.silent(200 * time.Millisecond)
}

func TestPrimaryConfirmedRetriesAndNack(t *testing.T) {
	a, b := tcpPair(t)
	ch := New(a, Config{Remote: a.RemoteAddr()})
	s := ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true, Confirmed: true,
		ResponseTimeout: 200 * time.Millisecond, Retries: 1})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	o := newRaw(t, b)
	sec := func(fn link.Function) link.Frame {
		return link.Frame{Function: fn, Dest: masterAddr, Src: outstationAddr}
	}

	errc := make(chan error, 1)
	go func() { errc <- s.Send(context.Background(), []byte{0xAA}) }()
	if f := o.read(); f.Function != link.PrimaryResetLinkStates {
		t.Fatal(f.String())
	}
	o.write(sec(link.SecondaryAck))
	f := o.read()
	if f.Function != link.PrimaryConfirmedUserData || !f.FCB || !f.FCV {
		t.Fatal(f.String())
	}
	// No answer: repeated with the same FCB.
	if r := o.read(); r.Function != link.PrimaryConfirmedUserData || !r.FCB {
		t.Fatal("retry", r.String())
	}
	// NACK: the link is reset and the frame sent once more.
	o.write(sec(link.SecondaryNack))
	if r := o.read(); r.Function != link.PrimaryResetLinkStates {
		t.Fatal(r.String())
	}
	o.write(sec(link.SecondaryAck))
	if r := o.read(); r.Function != link.PrimaryConfirmedUserData || !r.FCB {
		t.Fatal(r.String())
	}
	o.write(sec(link.SecondaryAck))
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	// The next frame toggles the FCB.
	go func() { errc <- s.Send(context.Background(), []byte{0xBB}) }()
	if r := o.read(); r.FCB {
		t.Fatal("FCB not toggled")
	}
	o.write(sec(link.SecondaryNotSupported))
	if err := <-errc; !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("not supported: %v", err)
	}
	// Silence: timeout after the retries.
	go func() { errc <- s.Send(context.Background(), []byte{0xCC}) }()
	o.read() // reset
	o.read() // repeat
	if err := <-errc; !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("timeout: %v", err)
	}
	// Context cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { errc <- s.Send(ctx, []byte{0xDD}) }()
	o.read()
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	// A secondary frame nobody waits for is ignored.
	o.write(sec(link.SecondaryAck))
}

func TestKeepAlive(t *testing.T) {
	a, b := tcpPair(t)
	ch := New(a, Config{Remote: a.RemoteAddr()})
	ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true,
		KeepAlive: 150 * time.Millisecond, ResponseTimeout: 150 * time.Millisecond})
	ch.Start()
	o := newRaw(t, b)

	// Answered probes keep the channel open.
	for range 2 {
		f := o.read()
		if f.Function != link.PrimaryRequestLinkStatus {
			t.Fatal(f.String())
		}
		o.write(link.Frame{Function: link.SecondaryLinkStatus, Dest: masterAddr, Src: outstationAddr})
	}
	// An unanswered one closes it.
	o.read()
	select {
	case <-ch.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("channel not closed")
	}
	if err := ch.Err(); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("Err = %v", err)
	}
}

func TestAcceptAndRemove(t *testing.T) {
	a, b := tcpPair(t)
	in := newInbox()
	var och *Channel
	och = New(b, Config{Remote: b.RemoteAddr(), Accept: func(local, remote link.Address) *Session {
		if local != outstationAddr {
			return nil
		}
		return och.AddSession(SessionConfig{Local: local, Remote: remote, OnFragment: in.fn})
	}})
	och.Start()
	defer func() { och.Close(nil); <-och.Done() }()
	m := newRaw(t, a)
	m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: 77, Data: segmentOf([]byte{9})})
	if d := in.next(t); !bytes.Equal(d.frag, []byte{9}) {
		t.Fatal("accepted session did not deliver")
	}
	ss := och.Sessions()
	if len(ss) != 1 || ss[0].Remote() != 77 {
		t.Fatal("session not added")
	}
	if och.Session(outstationAddr, 77) != ss[0] || och.Session(outstationAddr, 78) != nil {
		t.Fatal("Session")
	}
	ss[0].Remove()
	ss[0].Remove()
	if err := ss[0].Send(context.Background(), []byte{1}); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("send on removed session: %v", err)
	}
	if again := och.AddSession(SessionConfig{Local: 1, Remote: 2}); och.AddSession(SessionConfig{Local: 1, Remote: 2}) != again {
		t.Fatal("AddSession twice")
	}
}

func TestStreamFailure(t *testing.T) {
	a, b := tcpPair(t)
	ch := New(a, Config{Remote: a.RemoteAddr()})
	s := ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true})
	ch.Start()
	_ = b.Close()
	select {
	case <-ch.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("not closed on EOF")
	}
	if !errors.Is(ch.Err(), dnp3.ErrConnectionLost) {
		t.Fatalf("Err = %v", ch.Err())
	}
	if err := s.Send(context.Background(), []byte{1}); !errors.Is(err, dnp3.ErrConnectionLost) {
		t.Fatalf("send after loss: %v", err)
	}
	if err := s.SendBroadcast(context.Background(), []byte{1}, 5); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("broadcast to non-broadcast: %v", err)
	}

	// Closed by the application: Err is nil, sends report ErrClosed.
	c, _ := tcpPair(t)
	ch = New(c, Config{})
	s = ch.AddSession(SessionConfig{Local: 1, Remote: 2})
	ch.Start()
	ch.Close(nil)
	<-ch.Done()
	if ch.Err() != nil || !errors.Is(s.Send(context.Background(), []byte{1}), dnp3.ErrClosed) {
		t.Fatal("orderly close")
	}
	select {
	case <-ch.Closing():
	default:
		t.Fatal("Closing not closed")
	}
}

func TestQueueFull(t *testing.T) {
	a, b := tcpPair(t)
	block := make(chan struct{})
	ch := New(b, Config{})
	ch.AddSession(SessionConfig{Local: outstationAddr, Remote: masterAddr, QueueSize: 1,
		OnFragment: func([]byte, link.Address) { <-block }})
	ch.Start()
	defer func() { close(block); ch.Close(nil); <-ch.Done() }()
	m := newRaw(t, a)
	for i := range 5 {
		m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: masterAddr, Data: segmentOf([]byte{byte(i)})})
	}
	// The reader is not blocked: a link status request is still answered.
	m.write(link.Frame{Dir: true, Function: link.PrimaryRequestLinkStatus, Dest: outstationAddr, Src: masterAddr})
	if f := m.read(); f.Function != link.SecondaryLinkStatus {
		t.Fatal(f.String())
	}
}

func TestBroadcastFromMaster(t *testing.T) {
	p := newPair(t, true)
	// A broadcast is sent unconfirmed even on a confirmed session.
	if err := p.m.SendBroadcast(context.Background(), []byte{1, 2}, link.BroadcastOptionalConfirm); err != nil {
		t.Fatal(err)
	}
	if d := p.oin.next(t); d.dest != link.BroadcastOptionalConfirm || !bytes.Equal(d.frag, []byte{1, 2}) {
		t.Fatalf("broadcast %v %d", d.frag, d.dest)
	}
	// A broadcast towards the master is ignored.
	if err := p.o.SendBroadcast(context.Background(), []byte{3}, link.BroadcastNoConfirm); err != nil {
		t.Fatal(err)
	}
	p.min.none(t, 200*time.Millisecond)
}

// TestFragmentsBeforeEOFAreDelivered: a peer that sends fragments and
// closes at once (a master confirming a response and hanging up) must have
// every fragment delivered, also those still queued when the stream ends.
func TestFragmentsBeforeEOFAreDelivered(t *testing.T) {
	for range 20 {
		a, b := tcpPair(t)
		release := make(chan struct{})
		var mu sync.Mutex
		var got [][]byte
		ch := New(b, Config{})
		ch.AddSession(SessionConfig{Local: outstationAddr, Remote: masterAddr,
			OnFragment: func(frag []byte, _ link.Address) {
				<-release // hold the first one so that the rest wait in the queue
				mu.Lock()
				got = append(got, frag)
				mu.Unlock()
			}})
		ch.Start()
		m := newRaw(t, a)
		for i := range 3 {
			m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: masterAddr,
				Data: segmentOf([]byte{byte(i)})})
		}
		_ = a.Close()
		select {
		case <-ch.Closing():
		case <-time.After(3 * time.Second):
			t.Fatal("channel not closed on EOF")
		}
		close(release)
		<-ch.Done()
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n != 3 {
			t.Fatalf("%d of 3 fragments delivered after the peer closed", n)
		}
	}
}

// TestAcceptOnBroadcast: a master's first frame may be a broadcast; the
// channel asks Accept for its session, and a refused one drops the frame.
func TestAcceptOnBroadcast(t *testing.T) {
	a, b := tcpPair(t)
	in := newInbox()
	var och *Channel
	och = New(b, Config{Remote: b.RemoteAddr(), Accept: func(local, remote link.Address) *Session {
		if remote != 77 {
			return nil
		}
		return och.AddSession(SessionConfig{Local: outstationAddr, Remote: remote, OnFragment: in.fn})
	}})
	och.Start()
	defer func() { och.Close(nil); <-och.Done() }()
	m := newRaw(t, a)
	m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: link.BroadcastNoConfirm, Src: 78, Data: segmentOf([]byte{8})})
	m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: link.BroadcastNoConfirm, Src: 77, Data: segmentOf([]byte{9})})
	if d := in.next(t); !bytes.Equal(d.frag, []byte{9}) || d.dest != link.BroadcastNoConfirm {
		t.Fatalf("broadcast as first frame: %v to %d", d.frag, d.dest)
	}
	if ss := och.Sessions(); len(ss) != 1 || ss[0].Remote() != 77 {
		t.Fatal("refused master got a session")
	}
}

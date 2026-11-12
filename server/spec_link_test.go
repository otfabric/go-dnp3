// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// Spec tests: the outstation's side of IEEE 1815-2012 clause 13 (DNP3 over
// TCP and UDP) and of the link layer addressing of clause 9.2.5, against
// raw masters on loopback sockets and an in-memory UDP socket. Page
// numbers are printed pages.

// rawMaster is a master at link address 1 that writes link frames and
// reads the outstation's frames one by one: on a TCP connection, or on a
// connected UDP socket, where every datagram must decode to whole frames
// (clause 13.2.3.2.3).
type rawMaster struct {
	t       *testing.T
	conn    net.Conn
	udp     bool
	r       *link.Reader
	pending []link.Frame // the rest of the last datagram
	sg      transport.Segmenter
	ra      *transport.Reassembler
	frames  int // frames of the last response
}

func dialRaw(t *testing.T, network, addr string) *rawMaster {
	t.Helper()
	conn, err := net.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, udp := conn.(*net.UDPConn)
	return &rawMaster{t: t, conn: conn, udp: udp, r: link.NewReader(conn), ra: transport.NewReassembler(0)}
}

func encodeFrames(t *testing.T, fs ...link.Frame) []byte {
	t.Helper()
	var b []byte
	for _, f := range fs {
		e, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, e...)
	}
	return b
}

// write sends frames in one write: one datagram over UDP.
func (m *rawMaster) write(fs ...link.Frame) { m.writeRaw(encodeFrames(m.t, fs...)) }

func (m *rawMaster) writeRaw(b []byte) {
	m.t.Helper()
	if _, err := m.conn.Write(b); err != nil {
		m.t.Fatal(err)
	}
}

// rls is a REQUEST_LINK_STATUS from the master to dest.
func rls(dest link.Address) link.Frame {
	return link.Frame{Dir: true, Function: link.PrimaryRequestLinkStatus, Dest: dest, Src: 1}
}

// requestFrames returns the UNCONFIRMED_USER_DATA frames that carry f to
// dest.
func (m *rawMaster) requestFrames(dest link.Address, f *app.Fragment) []link.Frame {
	m.t.Helper()
	b, err := f.Encode()
	if err != nil {
		m.t.Fatal(err)
	}
	var fs []link.Frame
	for _, s := range m.sg.Segment(b) {
		fs = append(fs, link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: dest, Src: 1, Data: s})
	}
	return fs
}

func (m *rawMaster) request(dest link.Address, f *app.Fragment) { m.write(m.requestFrames(dest, f)...) }

// frame returns the next frame within d.
func (m *rawMaster) frame(d time.Duration) (link.Frame, error) {
	if len(m.pending) > 0 {
		f := m.pending[0]
		m.pending = m.pending[1:]
		return f, nil
	}
	_ = m.conn.SetReadDeadline(time.Now().Add(d))
	if !m.udp {
		return m.r.ReadFrame()
	}
	buf := make([]byte, 65535)
	n, err := m.conn.Read(buf)
	if err != nil {
		return link.Frame{}, err
	}
	for b := buf[:n]; len(b) > 0; {
		f, k, err := link.Decode(b)
		if err != nil {
			m.t.Fatalf("a datagram of %d octets does not hold whole frames: %v", n, err)
		}
		m.pending = append(m.pending, f)
		b = b[k:]
	}
	return m.frame(d)
}

// next returns the next frame from the outstation.
func (m *rawMaster) next() link.Frame {
	m.t.Helper()
	f, err := m.frame(3 * time.Second)
	if err != nil {
		m.t.Fatalf("no frame from the outstation: %v", err)
	}
	return f
}

// linkStatus reads the next frame, a LINK_STATUS from src.
func (m *rawMaster) linkStatus(src link.Address) {
	m.t.Helper()
	if f := m.next(); f.Function != link.SecondaryLinkStatus || f.Src != src || f.Dest != 1 || f.Dir {
		m.t.Fatalf("got %s, want LINK_STATUS from %d", f.String(), src)
	}
}

// noReply checks that what was sent before drew no link layer reply: a
// REQUEST_LINK_STATUS to the outstation at addr sent after it is answered
// first. The outstation answers link frames in the order they arrive.
func (m *rawMaster) noReply(addr link.Address) {
	m.t.Helper()
	m.write(rls(addr))
	m.linkStatus(addr)
}

// response reads frames until a whole fragment from src arrived and
// decodes it. Keep-alives of the outstation are skipped; any other frame
// fails the test: the outstation sends user data as UNCONFIRMED_USER_DATA,
// without a reset (clause 13.2.1.1).
func (m *rawMaster) response(src link.Address) *app.Fragment {
	m.t.Helper()
	m.frames = 0
	for {
		f := m.next()
		if f.Function == link.PrimaryRequestLinkStatus && f.Src == src {
			continue
		}
		if f.Function != link.PrimaryUnconfirmedUserData || f.Src != src || f.Dest != 1 || f.Dir {
			m.t.Fatalf("got %s while a response from %d was expected", f.String(), src)
		}
		m.frames++
		frag, err := m.ra.Add(f.Data)
		if err != nil {
			m.t.Fatal(err)
		}
		if frag == nil {
			continue
		}
		a, err := app.Decode(frag)
		if err != nil {
			m.t.Fatal(err)
		}
		return a
	}
}

// closed reads until the outstation closes the connection, within 3
// seconds, and returns the frames it sent before.
func (m *rawMaster) closed() []link.Frame {
	m.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got []link.Frame
	for {
		f, err := m.frame(time.Until(deadline))
		if err == nil {
			got = append(got, f)
			continue
		}
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
			m.t.Fatalf("the outstation did not close the connection; it sent %d frames", len(got))
		}
		return got
	}
}

func newServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// serveTCP serves s on a loopback listener and returns its address.
func serveTCP(t *testing.T, s *Server) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(l) }()
	return l.Addr().String()
}

// serveUDP serves s on a loopback UDP socket and returns its address and
// the channel ServeUDP's result goes to.
func serveUDP(t *testing.T, s *Server) (string, chan error) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- s.ServeUDP(pc) }()
	return pc.LocalAddr().String(), errc
}

// dialLinkMaster connects the scripted master of the conformance tests, whose
// link layer answers the outstation's keep-alives.
func dialLinkMaster(t *testing.T, addr string) *master {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	m := &master{t: t, in: make(chan *app.Fragment, 32)}
	m.ch = channel.New(conn, channel.Config{})
	m.sess = m.ch.AddSession(channel.SessionConfig{Local: 1, Remote: 10, Master: true,
		OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil {
				m.in <- f
			}
		}})
	m.ch.Start()
	t.Cleanup(func() { m.ch.Close(nil); <-m.ch.Done() })
	return m
}

// eventually polls cond until it holds, for at most 3 seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 3 seconds", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// readIIN is a READ of the internal indications.
func readIIN(seq uint8) *app.Fragment { return req(seq, app.FuncRead, app.AllObjects(app.G80V1)) }

// latchOn is a DIRECT_OPERATE_NO_ACK of control 0, as a broadcast carries.
func linkLatchOn(seq uint8) *app.Fragment {
	return req(seq, app.FuncDirectOperateNoAck, app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}}))
}

// framingMetrics counts framing errors.
type framingMetrics struct {
	dnp3.NopMetrics
	n atomic.Int64
}

func (m *framingMetrics) OnFramingError(net.Addr, error) { m.n.Add(1) }

// TestSpec13_2_3_3_SecondConnectionRejected checks clause 13.2.3.3 (p.
// 382) and its NOTE 2: a new connection from a master that is already
// connected is rejected once a keep-alive on the current connection shows
// that one stands. With WithMasters the session exists from the connect,
// so a connection that never speaks is rejected as well; without it, the
// second connection is rejected when it speaks. The current connection
// keeps working, and the second one gets no application response.
func TestSpec13_2_3_3_SecondConnectionRejected(t *testing.T) {
	for _, c := range []struct {
		name  string
		opts  []Option
		speak bool
	}{
		{"configured master, silent", []Option{WithMasters(1)}, false},
		{"any master, speaking", nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr := serveTCP(t, newServer(t, c.opts...))
			m := dialLinkMaster(t, addr)
			m.send(readIIN(1))
			m.recvFunc(app.FuncResponse)
			p := dialRaw(t, "tcp", addr)
			if c.speak {
				p.write(append([]link.Frame{rls(10)}, p.requestFrames(10, readIIN(2))...)...)
			}
			for _, f := range p.closed() {
				if f.Function != link.SecondaryLinkStatus {
					t.Fatalf("the rejected connection got %s", f.String())
				}
			}
			m.send(readIIN(3))
			if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 {
				t.Fatalf("response %s", f)
			}
			if closing(m.ch) {
				t.Fatalf("the current connection closed: %v", m.ch.Err())
			}
		})
	}
}

// TestSpec13_2_3_3_HalfOpenConnectionReplaced checks clause 13.2.3.3 NOTE
// 2 (p. 382) with Table 13-2 row 4 (p. 383): when the current connection
// leaves the keep-alive unanswered, as a half-open one does, it is closed
// and the master's new connection is taken.
func TestSpec13_2_3_3_HalfOpenConnectionReplaced(t *testing.T) {
	addr := serveTCP(t, newServer(t, WithMasters(1), WithLink(Link{Timeout: 100 * time.Millisecond})))
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	if f := old.response(10); f.Control.Seq != 1 {
		t.Fatalf("response %s", f)
	}
	// The old connection falls silent; the master connects again.
	m := dialLinkMaster(t, addr)
	fs := old.closed()
	if len(fs) != 1 || fs[0].Function != link.PrimaryRequestLinkStatus || fs[0].Src != 10 {
		t.Fatalf("the old connection got %v, want one keep-alive", fs)
	}
	m.send(readIIN(2))
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpec13_2_3_3_RequestDuringProbe: a request the master sends on its
// new connection while the current one is probed (clause 13.2.3.3 NOTE 2,
// p. 382) is held, and answered once the probe goes unanswered and the
// new connection is taken (Table 13-2 row 4, p. 383). Dropped, it would
// cost the master a response timeout, and a session key change at
// connect would fail. On a rejected connection it gets no answer.
func TestSpec13_2_3_3_RequestDuringProbe(t *testing.T) {
	t.Run("taken", func(t *testing.T) {
		addr := serveTCP(t, newServer(t, WithMasters(1), WithLink(Link{Timeout: 300 * time.Millisecond})))
		old := dialRaw(t, "tcp", addr)
		old.request(10, readIIN(1))
		if f := old.response(10); f.Control.Seq != 1 {
			t.Fatalf("response %s", f)
		}
		m := dialLinkMaster(t, addr)
		m.send(readIIN(2)) // while the old connection is probed
		if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 2 {
			t.Fatalf("response %s", f)
		}
		if fs := old.closed(); len(fs) != 1 || fs[0].Function != link.PrimaryRequestLinkStatus {
			t.Fatalf("the old connection got %v, want one keep-alive", fs)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		addr := serveTCP(t, newServer(t, WithMasters(1)))
		m := dialLinkMaster(t, addr)
		m.send(readIIN(1))
		m.recvFunc(app.FuncResponse)
		p := dialRaw(t, "tcp", addr)
		p.write(p.requestFrames(10, readIIN(2))...)
		for _, f := range p.closed() {
			if f.Function != link.SecondaryLinkStatus {
				t.Fatalf("the rejected connection got %s", f.String())
			}
		}
		m.send(readIIN(3))
		if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 3 {
			t.Fatalf("response %s", f)
		}
	})
}

// TestSpec13_2_3_3_1_IdleConnection checks clause 13.2.3.3.1 (p. 382)
// and Table 13-2 row 4 (p. 383) on the outstation: a connection on which
// no master spoke is closed after the keep-alive interval and the link
// timeout, as an unanswered keep-alive would close it, and the listener
// takes the next connection; with a configured master the keep-alive is
// sent and, unanswered, closes the connection; an answered keep-alive
// keeps it.
func TestSpec13_2_3_3_1_IdleConnection(t *testing.T) {
	lk := WithLink(Link{KeepAlive: 100 * time.Millisecond, Timeout: 50 * time.Millisecond})
	t.Run("no master spoke", func(t *testing.T) {
		s := newServer(t, lk)
		addr := serveTCP(t, s)
		start := time.Now()
		p := dialRaw(t, "tcp", addr)
		if fs := p.closed(); len(fs) != 0 {
			t.Fatalf("frames to a silent connection: %v", fs)
		}
		if d := time.Since(start); d < 150*time.Millisecond {
			t.Fatalf("closed after %v, before the keep-alive interval and the timeout", d)
		}
		eventually(t, "the connection is released", func() bool { return s.connections() == 0 })
		q := dialRaw(t, "tcp", addr)
		q.write(rls(10))
		q.linkStatus(10)
	})
	t.Run("configured master, unanswered", func(t *testing.T) {
		p := dialRaw(t, "tcp", serveTCP(t, newServer(t, lk, WithMasters(1))))
		fs := p.closed()
		if len(fs) != 1 || fs[0].Function != link.PrimaryRequestLinkStatus || fs[0].Dest != 1 || fs[0].Src != 10 {
			t.Fatalf("got %v, want one keep-alive", fs)
		}
	})
	t.Run("answered", func(t *testing.T) {
		p := dialRaw(t, "tcp", serveTCP(t, newServer(t, lk)))
		p.write(rls(10))
		p.linkStatus(10)
		for range 3 {
			if f := p.next(); f.Function != link.PrimaryRequestLinkStatus || f.Src != 10 || f.Dir {
				t.Fatalf("got %s, want a keep-alive", f.String())
			}
			p.write(link.Frame{Dir: true, Function: link.SecondaryLinkStatus, Dest: 10, Src: 1})
		}
	})
}

// TestSpec13_2_3_3_1_SilentLimit checks the limit of the idle connection:
// the keep-alive interval plus the link timeout, with their defaults (60
// and 2 seconds), the longest of a group, and none where the keep-alive
// is disabled or the stream is not TCP.
func TestSpec13_2_3_3_1_SilentLimit(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
	udp := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
	srv := func(l Link) *Server { return newServer(t, WithLink(l)) }
	for i, c := range []struct {
		remote  net.Addr
		servers []*Server
		want    time.Duration
		ok      bool
	}{
		{tcp, []*Server{srv(Link{})}, 62 * time.Second, true},
		{tcp, []*Server{srv(Link{KeepAlive: 5 * time.Second, Timeout: time.Second})}, 6 * time.Second, true},
		{tcp, []*Server{srv(Link{KeepAlive: time.Second}), srv(Link{KeepAlive: 3 * time.Second, Timeout: 500 * time.Millisecond})}, 3500 * time.Millisecond, true},
		{tcp, []*Server{srv(Link{}), srv(Link{KeepAlive: -1})}, 0, false},
		{udp, []*Server{srv(Link{})}, 0, false},
		{nil, []*Server{srv(Link{})}, 0, false},
	} {
		if got, ok := silentLimit(c.remote, c.servers); got != c.want || ok != c.ok {
			t.Errorf("case %d: %v %v, want %v %v", i, got, ok, c.want, c.ok)
		}
	}
}

// TestSpec13_2_3_2_4_UDPBroadcast checks clause 13.2.3.2.4 (p. 382): a
// broadcast in a UDP datagram is carried out by the outstation, and by
// every outstation of a Group on the socket, and the next response sets
// IIN1.0, the broadcast indication.
func TestSpec13_2_3_2_4_UDPBroadcast(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		h := &countingHandler{}
		addr, _ := serveUDP(t, newServer(t, WithHandler(h)))
		p := dialRaw(t, "udp", addr)
		p.request(link.BroadcastNoConfirm, linkLatchOn(1))
		eventually(t, "the broadcast control", func() bool { return h.count() == 1 })
		p.request(10, readIIN(2))
		if f := p.response(10); !f.IIN.Has(app.IINBroadcast) {
			t.Fatalf("IIN %s after a broadcast", f.IIN)
		}
	})
	t.Run("group", func(t *testing.T) {
		g, hs := groupOf(t, 10, 11)
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = g.ServeUDP(pc) }()
		p := dialRaw(t, "udp", pc.LocalAddr().String())
		p.request(link.BroadcastNoConfirm, linkLatchOn(1))
		eventually(t, "the broadcast control", func() bool { return hs[0].count() == 1 && hs[1].count() == 1 })
		for i, o := range []link.Address{10, 11} {
			p.request(o, readIIN(uint8(2+i)))
			if f := p.response(o); !f.IIN.Has(app.IINBroadcast) {
				t.Fatalf("outstation %d: IIN %s after a broadcast", o, f.IIN)
			}
		}
	})
}

// TestSpecTable13_1_BroadcastOverUDPBesideTCP checks Table 13-1 (p. 381)
// with clause 13.2.3.2.4 (p. 382): a master connected over TCP sends its
// broadcasts over UDP, from any source port. Each is carried out, the TCP
// connection stays the master's, its next response sets IIN1.0, and the
// UDP socket keeps serving.
func TestSpecTable13_1_BroadcastOverUDPBesideTCP(t *testing.T) {
	h := &countingHandler{}
	s := newServer(t, WithHandler(h))
	tcpAddr := serveTCP(t, s)
	udpAddr, udpDone := serveUDP(t, s)
	m := dialLinkMaster(t, tcpAddr)
	m.send(readIIN(1))
	m.recvFunc(app.FuncResponse)
	for i := range 2 {
		p := dialRaw(t, "udp", udpAddr) // a socket, and a source port, of its own
		p.request(link.BroadcastNoConfirm, linkLatchOn(uint8(2+i)))
		eventually(t, "the broadcast control", func() bool { return h.count() == i+1 })
	}
	m.send(readIIN(4))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINBroadcast) {
		t.Fatalf("IIN %s after the UDP broadcasts", f.IIN)
	}
	if closing(m.ch) {
		t.Fatalf("the TCP connection closed: %v", m.ch.Err())
	}
	select {
	case err := <-udpDone:
		t.Fatalf("the UDP socket ended: %v", err)
	default:
	}
}

// TestSpec13_2_3_3_1_UDPKeepAliveFailure: the keep-alive of clause
// 13.2.3.3.1 (p. 382) monitors a TCP connection; Table 13-2 (p. 383)
// closes connections, which a UDP socket does not have. An unanswered
// keep-alive over UDP leaves the socket serving.
func TestSpec13_2_3_3_1_UDPKeepAliveFailure(t *testing.T) {
	addr, done := serveUDP(t, newServer(t, WithLink(Link{KeepAlive: 50 * time.Millisecond, Timeout: 30 * time.Millisecond})))
	p := dialRaw(t, "udp", addr)
	p.request(10, readIIN(1))
	p.response(10)
	for range 2 {
		if f := p.next(); f.Function != link.PrimaryRequestLinkStatus || f.Src != 10 {
			t.Fatalf("got %s, want a keep-alive", f.String())
		}
	}
	select {
	case err := <-done:
		t.Fatalf("the socket ended: %v", err)
	default:
	}
	p.request(10, readIIN(2))
	if f := p.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpec13_2_3_2_3_ServerDatagrams checks clause 13.2.3.2.3 (p. 382) on
// the outstation: every frame of a datagram is taken; a frame cut at the
// end of a datagram is a framing error and does not swallow the next
// datagram; a response of several frames arrives in datagrams of whole
// frames.
func TestSpec13_2_3_2_3_ServerDatagrams(t *testing.T) {
	met := &framingMetrics{}
	s := newServer(t, WithMetrics(met))
	for i := range 300 {
		_ = s.Database().AddAnalogInput(uint32(i), PointConfig{}, app.Analog{Value: float64(i), Flags: app.FlagOnline})
	}
	addr, _ := serveUDP(t, s)
	p := dialRaw(t, "udp", addr)
	p.write(rls(10), rls(10))
	p.linkStatus(10)
	p.linkStatus(10)

	long := encodeFrames(t, link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: 10, Src: 1, Data: bytes.Repeat([]byte{0xC0}, link.MaxUserData)})
	p.writeRaw(append(encodeFrames(t, rls(10)), long[:60]...))
	p.linkStatus(10)
	p.write(rls(10))
	p.linkStatus(10)
	if met.n.Load() != 1 {
		t.Fatalf("%d framing errors, want 1", met.n.Load())
	}

	p.request(10, req(1, app.FuncRead, app.AllObjects(app.G30V0)))
	if f := p.response(10); f.Control.Seq != 1 || p.frames < 2 {
		t.Fatalf("response %s in %d frames", f, p.frames)
	}
}

// TestSpec10_4_1_Rule2_ConfirmThenRequest checks clause 10.4.1 rule 2 (p.
// 305): an application CONFIRM followed at once by a request, both in
// one TCP write or one UDP datagram, are both taken, in order: the
// confirmed event is not reported again.
func TestSpec10_4_1_Rule2_ConfirmThenRequest(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := newServer(t, WithMasters(1))
			_ = s.Database().AddBinaryInput(0, PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
			var addr string
			if network == "tcp" {
				addr = serveTCP(t, s)
			} else {
				addr, _ = serveUDP(t, s)
			}
			p := dialRaw(t, network, addr)
			_ = s.Database().UpdateBinaryInput(0, app.Binary{Value: true, Flags: app.FlagOnline})
			p.request(10, req(1, app.FuncRead, app.AllObjects(app.G60V2)))
			if f := p.response(10); !f.Control.CON || len(f.Headers) == 0 {
				t.Fatalf("event response %s", f)
			}
			p.write(append(p.requestFrames(10, confirm(1, false)), p.requestFrames(10, req(2, app.FuncRead, app.AllObjects(app.G60V2)))...)...)
			if f := p.response(10); f.Control.Seq != 2 || f.Control.CON || len(f.Headers) != 0 {
				t.Fatalf("after the CONFIRM: %s", f)
			}
		})
	}
}

// TestSpec13_2_1_1_ServerUnconfirmedByDefault checks clause 13.2.1.1 (p.
// 377): over TCP and UDP the outstation sends its responses as
// UNCONFIRMED_USER_DATA, without RESET_LINK_STATES (rawMaster.response
// takes no other frame).
func TestSpec13_2_1_1_ServerUnconfirmedByDefault(t *testing.T) {
	counters := func() *Server {
		s := newServer(t)
		for i := range 100 {
			_ = s.Database().AddCounter(uint32(i), PointConfig{}, app.Counter{Value: uint32(i), Flags: app.FlagOnline})
		}
		return s
	}
	udpAddr, _ := serveUDP(t, counters())
	for _, p := range []*rawMaster{dialRaw(t, "tcp", serveTCP(t, counters())), dialRaw(t, "udp", udpAddr)} {
		p.request(10, req(1, app.FuncRead, app.AllObjects(app.G20V0)))
		if f := p.response(10); f.Control.Seq != 1 || p.frames < 2 {
			t.Fatalf("response %s in %d frames", f, p.frames)
		}
	}
}

// TestSpec9_2_5_2_2_ServerSelfAddress checks clause 9.2.5.2.2 (p. 282) on
// the outstation: frames to 0xFFFC are ignored by default; with
// WithSelfAddress they are taken, link frames and requests, and answered
// with the outstation's own address; in a Group only the outstation that
// enables it answers.
func TestSpec9_2_5_2_2_ServerSelfAddress(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		p := dialRaw(t, "tcp", serveTCP(t, newServer(t)))
		p.write(rls(link.SelfAddress))
		p.request(link.SelfAddress, readIIN(1))
		p.noReply(10)
		p.request(10, readIIN(2))
		if f := p.response(10); f.Control.Seq != 2 {
			t.Fatalf("response %s: the request to 0xFFFC was answered", f)
		}
	})
	t.Run("enabled", func(t *testing.T) {
		p := dialRaw(t, "tcp", serveTCP(t, newServer(t, WithSelfAddress(true))))
		p.write(rls(link.SelfAddress))
		p.linkStatus(10)
		p.request(link.SelfAddress, readIIN(1))
		if f := p.response(10); f.Control.Seq != 1 {
			t.Fatalf("response %s", f)
		}
	})
	t.Run("group", func(t *testing.T) {
		a := newServer(t, WithAddress(10), WithSelfAddress(true))
		b := newServer(t, WithAddress(11))
		g, err := NewGroup(a, b)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = g.Close() })
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = g.Serve(l) }()
		p := dialRaw(t, "tcp", l.Addr().String())
		p.write(rls(11)) // 11 has a session on the connection too
		p.linkStatus(11)
		p.write(rls(link.SelfAddress))
		p.linkStatus(10)
		p.noReply(11)
	})
}

// TestSpec9_2_5_2_ReservedAddressesIgnored checks clause 9.2.5.2 (p. 282):
// the addresses 0xFFF0 to 0xFFFB are reserved; the outstation neither
// answers frames to them nor carries out their requests.
func TestSpec9_2_5_2_ReservedAddressesIgnored(t *testing.T) {
	p := dialRaw(t, "tcp", serveTCP(t, newServer(t, WithSelfAddress(true))))
	for i, dest := range []link.Address{0xFFF0, 0xFFF6, 0xFFFB} {
		p.write(rls(dest))
		p.request(dest, readIIN(uint8(i)))
	}
	p.noReply(10)
	p.request(10, readIIN(5))
	if f := p.response(10); f.Control.Seq != 5 {
		t.Fatalf("response %s: a request to a reserved address was answered", f)
	}
}

// TestSpec13_2_2_2_DefaultPorts checks the ports of clauses 13.2.2.2 (p.
// 378) and 7.8.8 (p. 258): 20000 for DNP3 over TCP and UDP, 19999 over TLS.
// ListenAndServe("") listens on them; listening is not tested (tests use
// port 0), the address it is given is.
func TestSpec13_2_2_2_DefaultPorts(t *testing.T) {
	if DefaultPort != 20000 || DefaultTLSPort != 19999 {
		t.Fatalf("ports %d and %d", DefaultPort, DefaultTLSPort)
	}
	if defaultPort(false) != DefaultPort || defaultPort(true) != DefaultTLSPort {
		t.Fatalf("defaultPort: %d without TLS, %d with", defaultPort(false), defaultPort(true))
	}
	for _, tc := range []struct {
		addr string
		tls  bool
		want string
	}{
		{"", false, ":20000"},
		{"", true, ":19999"},
		{"127.0.0.1:0", false, "127.0.0.1:0"},
		{"127.0.0.1:0", true, "127.0.0.1:0"},
	} {
		if got := listenAddr(tc.addr, tc.tls); got != tc.want {
			t.Errorf("listenAddr(%q, TLS %v) = %q, want %q", tc.addr, tc.tls, got, tc.want)
		}
	}
}

// TestSpec13_2_3_1_3_DialAndServeWaitsWhileConnected checks clause
// 13.2.3.1.3 (p. 379): of a dual end point's two connections the master's
// has priority, so DialAndServe does not connect while a master is
// connected to the listener, and connects once it left.
func TestSpec13_2_3_1_3_DialAndServeWaitsWhileConnected(t *testing.T) {
	s := newServer(t)
	m := dialLinkMaster(t, serveTCP(t, s))
	m.send(readIIN(1))
	m.recvFunc(app.FuncResponse)
	eventually(t, "the master's connection", s.streamConnected)

	ml, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ml.Close() }()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ml.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.DialAndServe(ctx, ml.Addr().String(), Redial{MinDelay: 20 * time.Millisecond, MaxDelay: 40 * time.Millisecond})
	}()
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatal("dialed while the master was connected")
	case <-time.After(200 * time.Millisecond): // ten checks
	}
	m.ch.Close(nil)
	<-m.ch.Done()
	select {
	case c := <-accepted:
		defer func() { _ = c.Close() }()
	case <-time.After(3 * time.Second):
		t.Fatal("no connection after the master left")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialAndServe: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialAndServe did not return")
	}
}

// TestSpec13_2_3_1_4_MasterIPsTCP checks clause 13.2.3.1.4 a (p. 379,
// should: validate connection requests from masters by IP address): a
// connection from an address outside WithMasterIPs is closed without an
// answer; one inside is served. A WithMasterIPs without a valid prefix is
// refused.
func TestSpec13_2_3_1_4_MasterIPsTCP(t *testing.T) {
	denied := dialRaw(t, "tcp", serveTCP(t, newServer(t, WithMasterIPs(netip.MustParsePrefix("192.0.2.0/24")))))
	if fs := denied.closed(); len(fs) != 0 {
		t.Fatalf("frames to a refused master: %v", fs)
	}
	allowed := dialRaw(t, "tcp", serveTCP(t, newServer(t, WithMasterIPs(netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("127.0.0.1/32")))))
	allowed.write(rls(10))
	allowed.linkStatus(10)
	for _, bad := range [][]netip.Prefix{nil, {{}}} {
		if _, err := New(WithMasterIPs(bad...)); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("WithMasterIPs(%v): %v", bad, err)
		}
	}
}

// packetConn is an in-memory UDP socket for the outstation: a test hands
// it datagrams from any address and reads what it sends, with the
// address.
type packetConn struct {
	in     chan packet
	out    chan packet
	closed chan struct{}
	once   sync.Once
}

type packet struct {
	b    []byte
	addr net.Addr
}

func newPacketConn() *packetConn {
	return &packetConn{in: make(chan packet, 16), out: make(chan packet, 256), closed: make(chan struct{})}
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.in:
		return copy(b, p.b), p.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *packetConn) WriteTo(b []byte, a net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.out <- packet{bytes.Clone(b), a}:
		return len(b), nil
	}
}

func (c *packetConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: DefaultPort}
}
func (c *packetConn) SetDeadline(time.Time) error      { return nil }
func (c *packetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *packetConn) SetWriteDeadline(time.Time) error { return nil }

func (c *packetConn) send(t *testing.T, from net.Addr, fs ...link.Frame) {
	c.in <- packet{encodeFrames(t, fs...), from}
}

// next returns the next datagram sent and its first frame.
func (c *packetConn) next(t *testing.T) (link.Frame, net.Addr) {
	t.Helper()
	select {
	case p := <-c.out:
		f, _, err := link.Decode(p.b)
		if err != nil {
			t.Fatal(err)
		}
		return f, p.addr
	case <-time.After(3 * time.Second):
		t.Fatal("no datagram sent")
		return link.Frame{}, nil
	}
}

func udpAt(ip string, port uint16) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), port))
}

// requestFrame is a single-frame request to dest.
func requestFrame(t *testing.T, dest link.Address, f *app.Fragment) link.Frame {
	t.Helper()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: dest, Src: 1, Data: append([]byte{0xC0}, b...)}
}

// TestSpec13_2_3_2_2_MasterIPsUDP checks clause 13.2.3.2.2 d (p. 382,
// shall: accept UDP requests only from given master IP addresses):
// datagrams from an address outside
// WithMasterIPs are dropped unanswered. The stranger's REQUEST_LINK_STATUS
// would be answered at once, before the master's request.
func TestSpec13_2_3_2_2_MasterIPsUDP(t *testing.T) {
	pc := newPacketConn()
	s := newServer(t, WithMasterIPs(netip.MustParsePrefix("127.0.0.0/8")))
	go func() { _ = s.ServeUDP(pc) }()
	master := udpAt("127.0.0.1", 40000)
	pc.send(t, udpAt("192.0.2.7", 40000), rls(10))
	pc.send(t, master, requestFrame(t, 10, readIIN(1)))
	if f, to := pc.next(t); f.Function != link.PrimaryUnconfirmedUserData || to.String() != master.String() {
		t.Fatalf("sent %s to %v", f.String(), to)
	}
}

// TestSpecTable13_1_Case1_ServeUDPFixed checks case 1 of Table 13-1 (p.
// 381): the outstation sends its responses to the fixed port of the
// master, whatever port the request came from, and takes datagrams from
// the master's IP address only. A peer that is not a UDP address is
// refused, and the socket closed.
func TestSpecTable13_1_Case1_ServeUDPFixed(t *testing.T) {
	pc := newPacketConn()
	s := newServer(t)
	fixed := udpAt("127.0.0.1", 20001)
	go func() { _ = s.ServeUDPFixed(pc, fixed) }()
	pc.send(t, udpAt("127.0.0.1", 40000), rls(10))
	if f, to := pc.next(t); f.Function != link.SecondaryLinkStatus || to.String() != fixed.String() {
		t.Fatalf("sent %s to %v", f.String(), to)
	}
	pc.send(t, udpAt("192.0.2.1", 20001), rls(10))
	pc.send(t, udpAt("127.0.0.1", 40001), requestFrame(t, 10, readIIN(1)))
	if f, to := pc.next(t); f.Function != link.PrimaryUnconfirmedUserData || to.String() != fixed.String() {
		t.Fatalf("sent %s to %v", f.String(), to)
	}

	for _, peer := range []net.Addr{nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20001}} {
		other := newPacketConn()
		if err := s.ServeUDPFixed(other, peer); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Fatalf("peer %v: %v", peer, err)
		}
		select {
		case <-other.closed:
		default:
			t.Fatalf("peer %v: the socket was not closed", peer)
		}
	}
}

// TestSpec13_2_3_5_1_ServeByMasterIP checks method 1 of clause 13.2.3.5.1
// (p. 386), required by 13.2.3.5.4: connections go to the outstation, or
// the Group, of the first route that holds the master's IP address; one
// that no route holds is closed; routes without a valid prefix, or with
// not exactly one target, are refused.
func TestSpec13_2_3_5_1_ServeByMasterIP(t *testing.T) {
	lp := netip.MustParsePrefix
	route := func(t *testing.T, routes ...Route) string {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- ServeByMasterIP(l, routes...) }()
		t.Cleanup(func() {
			_ = l.Close()
			select {
			case err := <-done:
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("ServeByMasterIP after Close: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("ServeByMasterIP did not return after Close")
			}
		})
		return l.Addr().String()
	}
	t.Run("server", func(t *testing.T) {
		other := newServer(t, WithAddress(20))
		mine := newServer(t)
		p := dialRaw(t, "tcp", route(t,
			Route{Masters: lp("192.0.2.0/24"), Server: other},
			Route{Masters: lp("127.0.0.0/8"), Server: mine},
			Route{Masters: lp("127.0.0.1/32"), Server: other}))
		p.write(rls(20))
		p.noReply(10)
	})
	t.Run("group", func(t *testing.T) {
		g, _ := groupOf(t, 10, 11)
		p := dialRaw(t, "tcp", route(t, Route{Masters: lp("127.0.0.1/32"), Group: g}))
		for _, o := range []link.Address{10, 11} {
			p.write(rls(o))
			p.linkStatus(o)
		}
	})
	t.Run("unrouted", func(t *testing.T) {
		p := dialRaw(t, "tcp", route(t, Route{Masters: lp("192.0.2.0/24"), Server: newServer(t)}))
		if fs := p.closed(); len(fs) != 0 {
			t.Fatalf("frames on an unrouted connection: %v", fs)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		s := newServer(t)
		g, _ := groupOf(t, 11)
		for i, routes := range [][]Route{
			nil,
			{{Server: s}},
			{{Masters: lp("127.0.0.1/32")}},
			{{Masters: lp("127.0.0.1/32"), Server: s, Group: g}},
		} {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			if err := ServeByMasterIP(l, routes...); !errors.Is(err, dnp3.ErrInvalidOption) {
				t.Errorf("routes %d: %v", i, err)
			}
			_ = l.Close()
		}
	})
}

// TestSpecTable13_2_Rows5And6_ServerReset checks Table 13-2 rows 5 and 6
// (p. 383) on the outstation: a master that resets its connection (TCP
// RST) ends it; the outstation closes it and keeps listening.
func TestSpecTable13_2_Rows5And6_ServerReset(t *testing.T) {
	s := newServer(t)
	addr := serveTCP(t, s)
	p := dialRaw(t, "tcp", addr)
	p.write(rls(10))
	p.linkStatus(10)
	eventually(t, "the connection", func() bool { return s.connections() == 1 })
	if err := p.conn.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = p.conn.Close()
	eventually(t, "the connection closed", func() bool { return s.connections() == 0 })
	q := dialRaw(t, "tcp", addr)
	q.write(rls(10))
	q.linkStatus(10)
}

// TestSpec13_2_3_3_ThirdConnectionDuringProbe checks clause 13.2.3.3 (p.
// 382) and its NOTE 2: while the keep-alive probes the master's current
// connection for a second connection, a third one of the master is
// rejected at once, without waiting for the probe; the answered probe
// rejects the second one, and the current connection keeps serving.
func TestSpec13_2_3_3_ThirdConnectionDuringProbe(t *testing.T) {
	addr := serveTCP(t, newServer(t, WithMasters(1), WithLink(Link{Timeout: 30 * time.Second})))
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	if f := old.response(10); f.Control.Seq != 1 {
		t.Fatalf("response %s", f)
	}
	second := dialRaw(t, "tcp", addr)
	old.probed() // unanswered for now: the probe runs
	third := dialRaw(t, "tcp", addr)
	if fs := third.closed(); len(fs) != 0 {
		t.Fatalf("frames to the third connection: %v", fs)
	}
	old.answerProbe()
	if fs := second.closed(); len(fs) != 0 {
		t.Fatalf("frames to the second connection: %v", fs)
	}
	old.request(10, readIIN(2))
	if f := old.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpec13_2_3_3_HeldRequestsBounded: the requests a new connection of
// the master sends while the current one is probed (clause 13.2.3.3 NOTE
// 2, p. 382) are held, at most maxHeld of them; once the probe fails and
// the new connection is taken (Table 13-2 row 4, p. 383), the held ones are
// answered in the order they came, and those beyond the bound are lost, as
// on the line.
func TestSpec13_2_3_3_HeldRequestsBounded(t *testing.T) {
	s := newServer(t, WithMasters(1), WithLink(Link{Timeout: 30 * time.Second}))
	addr := serveTCP(t, s)
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	old.response(10)
	second := dialRaw(t, "tcp", addr)
	old.probed()
	a := s.association(1)
	release := blockAssoc(t, a)
	for i := range maxHeld + 2 {
		second.request(10, readIIN(uint8(i)))
	}
	waitQueued(t, a, maxHeld+2)
	// The current connection goes: the probe fails after the requests.
	_ = old.conn.Close()
	waitQueued(t, a, maxHeld+3)
	release()
	for i := range maxHeld {
		if f := second.response(10); f.Control.Seq != uint8(i) {
			t.Fatalf("held request %d: response %s", i, f)
		}
	}
	second.request(10, readIIN(12))
	if f := second.response(10); f.Control.Seq != 12 {
		t.Fatalf("response %s: a request beyond the %d held was answered", f, maxHeld)
	}
}

// TestSpec13_2_3_3_CurrentConnectionGoneDuringProbe: when the master's
// current connection goes while it is probed for a new connection (clause
// 13.2.3.3 NOTE 2, p. 382), and another connection of the master took its
// place before the probe's result was handled, the new connection is
// measured against that one: it is probed in turn and, the probe answered,
// the new connection is rejected.
func TestSpec13_2_3_3_CurrentConnectionGoneDuringProbe(t *testing.T) {
	s := newServer(t, WithMasters(1), WithLink(Link{Timeout: 30 * time.Second}))
	addr := serveTCP(t, s)
	old := dialRaw(t, "tcp", addr)
	old.request(10, readIIN(1))
	old.response(10)
	second := dialRaw(t, "tcp", addr)
	old.probed()
	a := s.association(1)
	release := blockAssoc(t, a)
	third := dialRaw(t, "tcp", addr)
	waitQueued(t, a, 1) // the third connection, queued before the probe's result
	_ = old.conn.Close()
	waitQueued(t, a, 2)
	release()
	// The third connection took the gone one's place, and is probed for
	// the second, whose probe ended without deciding.
	third.probed()
	third.answerProbe()
	if fs := second.closed(); len(fs) != 0 {
		t.Fatalf("frames to the second connection: %v", fs)
	}
	third.request(10, readIIN(2))
	if f := third.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpec13_2_3_3_ConnectionGoneBeforeTaken: a connection of the master
// that is already closed when the association comes to take it is not
// taken: the current connection keeps serving, and is not probed (clause
// 13.2.3.3 NOTE 2, p. 382, probes for a new connection that stands).
func TestSpec13_2_3_3_ConnectionGoneBeforeTaken(t *testing.T) {
	s := newServer(t, WithMasters(1))
	addr := serveTCP(t, s)
	m := dialRaw(t, "tcp", addr)
	m.request(10, readIIN(1))
	m.response(10)
	a := s.association(1)
	release := blockAssoc(t, a)
	late := dialRaw(t, "tcp", addr)
	waitQueued(t, a, 1)
	_ = late.conn.Close()
	eventually(t, "the late connection closed", func() bool { return s.connections() == 1 })
	release()
	if onAssoc(t, a, func() bool { return a.probing }) {
		t.Fatal("the current connection is probed for a closed one")
	}
	m.request(10, readIIN(2))
	if f := m.response(10); f.Control.Seq != 2 {
		t.Fatalf("response %s", f)
	}
}

// TestSpecTable13_1_DatagramTakesOverFromGoneConnection checks clause
// 13.2.3.3 (p. 382) with Table 13-1 (p. 381) for a master that speaks over
// TCP and UDP: its datagram is not taken while its TCP connection stands
// (the probe of the connection is answered, and the request it carried is
// dropped); once the connection is gone, its next datagram takes the
// association and is answered.
func TestSpecTable13_1_DatagramTakesOverFromGoneConnection(t *testing.T) {
	s := newServer(t)
	tcpAddr := serveTCP(t, s)
	udpAddr, _ := serveUDP(t, s)
	tcp := dialRaw(t, "tcp", tcpAddr)
	tcp.request(10, readIIN(1))
	tcp.response(10)
	a := s.association(1)
	udp := dialRaw(t, "udp", udpAddr)
	udp.request(10, readIIN(2))
	tcp.probed()
	tcp.answerProbe()
	eventually(t, "the probe decided", func() bool { return !onAssoc(t, a, func() bool { return a.probing }) })
	_ = tcp.conn.Close()
	eventually(t, "the TCP connection gone", func() bool { return onAssoc(t, a, func() bool { return a.sess == nil }) })
	udp.request(10, readIIN(3))
	if f := udp.response(10); f.Control.Seq != 3 {
		t.Fatalf("response %s, want the one to the datagram after the connection went", f)
	}
}

// TestSpec13_2_3_1_4_MasterIPsGroup checks clause 13.2.3.1.4 a (p. 379,
// should: validate connection requests from masters by IP address) for a
// Group: a connection is taken only from an address every outstation of
// the group allows; one that any of them refuses is closed without an
// answer.
func TestSpec13_2_3_1_4_MasterIPsGroup(t *testing.T) {
	lp := netip.MustParsePrefix
	serve := func(t *testing.T, servers ...*Server) string {
		t.Helper()
		g, err := NewGroup(servers...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = g.Close() })
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = g.Serve(l) }()
		return l.Addr().String()
	}
	denied := dialRaw(t, "tcp", serve(t, newServer(t, WithAddress(10)), newServer(t, WithAddress(11), WithMasterIPs(lp("192.0.2.0/24")))))
	if fs := denied.closed(); len(fs) != 0 {
		t.Fatalf("frames to a refused master: %v", fs)
	}
	allowed := dialRaw(t, "tcp", serve(t, newServer(t, WithAddress(10)), newServer(t, WithAddress(11), WithMasterIPs(lp("127.0.0.0/8")))))
	for _, o := range []link.Address{10, 11} {
		allowed.write(rls(o))
		allowed.linkStatus(o)
	}
}

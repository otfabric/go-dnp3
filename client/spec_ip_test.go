// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
	"github.com/otfabric/go-dnp3/transport"
)

// Spec tests: the master's side of IEEE 1815-2012 clause 13 (DNP3 over
// TCP and UDP): datagrams, the UDP ports of Table 13-1, the dual end point
// of 13.2.3.1.3 and the connection management of Table 13-2. Page numbers
// are printed pages.

// udpFake is a raw outstation at link address 10 on a loopback UDP
// socket. It answers each request with the fragment answer returns, all
// of its frames in one datagram, and records the source and the function
// of every request and confirmation.
type udpFake struct {
	pc    net.PacketConn
	decoy net.PacketConn // sends a stray response before each answer

	mu   sync.Mutex
	from []net.Addr
	fns  []app.FunctionCode
	errs []string
}

func newUDPFake(t *testing.T, answer func(req *app.Fragment) *app.Fragment) *udpFake {
	t.Helper()
	listen := func() net.PacketConn {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		return pc
	}
	o := &udpFake{pc: listen(), decoy: listen()}
	go o.run(answer)
	return o
}

func (o *udpFake) fail(s string) {
	o.mu.Lock()
	o.errs = append(o.errs, s)
	o.mu.Unlock()
}

// datagram returns the frames carrying frag from the outstation, in one
// datagram.
func datagram(sg *transport.Segmenter, frag *app.Fragment) ([]byte, error) {
	b, err := frag.Encode()
	if err != nil {
		return nil, err
	}
	var dg []byte
	for _, s := range sg.Segment(b) {
		f := link.Frame{Function: link.PrimaryUnconfirmedUserData, Dest: 1, Src: 10, Data: s}
		e, err := f.Encode()
		if err != nil {
			return nil, err
		}
		dg = append(dg, e...)
	}
	return dg, nil
}

func (o *udpFake) run(answer func(*app.Fragment) *app.Fragment) {
	buf := make([]byte, 65535)
	ra := transport.NewReassembler(0)
	var sg transport.Segmenter
	for {
		n, from, err := o.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		for b := buf[:n]; len(b) > 0; {
			f, k, err := link.Decode(b)
			if err != nil {
				o.fail("a datagram of the master does not hold whole frames: " + err.Error())
				break
			}
			b = b[k:]
			if f.Function != link.PrimaryUnconfirmedUserData {
				o.fail("the master sent " + f.String())
				continue
			}
			frag, err := ra.Add(f.Data)
			if err != nil || frag == nil {
				continue
			}
			req, err := app.Decode(frag)
			if err != nil {
				o.fail("request: " + err.Error())
				continue
			}
			o.mu.Lock()
			o.from = append(o.from, from)
			o.fns = append(o.fns, req.Function)
			o.mu.Unlock()
			if req.Function == app.FuncConfirm {
				continue
			}
			res := answer(req)
			if o.decoy != nil {
				stray := &app.Fragment{Control: res.Control, Function: app.FuncResponse, Headers: []app.Header{app.Ranged(app.G30V1, 0, app.Analog{Value: -1})}}
				if dg, err := datagram(&sg, stray); err == nil {
					_, _ = o.decoy.WriteTo(dg, from)
				}
			}
			dg, err := datagram(&sg, res)
			if err != nil {
				o.fail("answer: " + err.Error())
				continue
			}
			_, _ = o.pc.WriteTo(dg, from)
		}
	}
}

func (o *udpFake) check(t *testing.T) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, e := range o.errs {
		t.Error(e)
	}
}

// analogs returns n analog inputs with flags, five octets each.
func analogs(n int) app.Header {
	vs := make([]app.Value, n)
	for i := range vs {
		vs[i] = app.Analog{Value: float64(i), Flags: app.FlagOnline}
	}
	return app.Ranged(app.G30V1, 0, vs...)
}

// TestSpec13_2_3_2_ClientDatagrams checks the master over UDP: clause
// 13.2.3.2.3 (p. 382), a response whose frames arrive together in one
// datagram of more than a thousand octets is read whole; 13.2.3.2.2 b, the
// READ and the CONFIRM leave from the port the responses arrive at; 13.2.3.2.2
// c, a datagram from another address is ignored (a stray response sent
// first from another port does not answer the READ); 13.2.1.1 (p. 377),
// every frame is UNCONFIRMED_USER_DATA, and every datagram holds whole
// frames.
func TestSpec13_2_3_2_ClientDatagrams(t *testing.T) {
	o := newUDPFake(t, func(req *app.Fragment) *app.Fragment {
		res := &app.Fragment{Control: app.SingleControl(req.Control.Seq), Function: app.FuncResponse}
		if req.Function == app.FuncRead {
			res.Control.CON = true
			res.Headers = []app.Header{analogs(200)}
		}
		return res
	})
	addr := o.pc.LocalAddr().String()
	c, err := Dial(testCtx(t), addr, WithStream(UDP(addr)), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	res, err := c.Read(testCtx(t), app.AllObjects(app.G30V0))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Measurements()); n != 200 {
		t.Fatalf("%d measurements, want 200", n)
	}
	waitFor(t, "the CONFIRM", func() bool {
		o.mu.Lock()
		defer o.mu.Unlock()
		return len(o.fns) > 0 && o.fns[len(o.fns)-1] == app.FuncConfirm
	})
	o.mu.Lock()
	for i, a := range o.from {
		if a.String() != o.from[0].String() {
			t.Errorf("%s from %v, the READ from %v", o.fns[i], a, o.from[0])
		}
	}
	o.mu.Unlock()
	o.check(t)
}

// TestSpecTable13_1_Case1_UDPFrom checks case 1 of Table 13-1 (p. 381)
// end to end: the master sends from the local port given to UDPFrom, so
// an outstation that answers to that fixed port (ServeUDPFixed) reaches
// it. An invalid local address fails the connect.
func TestSpecTable13_1_Case1_UDPFrom(t *testing.T) {
	srv, err := server.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := free.LocalAddr().(*net.UDPAddr)
	_ = free.Close()
	go func() { _ = srv.ServeUDPFixed(pc, local) }()

	c, err := Dial(testCtx(t), "outstation", WithStream(UDPFrom(local.String(), pc.LocalAddr().String())), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	readOne(t, c)

	bad, err := New("outstation", WithStream(UDPFrom("127.0.0.1", pc.LocalAddr().String())))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	if err := bad.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("a local address without a port: %v", err)
	}
}

// readOne reads binary input 0, which the outstations of these tests have.
func readOne(t *testing.T, c *Client) {
	t.Helper()
	res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("read: %v %v", res, err)
	}
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// deadAddr returns a loopback address nobody listens on: a dial to it is
// refused at once.
func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}

// dualServer is an outstation that connects to the master at l
// (DialAndServe), until the test ends.
func dualServer(t *testing.T, l net.Listener, opts ...server.Option) *server.Server {
	t.Helper()
	srv, err := server.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.DialAndServe(ctx, l.Addr().String(), server.Redial{MinDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond})
		close(done)
	}()
	t.Cleanup(func() { cancel(); _ = srv.Close(); <-done })
	return srv
}

// expectEOF checks that the other end closes conn within 3 seconds.
func expectEOF(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	if ne, ok := errors.AsType[net.Error](err); err == nil || ok && ne.Timeout() {
		t.Fatalf("the connection was not closed: %v", err)
	}
}

// TestSpec13_2_3_1_3_DualEndpointTakesOutstationConnection checks clause
// 13.2.3.1.3 (p. 379) and Figure 13-7: a master dual end point whose own
// connect failed takes the connection the outstation establishes, and
// closes a second one while it is connected ("reject S'IN").
func TestSpec13_2_3_1_3_DualEndpointTakesOutstationConnection(t *testing.T) {
	l := listenTCP(t)
	c, err := New(deadAddr(t), WithDualEndpoint(l, nil), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("Connect to nobody: %v", err)
	}
	dualServer(t, l)
	waitFor(t, "the outstation's connection", func() bool { return c.State() == dnp3.StateConnected })
	readOne(t, c)

	extra, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = extra.Close() }()
	expectEOF(t, extra)
	readOne(t, c)
}

// dialerFunc adapts a function to a Dialer.
type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// TestSpec13_2_3_1_3_DualEndpointOwnDialWins checks clause 13.2.3.1.3 (p.
// 379): the master has priority on the creation of the connection. An
// outstation connection that arrives while the master's own dial is in
// progress is closed once that dial succeeds, and the master uses its
// own.
func TestSpec13_2_3_1_3_DualEndpointOwnDialWins(t *testing.T) {
	_, addr := outstation(t)
	l := listenTCP(t)
	var c *Client
	var incoming net.Conn
	dial := dialerFunc(func(ctx context.Context, network, a string) (net.Conn, error) {
		in, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return nil, err
		}
		incoming = in
		waitFor(t, "the outstation's connection queued", func() bool {
			c.dual.mu.Lock()
			defer c.dual.mu.Unlock()
			return c.dual.queued != nil
		})
		var d net.Dialer
		return d.DialContext(ctx, network, a)
	})
	c, err := New(addr, WithDualEndpoint(l, nil), WithDialer(dial), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = incoming.Close() }()
	expectEOF(t, incoming)
	if got := c.remoteAddr().String(); got != addr {
		t.Fatalf("connected to %s, want the dialed %s", got, addr)
	}
	readOne(t, c)
}

// TestSpec13_2_3_1_4_DualEndpointAllow checks clause 13.2.3.1.4 b (p.
// 379): a master dual end point validates the outstation's address; a
// connection from an address it does not accept is closed and not used.
func TestSpec13_2_3_1_4_DualEndpointAllow(t *testing.T) {
	l := listenTCP(t)
	asked := make(chan net.Addr, 4)
	c, err := New(deadAddr(t), WithDualEndpoint(l, func(a net.Addr) bool { asked <- a; return false }), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.Connect(testCtx(t)) // fails; the end point listens from now on
	in, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	select {
	case a := <-asked:
		if a.String() != in.LocalAddr().String() {
			t.Fatalf("allow asked about %v, want %v", a, in.LocalAddr())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("allow was not asked")
	}
	expectEOF(t, in)
	if s := c.State(); s == dnp3.StateConnected {
		t.Fatal("connected over a refused connection")
	}
}

// TestSpec13_2_3_1_3_DualEndpointOptions: Close closes the end point's
// listener, whether or not it listened yet; a nil listener, and
// WithDualEndpoint with WithStream, are refused.
func TestSpec13_2_3_1_3_DualEndpointOptions(t *testing.T) {
	idle := listenTCP(t)
	c, err := New(deadAddr(t), WithDualEndpoint(idle, nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, err := idle.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	used := listenTCP(t)
	c, err = New(deadAddr(t), WithDualEndpoint(used, nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Connect(testCtx(t))
	_ = c.Close()
	if conn, err := net.Dial("tcp", used.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("the end point still listens after Close")
	}
	for _, opts := range [][]Option{
		{WithDualEndpoint(nil, nil)},
		{WithDualEndpoint(listenTCP(t), nil), WithStream(UDP("127.0.0.1:20000"))},
	} {
		if _, err := New("outstation", opts...); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("New: %v", err)
		}
	}
}

// TestSpec13_2_3_1_3_DualEndpointTLS checks the dual end point with TLS
// (clause 13.2.3.1.3 with 7.8.8): the master is the TLS server of the
// connection the outstation establishes.
func TestSpec13_2_3_1_3_DualEndpointTLS(t *testing.T) {
	cert := selfSigned(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	l := listenTCP(t)
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	c, err := New(deadAddr(t), WithDualEndpoint(tl, nil), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.Connect(testCtx(t))
	dualServer(t, l, server.WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	waitFor(t, "the outstation's TLS connection", func() bool { return c.State() == dnp3.StateConnected })
	readOne(t, c)
}

// gate is a connection that a test can freeze: the outstation then reads
// nothing more and its writes are lost, as over a broken path.
type gate struct {
	net.Conn
	frozen atomic.Bool
	done   chan struct{}
	once   sync.Once
}

func (g *gate) Read(b []byte) (int, error) {
	n, err := g.Conn.Read(b)
	if g.frozen.Load() {
		<-g.done
		return 0, io.EOF
	}
	return n, err
}

func (g *gate) Write(b []byte) (int, error) {
	if g.frozen.Load() {
		return len(b), nil
	}
	return g.Conn.Write(b)
}

func (g *gate) Close() error {
	g.once.Do(func() { close(g.done) })
	return g.Conn.Close()
}

// servedConns serves every connection accepted on a loopback listener
// with an outstation, through a gate the test receives.
func servedConns(t *testing.T) (string, chan *gate) {
	t.Helper()
	srv, err := server.New()
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	l := listenTCP(t)
	gates := make(chan *gate, 8)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			g := &gate{Conn: conn, done: make(chan struct{})}
			gates <- g
			go func() { _ = srv.ServeConn(g, conn.RemoteAddr()) }()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); _ = srv.Close() })
	return l.Addr().String(), gates
}

func nextGate(t *testing.T, gates chan *gate) *gate {
	t.Helper()
	select {
	case g := <-gates:
		return g
	case <-time.After(3 * time.Second):
		t.Fatal("no connection")
		return nil
	}
}

// lostWith connects a client that reconnects, and returns the channel the
// error of each lost connection goes to.
func lostWith(t *testing.T, addr string, opts ...Option) (*Client, chan error) {
	t.Helper()
	lost := make(chan error, 8)
	c, err := Dial(testCtx(t), addr, append([]Option{
		WithAutoIntegrity(false),
		WithReconnect(Reconnect{MinDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}),
		WithStateHandler(func(s dnp3.State, err error) {
			if s == dnp3.StateConnecting && err != nil {
				lost <- err
			}
		}),
	}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, lost
}

func lostErr(t *testing.T, lost chan error) error {
	t.Helper()
	select {
	case err := <-lost:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("the connection was not lost")
		return nil
	}
}

// TestSpecTable13_2_Row3_ClientKeepAlive checks clause 13.2.3.3.1 (p.
// 382) and Table 13-2 row 3 (p. 383) on the master: a keep-alive that
// draws no answer closes the connection, and the master connects again.
func TestSpecTable13_2_Row3_ClientKeepAlive(t *testing.T) {
	addr, gates := servedConns(t)
	c, lost := lostWith(t, addr, WithLink(Link{KeepAlive: 50 * time.Millisecond, Timeout: 50 * time.Millisecond}))
	nextGate(t, gates).frozen.Store(true)
	if err := lostErr(t, lost); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("lost with %v, want a timeout", err)
	}
	nextGate(t, gates)
	waitFor(t, "the new connection", func() bool { return c.State() == dnp3.StateConnected })
	readOne(t, c)
}

// TestSpecTable13_2_Rows5And6_ClientReset checks Table 13-2 rows 5 and 6
// (p. 383) on the master: a connection the outstation resets (TCP RST) is
// closed, and the master connects again.
func TestSpecTable13_2_Rows5And6_ClientReset(t *testing.T) {
	addr, gates := servedConns(t)
	c, lost := lostWith(t, addr)
	first := nextGate(t, gates)
	if err := first.Conn.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = first.Conn.Close()
	if err := lostErr(t, lost); !errors.Is(err, dnp3.ErrConnectionLost) {
		t.Fatalf("lost with %v", err)
	}
	nextGate(t, gates)
	waitFor(t, "the new connection", func() bool { return c.State() == dnp3.StateConnected })
	readOne(t, c)
}

// TestSpec10_4_5_UnsolicitedDuringRequest checks clause 10.4.5 (p. 306):
// an unsolicited response that arrives while a solicited request waits
// for its response is processed, and the request completes.
func TestSpec10_4_5_UnsolicitedDuringRequest(t *testing.T) {
	l := listenTCP(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		reqs := make(chan *app.Fragment, 8)
		sess := ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1, OnFragment: func(b []byte, _ link.Address) {
			if f, err := app.Decode(b); err == nil && f.Function != app.FuncConfirm {
				reqs <- f
			}
		}})
		ch.Start()
		defer func() { ch.Close(nil); <-ch.Done() }()
		send := func(f *app.Fragment) {
			if b, err := f.Encode(); err == nil {
				_ = sess.Send(context.Background(), b)
			}
		}
		for {
			select {
			case r := <-reqs:
				if r.Function == app.FuncRead {
					send(&app.Fragment{Control: app.Control{FIR: true, FIN: true, CON: true, UNS: true, Seq: 3}, Function: app.FuncUnsolicitedResponse,
						Headers: []app.Header{app.Ranged(app.G30V1, 7, app.Analog{Value: 42, Flags: app.FlagOnline})}})
				}
				send(&app.Fragment{Control: app.SingleControl(r.Control.Seq), Function: app.FuncResponse,
					Headers: []app.Header{app.Ranged(app.G1V2, 0, app.Binary{Value: true, Flags: app.FlagOnline})}})
			case <-ch.Done():
				return
			}
		}
	}()
	unsolicited := make(chan []Measurement, 4)
	c, err := Dial(testCtx(t), l.Addr().String(), WithAutoIntegrity(false),
		WithHandler(HandlerFunc(func(info ResponseInfo, ms []Measurement) {
			if info.Unsolicited {
				unsolicited <- ms
			}
		})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("read: %v %v", res, err)
	}
	select {
	case ms := <-unsolicited:
		if len(ms) != 1 || ms[0].Index != 7 {
			t.Fatalf("unsolicited %v", ms)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the unsolicited response was not processed")
	}
}

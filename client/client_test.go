// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// outstation starts a server with a few points on a loopback listener.
func outstation(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	db := srv.Database()
	_ = db.AddBinaryInput(0, server.PointConfig{Class: 1}, app.Binary{Value: true, Flags: app.FlagOnline})
	_ = db.AddAnalogInput(0, server.PointConfig{Class: 2}, app.Analog{Value: 1, Flags: app.FlagOnline})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, l.Addr().String()
}

// silent accepts connections and never answers.
func silent(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return l.Addr().String()
}

func TestOptionValidation(t *testing.T) {
	bad := []Option{
		WithAddresses(0xFFFF, 10), WithDialer(nil), WithStream(nil),
		WithReconnect(Reconnect{MinDelay: time.Second, MaxDelay: time.Millisecond}),
		WithRetry(Retry{}), WithResponseTimeout(0), WithMaxFragment(10),
		WithStartup(Startup{EnableUnsolicited: []int{4}}), WithPoll(Poll{}), WithQueueLimit(0),
	}
	for i, o := range bad {
		if _, err := New("127.0.0.1", o); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("option %d accepted: %v", i, err)
		}
	}
	c, err := New("127.0.0.1", WithAddresses(3, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Addr() != "127.0.0.1:20000" || c.Outstation() != 4 || c.State() != dnp3.StateDisconnected {
		t.Fatalf("defaults: %s %d %s", c.Addr(), c.Outstation(), c.State())
	}
}

func TestNotConnectedAndClosed(t *testing.T) {
	c, _ := New("127.0.0.1:1")
	if _, err := c.IntegrityPoll(testCtx(t)); !errors.Is(err, dnp3.ErrNotConnected) {
		t.Fatalf("not connected: %v", err)
	}
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("connect to closed port: %v", err)
	}
	_ = c.Close()
	_ = c.Close()
	if _, err := c.IntegrityPoll(testCtx(t)); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("after close: %v", err)
	}
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrClosed) {
		t.Fatalf("connect after close: %v", err)
	}
	if _, err := Dial(testCtx(t), "127.0.0.1:1"); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("dial: %v", err)
	}
}

func TestConnectTwice(t *testing.T) {
	_, addr := outstation(t)
	c, err := Dial(testCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(testCtx(t)); !errors.Is(err, dnp3.ErrBusy) {
		t.Fatalf("second connect: %v", err)
	}
}

func TestTimeoutAndRetry(t *testing.T) {
	addr := silent(t)
	m := &metrics{}
	c, err := Dial(testCtx(t), addr, WithResponseTimeout(100*time.Millisecond),
		WithRetry(Retry{Attempts: 3, Backoff: 10 * time.Millisecond}), WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	_, err = c.IntegrityPoll(testCtx(t))
	if !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("silent outstation: %v", err)
	}
	if m.retries.Load() != 2 || m.done.Load() != 1 || m.requests.Load() != 1 {
		t.Fatalf("retries %d done %d requests %d", m.retries.Load(), m.done.Load(), m.requests.Load())
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("retries did not wait for their timeouts")
	}
	// Controls are never retried.
	_, err = c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0))
	if !errors.Is(err, dnp3.ErrTimeout) || m.retries.Load() != 2 {
		t.Fatalf("control retried: %v %d", err, m.retries.Load())
	}
	// A canceled context stops waiting at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Read(ctx, app.AllObjects(app.G1V0)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestQueueLimit(t *testing.T) {
	addr := silent(t)
	c, err := Dial(testCtx(t), addr, WithResponseTimeout(time.Second), WithQueueLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	go func() { _, _ = c.IntegrityPoll(context.Background()) }() // holds the turn
	time.Sleep(50 * time.Millisecond)
	go func() { _, _ = c.IntegrityPoll(context.Background()) }() // waits
	time.Sleep(50 * time.Millisecond)
	if _, err := c.IntegrityPoll(testCtx(t)); !errors.Is(err, dnp3.ErrBusy) {
		t.Fatalf("over the queue limit: %v", err)
	}
}

func TestTLS(t *testing.T) {
	cert := selfSigned(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	srv, err := server.New(server.WithTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	c, err := Dial(testCtx(t), l.Addr().String(), WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	res, err := c.IntegrityPoll(testCtx(t))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("over TLS: %v", err)
	}
	// A client that does not trust the certificate fails to connect.
	if _, err := Dial(testCtx(t), l.Addr().String(), WithTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost"})); !errors.Is(err, dnp3.ErrConnectFailed) {
		t.Fatalf("untrusted: %v", err)
	}
	// ListenAndServe with TLS.
	srv2, _ := server.New(server.WithTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	go func() { _ = srv2.ListenAndServe("127.0.0.1:0") }()
	time.Sleep(50 * time.Millisecond)
	_ = srv2.Close()
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestPollsAndAutoEventPoll(t *testing.T) {
	srv, addr := outstation(t)
	var mu sync.Mutex
	var got []Measurement
	h := HandlerFunc(func(_ ResponseInfo, ms []Measurement) {
		mu.Lock()
		got = append(got, ms...)
		mu.Unlock()
	})
	c, err := Dial(testCtx(t), addr, WithHandler(h), WithAutoEventPoll(true), WithAutoIntegrity(false),
		WithPoll(Poll{Interval: 50 * time.Millisecond, Headers: []app.Header{app.AllObjects(app.G30V0)}}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	count := func(event bool, g uint8) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, m := range got {
			if m.Event == event && m.GV.Group() == g {
				n++
			}
		}
		return n
	}
	waitFor(t, "periodic polls", func() bool { return count(false, 30) >= 3 })
	// An event: the next response reports class 1 events and the client
	// polls them on its own.
	_ = srv.Database().UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	waitFor(t, "automatic event poll", func() bool { return count(true, 2) >= 1 })
}

func TestStateHandlerAndLogging(t *testing.T) {
	_, addr := outstation(t)
	var states []dnp3.State
	var mu sync.Mutex
	var logBuf syncBuffer
	c, err := Dial(testCtx(t), addr, WithStateHandler(func(s dnp3.State, _ error) {
		mu.Lock()
		states = append(states, s)
		mu.Unlock()
	}), WithLogger(dnp3.NewSlogLogger(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		WithDialer(&net.Dialer{Timeout: time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.IntegrityPoll(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(states) < 3 || states[0] != dnp3.StateConnecting || states[1] != dnp3.StateConnected || states[len(states)-1] != dnp3.StateDisconnected {
		t.Fatalf("states %v", states)
	}
	for _, want := range []string{"component=dnp3.client", "request sent", "fragment received", "connected"} {
		if !strings.Contains(logBuf.String(), want) {
			t.Errorf("log misses %q", want)
		}
	}
}

func TestEchoMismatch(t *testing.T) {
	req := []app.Header{app.Indexed(app.G12V1, app.Object{Index: 1, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})}
	cases := map[string][]app.Header{
		"header count": {},
		"variation":    {app.Indexed(app.G41V1, app.Object{Index: 1, Value: app.AnalogOutput{}})},
		"index":        {app.Indexed(app.G12V1, app.Object{Index: 2, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})},
		"value":        {app.Indexed(app.G12V1, app.Object{Index: 1, Value: app.CROB{Op: app.OpLatchOff, Count: 1}})},
	}
	for name, echo := range cases {
		res := &Result{Fragments: []*app.Fragment{{Function: app.FuncResponse, Headers: echo}}}
		if _, err := echoStatuses(req, res); !errors.Is(err, dnp3.ErrProtocol) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := commandHeaders(nil); err == nil {
		t.Error("no commands accepted")
	}
	if _, err := commandHeaders([]Command{{Value: app.Binary{}}}); err == nil {
		t.Error("non-command accepted")
	}
}

func TestMeasurementsHelper(t *testing.T) {
	f := &app.Fragment{Function: app.FuncResponse, Headers: []app.Header{
		app.Ranged(app.G30V1, 0, app.Analog{Value: 1}),
		app.Counted(app.G50V1, app.AbsoluteTime{Time: 5}), // the time, not a point
		app.Indexed(app.G2V2, app.Object{Index: 3, Value: app.Binary{Value: true}}),
		app.Ranged(app.G50V4, 7, app.AbsoluteTime{Time: 9, Interval: 15, Units: app.UnitMinutes}),
		app.Ranged(app.G101V1, 1, app.BCD{Value: 1234}),
		app.Ranged(app.G102V1, 2, app.UnsignedInteger{Value: 200}),
	}}
	ms := Measurements(f)
	if len(ms) != 5 || ms[0].Event || !ms[1].Event || ms[1].Index != 3 {
		t.Fatalf("%+v", ms)
	}
	if ms[2].GV != app.G50V4 || ms[2].Index != 7 || ms[2].Value.(app.AbsoluteTime).Interval != 15 || ms[2].Event {
		t.Fatalf("time and interval: %+v", ms[2])
	}
	if ms[3].Value.(app.BCD).Value != 1234 || ms[4].Value.(app.UnsignedInteger).Value != 200 {
		t.Fatalf("BCD and unsigned integer: %+v %+v", ms[3], ms[4])
	}
}

func TestInvalidRequests(t *testing.T) {
	_, addr := outstation(t)
	c, err := Dial(testCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx := testCtx(t)
	if _, err := c.Read(ctx); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("read without headers")
	}
	if _, err := c.EventPoll(ctx, 4); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("event class 4")
	}
	if err := c.EnableUnsolicited(ctx, 0); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("unsolicited class 0")
	}
	if err := c.AssignClass(ctx, 5); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("assign class 5")
	}
	if err := c.SyncTime(ctx, TimeSyncNone); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Error("time sync none")
	}
	// WriteAttribute without a write handler: the outstation refuses it.
	var ie *dnp3.IINError
	if err := c.WriteAttribute(ctx, app.AttrUserLocation, app.StringAttribute("x")); !errors.As(err, &ie) {
		t.Errorf("write attribute: %v", err)
	}
}

type metrics struct {
	dnp3.NopMetrics
	requests, done, retries atomic.Int64
}

func (m *metrics) OnRequest(net.Addr, uint16, app.FunctionCode) { m.requests.Add(1) }
func (m *metrics) OnRequestDone(net.Addr, uint16, app.FunctionCode, time.Duration, error) {
	m.done.Add(1)
}
func (m *metrics) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) { m.retries.Add(1) }

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var _ = link.Address(0)

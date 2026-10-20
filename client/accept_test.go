// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// TestAcceptOverTLS: the outstation establishes a TLS connection to the
// master, which is the TLS server of it.
func TestAcceptOverTLS(t *testing.T) {
	cert := selfSigned(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	srv, err := server.New(server.WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	go func() {
		_ = srv.DialAndServe(context.Background(), l.Addr().String(), server.Redial{MinDelay: 10 * time.Millisecond})
	}()
	defer func() { _ = srv.Close() }()

	c, err := Dial(testCtx(t), "outstation", WithStream(Accept(tl)), WithAutoIntegrity(false),
		WithReconnect(Reconnect{MinDelay: 10 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("read over the outstation's TLS connection: %v %v", res, err)
	}
	// Without the outstation, the client waits for its next connection:
	// Close ends that wait at once.
	_ = srv.Close()
	waitFor(t, "the lost connection", func() bool { return c.State() != dnp3.StateConnected })
	start := time.Now()
	_ = c.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Close while waiting for a connection took %v", d)
	}
	// An Accept whose context ends, on a listener nobody dials.
	idle, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := Accept(idle)(ctx); err == nil {
		t.Fatal("Accept returned without a connection")
	}
	// The connection that the abandoned Accept takes later is closed, not
	// leaked: its peer reads the end of the stream.
	late, err := net.Dial("tcp", idle.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = late.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := late.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection taken by an abandoned Accept: %v", err)
	}
	_ = late.Close()
	_ = idle.Close()
	if _, _, err := Accept(idle)(context.Background()); err == nil {
		t.Fatal("Accept on a closed listener")
	}
}

func TestUDPStream(t *testing.T) {
	srv, err := server.New()
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Database().AddBinaryInput(0, server.PointConfig{}, app.Binary{Value: true, Flags: app.FlagOnline})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeUDP(pc) }()
	defer func() { _ = srv.Close() }()
	addr := pc.LocalAddr().String()
	c, err := Dial(testCtx(t), addr, WithStream(UDP(addr)), WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if res, err := c.Read(testCtx(t), app.AllObjects(app.G1V0)); err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("read over UDP: %v %v", res, err)
	}
	// An address that does not resolve fails to open.
	if _, _, err := UDP("no-such-host.invalid:20000")(testCtx(t)); err == nil {
		t.Fatal("UDP to an address that does not resolve")
	}
}

func TestBroadcast(t *testing.T) {
	var executed atomic.Int64
	accept := server.HandlerFunc(func(_ context.Context, _ server.Command, op server.OperateType) app.CommandStatus {
		if op == server.DirectOperateNoAck {
			executed.Add(1)
		}
		return app.StatusSuccess
	})
	_, addr := outstation(t, server.WithHandler(accept))
	c, err := Dial(testCtx(t), addr, WithAutoIntegrity(false), WithMetrics(&authResponses{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	if err := c.Broadcast(testCtx(t), link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, crob); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the broadcast control", func() bool { return executed.Load() == 1 })
	// The outstation reports the broadcast in its next response.
	res, err := c.Read(testCtx(t), app.ClassHeaders(0)...)
	if err != nil || !res.IIN.Has(app.IINBroadcast) {
		t.Fatalf("IIN after the broadcast: %v %v", res, err)
	}
	if err := c.Broadcast(testCtx(t), 10, app.FuncDirectOperateNoAck, crob); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("broadcast to a station address: %v", err)
	}
	if err := c.Broadcast(testCtx(t), link.BroadcastNoConfirm, app.FuncRead, app.ClassHeaders(0)...); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("broadcast READ: %v", err)
	}
	if err := c.Broadcast(testCtx(t), link.BroadcastNoConfirm, app.FuncWrite, app.Header{GV: app.G12V1, Qualifier: app.Qual1ByteStartStop,
		Objects: []app.Object{{Value: app.Binary{}}}}); err == nil {
		t.Fatal("broadcast of a request that does not encode")
	}
	n, err := New("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	if err := n.Broadcast(testCtx(t), link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, crob); !errors.Is(err, dnp3.ErrNotConnected) {
		t.Fatalf("broadcast without a connection: %v", err)
	}
}

func TestAttributeSetsClient(t *testing.T) {
	_, addr := outstation(t,
		server.WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: app.StringAttribute("zero")}),
		server.WithAttributeSet(3, map[uint8]app.Attribute{10: app.StringAttribute("three")}, 10))
	c, err := Dial(testCtx(t), addr, WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got, err := c.ReadAttributes(testCtx(t), app.AttrManufacturerName); err != nil || string(got[app.AttrManufacturerName].Data) != "zero" {
		t.Fatalf("set 0: %v %v", got, err)
	}
	if err := c.WriteAttributeSet(testCtx(t), 3, 10, app.StringAttribute("changed")); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ReadAttributeSet(testCtx(t), 3, 10); err != nil || string(got[10].Data) != "changed" {
		t.Fatalf("set 3 after the write: %v %v", got, err)
	}
	if _, err := c.ReadAttributeSet(testCtx(t), 4, 10); err == nil {
		t.Fatal("read of a set that does not exist")
	}
	if err := c.WriteAttribute(testCtx(t), app.AttrManufacturerName, app.StringAttribute("x")); err == nil {
		t.Fatal("set 0 written without a WriteHandler")
	}
}

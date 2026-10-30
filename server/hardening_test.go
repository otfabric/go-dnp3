// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"syscall"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// TestFrozenAnalogWithoutFlagKeepsQuality: a frozen analog input read
// without flag is reported with flags when they are not ONLINE alone, as
// the other analog inputs are.
func TestFrozenAnalogWithoutFlagKeepsQuality(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddFrozenAnalogInput(0, PointConfig{}, app.Analog{Value: 1, Flags: app.FlagCommLost})
	_ = db.AddFrozenAnalogInput(1, PointConfig{}, app.Analog{Value: 2, Flags: app.FlagOnline})
	for i, c := range []struct{ read, abnormal app.GroupVariation }{{app.G31V5, app.G31V1}, {app.G31V6, app.G31V2}} {
		m.send(req(uint8(i+1), app.FuncRead, app.AllObjects(c.read)))
		f := m.recvFunc(app.FuncResponse)
		if len(f.Headers) != 2 || f.Headers[0].GV != c.abnormal || f.Headers[1].GV != c.read {
			t.Fatalf("read of %s: %v", c.read, f.Headers)
		}
	}
}

// TestAnalogOutOfRangeKeepsFlags: an ONLINE analog input whose value an
// integer variation without flag cannot carry (out of its range, NaN) is
// reported with flags, which say OVER_RANGE, instead of a clamped number.
func TestAnalogOutOfRangeKeepsFlags(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.Update(AnalogInput, 0, app.Analog{Value: 40000, Flags: app.FlagOnline}, EventSuppress)
	_ = db.AddAnalogInput(1, PointConfig{}, app.Analog{Value: math.NaN(), Flags: app.FlagOnline})
	_ = db.AddAnalogInput(2, PointConfig{}, app.Analog{Value: 7, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.AllObjects(app.G30V4)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 2 || f.Headers[0].GV != app.G30V2 || len(f.Headers[0].Objects) != 2 || f.Headers[1].GV != app.G30V4 {
		t.Fatalf("read of g30v4: %v", f.Headers)
	}
	if a := f.Headers[0].Objects[0].Value.(app.Analog); a.Flags&app.FlagOverRange == 0 {
		t.Fatalf("40000 in 16 bits without OVER_RANGE: %v", a)
	}
	m.send(req(2, app.FuncRead, app.AllObjects(app.G30V3)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 3 || f.Headers[0].GV != app.G30V3 || f.Headers[1].GV != app.G30V1 {
		t.Fatalf("read of g30v3: %v", f.Headers)
	}
}

// TestDeadbandMustBeANumber: a NaN, infinite or negative deadband is
// refused when a point is added and answered with IIN2.2 when written.
func TestDeadbandMustBeANumber(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	for _, d := range []float64{math.NaN(), -1, math.Inf(1)} {
		if err := db.AddAnalogInput(5, PointConfig{Deadband: d}, app.Analog{}); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Fatalf("deadband %v: %v", d, err)
		}
	}
	for i, d := range []float64{math.NaN(), -1} {
		m.send(req(uint8(i+1), app.FuncWrite, app.Indexed(app.G34V3, app.Object{Index: 0, Value: app.AnalogDeadband{Value: d}})))
		if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
			t.Fatalf("WRITE of deadband %v: IIN %s", d, f.IIN)
		}
	}
	m.send(req(3, app.FuncWrite, app.Indexed(app.G34V3, app.Object{Index: 0, Value: app.AnalogDeadband{Value: 0.5}})))
	if f := m.recvFunc(app.FuncResponse); f.IIN&dnp3.IINErrorBits != 0 {
		t.Fatalf("WRITE of deadband 0.5: IIN %s", f.IIN)
	}
}

// TestAssignClassWorkIsBounded: ASSIGN_CLASS of the widest range takes the
// time of the points that exist, not of the 2^32 indexes it names.
func TestAssignClassWorkIsBounded(t *testing.T) {
	m := newMaster(t)
	start := time.Now()
	hs := []app.Header{app.AllObjects(app.G60V3)}
	for range 20 {
		hs = append(hs, app.IndexRange(app.G1V0, 0, math.MaxUint32))
	}
	m.send(req(1, app.FuncAssignClass, hs...))
	f := m.recvFunc(app.FuncResponse)
	if !f.IIN.Has(app.IINParameterError) || time.Since(start) > 5*time.Second {
		t.Fatalf("ASSIGN_CLASS of 2^32 indexes: IIN %s after %s", f.IIN, time.Since(start))
	}
	m.send(req(2, app.FuncAssignClass, app.AllObjects(app.G60V3), app.IndexRange(app.G1V0, 0, 1)))
	if f := m.recvFunc(app.FuncResponse); f.IIN&dnp3.IINErrorBits != 0 {
		t.Fatalf("ASSIGN_CLASS of 0..1: IIN %s", f.IIN)
	}
	db := m.srv.Database()
	db.mu.RLock()
	c := db.points[BinaryInput][1].cfg.Class
	db.mu.RUnlock()
	if c != 2 {
		t.Fatalf("class of binary input 1: %d", c)
	}
	if !db.assignClass(BinaryInput, false, 3, 2, 1) {
		t.Fatal("an empty range")
	}
}

// TestReadWorkIsBounded: a READ repeating headers that name every point
// plans no more than a few complete reads of the database, and says so
// with IIN2.2.
func TestReadWorkIsBounded(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	for i := range uint32(2000) {
		_ = db.AddAnalogInput(i, PointConfig{}, app.Analog{Flags: app.FlagOnline})
	}
	var hs []app.Header
	for range 100 {
		hs = append(hs, app.AllObjects(app.G60V1))
	}
	a := m.srv.associations()[0]
	db.mu.RLock()
	p := a.planRead(req(1, app.FuncRead, hs...))
	db.mu.RUnlock()
	n := 0
	for _, it := range p.items {
		n += len(it.h.Objects)
	}
	if !p.iin.Has(app.IINParameterError) || n > 4*db.size()+1024 {
		t.Fatalf("100 class 0 headers: IIN %s, %d objects", p.iin, n)
	}
	db.mu.RLock()
	p = a.planRead(req(2, app.FuncRead, app.AllObjects(app.G60V1), app.AllObjects(app.G30V0), app.AllObjects(app.G34V0)))
	db.mu.RUnlock()
	if p.iin.Has(app.IINParameterError) {
		t.Fatalf("an ordinary read: IIN %s", p.iin)
	}
}

// TestPanicIsContained: a panic while serving a request is logged and the
// association goes on serving.
func TestPanicIsContained(t *testing.T) {
	m := newMaster(t)
	a := m.srv.associations()[0]
	a.post(func() { panic("boom") })
	m.send(req(1, app.FuncRead, app.AllObjects(app.G1V0)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) == 0 {
		t.Fatalf("read after a panic: %v", f)
	}
}

// TestTLSHandshakeTimesOut: a peer that stalls the TLS handshake is dropped
// after handshakeTimeout, accepted or dialled.
func TestTLSHandshakeTimesOut(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 100 * time.Millisecond
	defer func() { handshakeTimeout = old }()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			time.Sleep(time.Second)
			_ = c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := handshake(tls.Server(c, &tls.Config{MinVersion: tls.VersionTLS12})); err == nil || time.Since(start) > 900*time.Millisecond {
		t.Fatalf("stalled handshake: %v after %s", err, time.Since(start))
	}
	if err := handshake(c); err != nil {
		t.Fatalf("plain connection: %v", err)
	}
	if _, err := (&Server{opts: options{tls: &tls.Config{MinVersion: tls.VersionTLS12}}}).dial(context.Background(), l.Addr().String()); err == nil {
		t.Fatal("dial to a listener that never answers the handshake")
	}
}

// errPacketConn fails its first read and write with errors of one
// datagram, then works as pc.
type errPacketConn struct {
	net.PacketConn
	reads, writes int
}

func (p *errPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.reads++; p.reads == 1 {
		return 0, nil, syscall.ECONNREFUSED
	}
	return p.PacketConn.ReadFrom(b)
}

func (p *errPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.writes++; p.writes == 1 {
		return 0, syscall.EHOSTUNREACH
	}
	return p.PacketConn.WriteTo(b, addr)
}

// TestUDPSurvivesDatagramErrors: an error that concerns one datagram does
// not end a UDP outstation's socket; a closed socket does.
func TestUDPSurvivesDatagramErrors(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	u := &udpStream{pc: &errPacketConn{PacketConn: pc}, peer: peer.LocalAddr()}
	if n, err := u.Write([]byte{1}); n != 1 || err != nil {
		t.Fatalf("write after EHOSTUNREACH: %d %v", n, err)
	}
	if _, err := peer.WriteTo([]byte{2, 3}, pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if n, err := u.Read(b); n != 2 || err != nil {
		t.Fatalf("read after ECONNREFUSED: %d %v", n, err)
	}
	_ = u.Close()
	if _, err := u.Read(b); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read of a closed socket: %v", err)
	}
	if _, err := u.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write to a closed socket: %v", err)
	}
}

// TestUnsynchronizedEventsUseRelativeTime: a binary event recorded while
// the time is unsynchronized is reported in the variation with relative
// time under a g51v2 CTO, also when it is read after a time sync; one
// recorded after the sync keeps absolute time; a master that asks for
// absolute time gets it.
func TestUnsynchronizedEventsUseRelativeTime(t *testing.T) {
	m := newMaster(t, WithTimeSync(time.Hour))
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	m.send(req(1, app.FuncWrite, app.Counted(app.G50V1, app.AbsoluteTime{Time: app.Now()})))
	m.recvFunc(app.FuncResponse)
	_ = db.UpdateBinaryInput(0, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(2, app.FuncRead, app.AllObjects(app.G60V2)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 3 || f.Headers[0].GV != app.G51V2 || f.Headers[1].GV != app.G2V3 || f.Headers[2].GV != app.G2V2 {
		t.Fatalf("an event before and one after the sync: %v", f.Headers)
	}
	m.send(confirm(2, false))

	m2 := newMaster(t, WithTimeSync(time.Hour))
	_ = m2.srv.Database().UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	m2.send(req(1, app.FuncRead, app.AllObjects(app.G2V2)))
	if f := m2.recvFunc(app.FuncResponse); len(f.Headers) != 1 || f.Headers[0].GV != app.G2V2 {
		t.Fatalf("a read of g2v2 while unsynchronized: %v", f.Headers)
	}
}

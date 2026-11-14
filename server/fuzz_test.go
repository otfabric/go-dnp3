// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"runtime"
	"testing"
	"testing/fstest"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// FuzzOutstation feeds arbitrary request fragments to an outstation with
// secure authentication, file transfer and points of every type. Whatever
// arrives, it must neither panic nor hang; the state carries over from one
// input to the next, as on a long-lived connection.
func FuzzOutstation(f *testing.F) {
	crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
	seeds := []*app.Fragment{
		req(0, app.FuncRead, app.ClassHeaders(0, 1, 2, 3)...),
		req(1, app.FuncRead, app.AllObjects(app.G121V0), app.IndexRange(app.G121V1, 0, 40)),
		req(2, app.FuncDirectOperate, crob),
		req(3, app.FuncSelect, crob),
		req(4, app.FuncDirectOperate, app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: 1, User: 1}), crob,
			app.FreeFormat(app.G120V9, app.AuthMAC{MAC: make([]byte, 16)})),
		req(5, app.FuncAuthRequest, app.FreeFormat(app.G120V2, app.AuthReply{CSQ: 1, User: 1, MAC: make([]byte, 16)})),
		req(6, app.FuncAuthRequest, app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: 1})),
		req(7, app.FuncAuthRequest, app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: 1, User: 1, WrappedKeys: make([]byte, 40)})),
		req(8, app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "a.txt", Mode: app.FileModeRead, RequestID: 1})),
		req(9, app.FuncRead, app.FreeFormat(app.G70V5, app.FileTransport{Handle: 1, Block: 0})),
		req(10, app.FuncGetFileInfo, app.FreeFormat(app.G70V7, app.FileDescriptor{Name: "/", RequestID: 1})),
		req(11, app.FuncImmediateFreeze, app.AllObjects(app.G20V0)),
		req(12, app.FuncAssignClass, app.AllObjects(app.G60V2), app.AllObjects(app.G1V0)),
		req(13, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})),
		req(14, app.FuncRead, app.AllObjects(app.GV(0, 254))),
		// Found by fuzzing: a range over every attribute set.
		req(15, app.FuncRead, app.Header{GV: app.GV(0, app.AttrAllAttributes), Qualifier: app.Qual4ByteStartStop, Stop: 0xFFFFFFFF}),
		req(1, app.FuncWrite, app.Ranged(app.GV(0, 10), 1, app.StringAttribute("x"))),
		req(2, app.FuncFreezeAtTime, app.Counted(app.G50V2, app.AbsoluteTime{Interval: 1}), app.AllObjects(app.G20V0)),
		req(3, app.FuncRead, app.AllObjects(app.G34V0)),
		// Count-limited event reads, a count of 0 among them.
		req(4, app.FuncRead, app.CountOf(app.G60V2, 0), app.CountOf(app.G2V3, 2), app.Header{GV: app.G32V0, Qualifier: app.Qual2ByteCount, Count: 1}),
		req(5, app.FuncFreezeAtTimeNoAck, app.Counted(app.G50V2, app.AbsoluteTime{}), app.AllObjects(app.G20V0)),
	}
	// Found by fuzzing: a READ of g70v5 under a qualifier that carries
	// indices only, so its object has no file transport block. It took
	// the outstation down (v1.3.2 and earlier).
	f.Add([]byte("\xc9\x01F\x05'\x01\b\x00\x01\x00\x00\x00\x00;;\x00\x00\x00"))
	for _, s := range seeds {
		b, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	srv, err := New(WithHandler(&countingHandler{}),
		WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, StatisticsThreshold: 1}),
		WithFileServer(FSFileServer{FS: fstest.MapFS{"a.txt": {Data: []byte("hello")}}}),
		WithAttributeSet(1, map[uint8]app.Attribute{10: app.StringAttribute("t")}, 10))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = srv.Close() })
	db := srv.Database()
	_ = db.AddBinaryInput(0, PointConfig{Class: 1}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddBinaryOutput(0, PointConfig{}, app.Binary{Flags: app.FlagOnline})
	_ = db.AddCounter(0, PointConfig{Class: 2}, app.Counter{Flags: app.FlagOnline})
	_ = db.AddAnalogInput(0, PointConfig{Class: 3}, app.Analog{Flags: app.FlagOnline})
	_ = db.Add(OctetString, 0, PointConfig{}, app.OctetString{Data: []byte{1}})
	a := srv.association(1)

	// A second outstation with the smallest fragments and many points of
	// mixed sizes, so that responses are split at every boundary.
	small, err := New(WithHandler(&countingHandler{}), WithMaxFragment(249, 2048))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = small.Close() })
	sdb := small.Database()
	for i := range uint32(200) {
		_ = sdb.AddBinaryInput(i, PointConfig{Class: Class(1 + i%3), EventVariation: uint8(1 + i%3)}, app.Binary{Flags: app.FlagOnline})
	}
	for i := range uint32(100) {
		_ = sdb.AddAnalogInput(i, PointConfig{Class: Class(1 + i%3), StaticVariation: uint8(1 + i%6), EventVariation: uint8(1 + i%8)}, app.Analog{Flags: app.FlagOnline})
	}
	for i := range uint32(50) {
		_ = sdb.Add(OctetString, i, PointConfig{Class: 1}, app.OctetString{Data: make([]byte, 1+i%40)})
	}
	sa := small.association(1)
	tick := 0

	run := func(t *testing.T, a *association, s *Server, frag []byte) {
		done := make(chan struct{})
		a.post(func() {
			a.handle(inbound{frag: frag, dest: s.Address(), at: time.Now()})
			close(done)
		})
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("request not handled within 5s")
		}
	}
	f.Fuzz(func(t *testing.T, frag []byte) {
		// The goroutines a request starts end with it.
		goroutines := runtime.NumGoroutine()
		// New events for every input, of every size.
		tick++
		_ = sdb.UpdateBinaryInput(uint32(max(tick%200, 0)), app.Binary{Value: tick%2 == 0, Flags: app.FlagOnline})
		_ = sdb.UpdateAnalogInput(uint32(max(tick%100, 0)), app.Analog{Value: float64(tick), Flags: app.FlagOnline})
		run(t, a, srv, frag)
		run(t, sa, small, frag)
		settles(t, goroutines)
		// What the outstations keep between requests stays within their
		// limits, whatever the requests were.
		for _, as := range []struct {
			a *association
			s *Server
		}{{a, srv}, {sa, small}} {
			withinLimits(t, as.a, as.s)
		}
	})
}

// withinLimits fails t when the state an association keeps between
// requests exceeds the limits of the outstation: the event buffer, the open
// files (16 per master), the fragments held during a probe, the file
// transport statuses not yet answered and the FREEZE_AT_TIME schedules.
func withinLimits(t *testing.T, a *association, s *Server) {
	t.Helper()
	var problems []string
	done := make(chan struct{})
	a.post(func() {
		defer close(done)
		if n := len(a.files); n > 16 {
			problems = append(problems, fmt.Sprintf("%d open files", n))
		}
		if n := len(a.held); n > maxHeld {
			problems = append(problems, fmt.Sprintf("%d fragments held", n))
		}
		if n := len(a.pendingFileStatus); n > 0 {
			problems = append(problems, fmt.Sprintf("%d file transport statuses left after the response", n))
		}
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("association did not answer within 5s")
	}
	a.events.mu.Lock()
	total := 0
	for typ := range a.events.count {
		if a.events.count[typ] > a.events.limit[typ] {
			problems = append(problems, fmt.Sprintf("%d events of type %d, limit %d", a.events.count[typ], typ, a.events.limit[typ]))
		}
		total += a.events.limit[typ]
	}
	if n := len(a.events.events); n > total {
		problems = append(problems, fmt.Sprintf("%d events buffered, limits %d", n, total))
	}
	a.events.mu.Unlock()
	s.mu.Lock()
	if n := len(s.freezes); n > MaxScheduledFreezes {
		problems = append(problems, fmt.Sprintf("%d scheduled freezes", n))
	}
	s.mu.Unlock()
	if len(problems) > 0 {
		t.Fatalf("state beyond the limits: %v", problems)
	}
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

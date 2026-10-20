// SPDX-License-Identifier: MIT

package server

import (
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
	}
	for _, s := range seeds {
		b, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	srv, err := New(WithHandler(&countingHandler{}),
		WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, StatisticsThreshold: 1}),
		WithFileServer(FSFileServer{FS: fstest.MapFS{"a.txt": {Data: []byte("hello")}}}))
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
	f.Fuzz(func(t *testing.T, frag []byte) {
		done := make(chan struct{})
		a.post(func() {
			a.handle(inbound{frag: frag, dest: srv.Address(), at: time.Now()})
			close(done)
		})
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("request not handled within 5s")
		}
	})
}

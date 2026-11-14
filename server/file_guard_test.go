// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// guardFile is a File that records its Close and may panic in it.
type guardFile struct {
	sinkFile
	panics bool
	mu     sync.Mutex
	closed int
	abort  bool
}

func (f *guardFile) Close(abort bool) error {
	f.mu.Lock()
	f.closed++
	f.abort = abort
	f.mu.Unlock()
	if f.panics {
		panic("close failed")
	}
	return nil
}

func (f *guardFile) closes() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed, f.abort
}

// guardFiles is a FileServer whose Open and Delete answer what the test
// says, and may wait for it.
type guardFiles struct {
	open     func(FileRequest) (File, app.FileStatus)
	opening  chan struct{} // receives when Open is called, if set
	deleting chan struct{} // receives when Delete is called, if set
	proceed  chan struct{} // Open and Delete wait for it, if set
}

func (g *guardFiles) Open(_ context.Context, req FileRequest) (File, app.FileStatus) {
	if g.opening != nil {
		g.opening <- struct{}{}
		<-g.proceed
	}
	return g.open(req)
}

func (g *guardFiles) Delete(_ context.Context, name string, _ uint32) app.FileStatus {
	if g.deleting != nil {
		g.deleting <- struct{}{}
		<-g.proceed
	}
	return app.FileSuccess
}

func (g *guardFiles) Info(context.Context, string) (app.FileDescriptor, app.FileStatus) {
	return app.FileDescriptor{}, app.FileSuccess
}

func openReq(name string) *app.Fragment {
	return req(1, app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: name, Mode: app.FileModeRead, RequestID: 1}))
}

func deleteReq(name string) *app.Fragment {
	return req(1, app.FuncDeleteFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: name, RequestID: 2}))
}

func statusOf(r *response) app.FileCommandStatus {
	return r.plans[0].headers[0].Objects[0].Value.(app.FileCommandStatus)
}

// TestDetachClosesFilesDespitePanic: a File whose Close panics neither
// keeps the other files of a master that went away open nor skips the
// communications failure that makes its session keys invalid (Table 7-8
// row 9).
func TestDetachClosesFilesDespitePanic(t *testing.T) {
	bad, good := &guardFile{panics: true}, &guardFile{}
	files := []*guardFile{bad, good}
	g := &guardFiles{open: func(FileRequest) (File, app.FileStatus) {
		f := files[0]
		files = files[1:]
		return f, app.FileSuccess
	}}
	srv, err := New(WithMasters(1), WithFileServer(g),
		WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, UpdateKey: specUpdateKey}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	a := srv.association(1)
	state := onAssoc(t, a, func() app.KeyStatus {
		for _, name := range []string{"/a", "/b"} {
			if st := statusOf(a.file(openReq(name))); st.Status != app.FileSuccess {
				t.Errorf("open %s: %s", name, st.Status)
			}
		}
		a.keys.state = app.KeyStatusOK
		a.detach()
		return a.keys.state
	})
	if state != app.KeyStatusCommFail {
		t.Fatalf("key status after detach: %v", state)
	}
	for i, f := range []*guardFile{bad, good} {
		if n, abort := f.closes(); n != 1 || !abort {
			t.Errorf("file %d: closed %d times, abort %v", i, n, abort)
		}
	}
	if n := onAssoc(t, a, func() int { return len(a.files) }); n != 0 || srv.handles.isOpen("/a") || srv.handles.isOpen("/b") {
		t.Fatalf("files left open: %d", n)
	}
}

// TestCloseFilePanicIsFatal: CLOSE_FILE of a File whose Close panics is
// FATAL, without the panic's text, and the handle is released.
func TestCloseFilePanicIsFatal(t *testing.T) {
	f := &guardFile{panics: true}
	srv, err := New(WithMasters(1), WithFileServer(&guardFiles{open: func(FileRequest) (File, app.FileStatus) { return f, app.FileSuccess }}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	a := srv.association(1)
	st := onAssoc(t, a, func() app.FileCommandStatus {
		h := statusOf(a.file(openReq("/f"))).Handle
		return statusOf(a.file(req(2, app.FuncCloseFile, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: h}))))
	})
	if st.Status != app.FileFatal || st.Text != "" || srv.handles.isOpen("/f") {
		t.Fatalf("close: %+v", st)
	}
}

// TestRefusedOpenClosesFile: a FileServer that refuses an OPEN_FILE but
// returns a File gets it closed, aborted; the handle is not kept.
func TestRefusedOpenClosesFile(t *testing.T) {
	for _, panics := range []bool{false, true} {
		f := &guardFile{panics: panics}
		srv, err := New(WithMasters(1), WithFileServer(&guardFiles{open: func(FileRequest) (File, app.FileStatus) {
			return f, app.FilePermissionDenied
		}}))
		if err != nil {
			t.Fatal(err)
		}
		a := srv.association(1)
		st := onAssoc(t, a, func() app.FileCommandStatus { return statusOf(a.file(openReq("/f"))) })
		if n, abort := f.closes(); st.Status != app.FilePermissionDenied || n != 1 || !abort || srv.handles.isOpen("/f") {
			t.Errorf("panics=%v: status %s, closed %d abort %v", panics, st.Status, n, abort)
		}
		_ = srv.Close()
	}
}

// TestOpenFileNamesCompareCleaned: a file is open under every name that
// names the same path (5.3.8 Rule 11): DELETE_FILE of it is FILE_LOCKED.
func TestOpenFileNamesCompareCleaned(t *testing.T) {
	var h fileHandles
	if _, ok := h.assign("/dir/f"); !ok {
		t.Fatal("assign")
	}
	for _, name := range []string{"/dir/f", "dir/f", `\dir\f`, "/dir/../dir/./f", "//dir//f"} {
		if !h.isOpen(name) || h.startDelete(name) {
			t.Errorf("%q not taken as the open file", name)
		}
	}
	if h.isOpen("/dir/g") {
		t.Error("another file is open")
	}
}

// TestDeleteAndOpenExclusive: a DELETE_FILE in progress and an OPEN_FILE
// of the same file in another association exclude each other: the second
// one is FILE_LOCKED (5.3.8 Rule 11).
func TestDeleteAndOpenExclusive(t *testing.T) {
	g := &guardFiles{
		open:     func(FileRequest) (File, app.FileStatus) { return &guardFile{}, app.FileSuccess },
		deleting: make(chan struct{}),
		proceed:  make(chan struct{}),
	}
	srv, err := New(WithMasters(1, 2), WithFileServer(g))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	a, b := srv.association(1), srv.association(2)

	// A delete waits in the FileServer: an open of that file is locked,
	// of another file not.
	deleted := make(chan app.FileStatus, 1)
	a.post(func() { deleted <- statusOf(a.file(deleteReq("/f"))).Status })
	<-g.deleting
	if st := onAssoc(t, b, func() app.FileStatus { return statusOf(b.file(openReq("f"))).Status }); st != app.FileLocked {
		t.Fatalf("open during the delete: %s", st)
	}
	if st := onAssoc(t, b, func() app.FileStatus { return statusOf(b.file(openReq("/g"))).Status }); st != app.FileSuccess {
		t.Fatalf("open of another file during the delete: %s", st)
	}
	g.proceed <- struct{}{}
	if st := <-deleted; st != app.FileSuccess {
		t.Fatalf("delete: %s", st)
	}
	if st := onAssoc(t, b, func() app.FileStatus { return statusOf(b.file(openReq("/f"))).Status }); st != app.FileSuccess {
		t.Fatalf("open after the delete: %s", st)
	}

	// An open waits in the FileServer: a delete of that file is locked.
	g.deleting = nil
	g.opening = make(chan struct{})
	opened := make(chan app.FileStatus, 1)
	a.post(func() { opened <- statusOf(a.file(openReq("/h"))).Status })
	<-g.opening
	if st := onAssoc(t, b, func() app.FileStatus { return statusOf(b.file(deleteReq("/h"))).Status }); st != app.FileLocked {
		t.Fatalf("delete during the open: %s", st)
	}
	g.proceed <- struct{}{}
	if st := <-opened; st != app.FileSuccess {
		t.Fatalf("open: %s", st)
	}
}

// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/otfabric/go-dnp3/app"
)

// faulty is a FileServer whose files fail: "/nil" opens to no file, and
// the files it opens fail to read, write and close.
type faulty struct{}

func (faulty) Open(_ context.Context, req FileRequest) (File, app.FileStatus) {
	if req.Name == "/nil" {
		return nil, app.FileSuccess
	}
	return brokenFile{}, app.FileSuccess
}
func (faulty) Delete(context.Context, string, uint32) app.FileStatus { return app.FileSuccess }
func (faulty) Info(context.Context, string) (app.FileDescriptor, app.FileStatus) {
	return app.FileDescriptor{Type: app.FileTypeSimple, Size: 3}, app.FileSuccess
}

type brokenFile struct{}

func (brokenFile) Read([]byte) (int, error)  { return 0, errors.New("bad sector") }
func (brokenFile) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func (brokenFile) Size() uint32              { return 3 }
func (brokenFile) Close(bool) error          { return errors.New("close failed") }

// TestFileRequestErrors: malformed file requests are parameter errors, and
// the failures of the file server reach the master as file statuses.
func TestFileRequestErrors(t *testing.T) {
	m := newMaster(t, WithFileServer(faulty{}))
	seq := uint8(0)
	ask := func(fc app.FunctionCode, hs ...app.Header) *app.Fragment {
		t.Helper()
		seq = app.NextSeq(seq)
		m.send(req(seq, fc, hs...))
		return m.recvFunc(app.FuncResponse)
	}
	cmd := app.FreeFormat(app.G70V3, app.FileCommand{Name: "/f", Mode: app.FileModeRead, RequestID: 1})
	status := app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 1, RequestID: 1})
	for _, c := range []struct {
		name string
		fc   app.FunctionCode
		hs   []app.Header
	}{
		{"two headers", app.FuncOpenFile, []app.Header{cmd, cmd}},
		{"open with a status", app.FuncOpenFile, []app.Header{status}},
		{"close with a command", app.FuncCloseFile, []app.Header{cmd}},
		{"delete with a status", app.FuncDeleteFile, []app.Header{status}},
		{"info with a command", app.FuncGetFileInfo, []app.Header{cmd}},
		{"authenticate with a command", app.FuncAuthenticateFile, []app.Header{cmd}},
	} {
		if f := ask(c.fc, c.hs...); !f.IIN.Has(app.IINParameterError) {
			t.Errorf("%s: %v", c.name, f)
		}
	}

	// A file server that opens no file is a fatal error.
	nilOpen := app.FreeFormat(app.G70V3, app.FileCommand{Name: "/nil", Mode: app.FileModeRead, RequestID: 1})
	if st := fileStatus(t, ask(app.FuncOpenFile, nilOpen)); st.Status != app.FileFatal {
		t.Fatalf("open to no file: %+v", st)
	}
	// A descriptor without a name is answered with the name asked for.
	if f := ask(app.FuncGetFileInfo, app.FreeFormat(app.G70V7, app.FileDescriptor{Name: "/f", RequestID: 1})); f.Headers[0].Objects[0].Value.(app.FileDescriptor).Name != "/f" {
		t.Fatalf("info: %v", f)
	}

	// A read that fails, and a block out of sequence.
	r := fileStatus(t, ask(app.FuncOpenFile, cmd))
	if st := transportStatus(t, ask(app.FuncRead, app.FreeFormat(app.G70V5, app.FileTransport{Handle: r.Handle, Block: 1}))); st.Status != app.FileBlockSequence {
		t.Fatalf("block out of sequence: %+v", st)
	}
	if st := transportStatus(t, ask(app.FuncRead, app.FreeFormat(app.G70V5, app.FileTransport{Handle: r.Handle}))); st.Status != app.FileFatal || st.Text != "bad sector" {
		t.Fatalf("failing read: %+v", st)
	}
	// A close that fails reports the error.
	if st := fileStatus(t, ask(app.FuncCloseFile, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: r.Handle, RequestID: 1}))); st.Status != app.FileFatal || st.Text != "close failed" {
		t.Fatalf("failing close: %+v", st)
	}

	// A write that fails.
	w := fileStatus(t, ask(app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "/w", Mode: app.FileModeWrite, Size: 1, RequestID: 1})))
	if st := transportStatus(t, ask(app.FuncWrite, app.FreeFormat(app.G70V5, app.FileTransport{Handle: w.Handle, Last: true, Data: []byte("x")}))); st.Status != app.FileFatal || st.Text != "disk full" {
		t.Fatalf("failing write: %+v", st)
	}
}

// TestFSFileServerDirectoryRead: a directory listing is read to its end.
func TestFSFileServerDirectoryRead(t *testing.T) {
	m := newMaster(t, WithFileServer(FSFileServer{FS: fstest.MapFS{"d/a.txt": {Data: []byte("alpha")}}}))
	m.send(req(1, app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "/d", Mode: app.FileModeRead, RequestID: 1})))
	st := fileStatus(t, m.recvFunc(app.FuncResponse))
	m.send(req(2, app.FuncRead, app.FreeFormat(app.G70V5, app.FileTransport{Handle: st.Handle})))
	f := m.recvFunc(app.FuncResponse)
	tr, ok := f.Headers[0].Objects[0].Value.(app.FileTransport)
	if !ok || !tr.Last {
		t.Fatalf("listing block: %v", f)
	}
	if ds, err := app.DecodeFileDescriptors(tr.Data); err != nil || len(ds) != 1 || ds[0].Name != "a.txt" {
		t.Fatalf("listing %+v %v", ds, err)
	}
}

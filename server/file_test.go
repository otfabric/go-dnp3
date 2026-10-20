// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/transport"
)

// sink is a FileServer whose files can be written, with what was closed.
type sink struct {
	mu      sync.Mutex
	written map[string][]byte
	aborted int
}

func (s *sink) Open(_ context.Context, req FileRequest) (File, app.FileStatus) {
	if req.Mode == app.FileModeRead {
		return &sinkFile{r: bytes.NewReader([]byte("hello"))}, app.FileSuccess
	}
	return &sinkFile{s: s, name: req.Name}, app.FileSuccess
}
func (s *sink) Delete(context.Context, string, uint32) app.FileStatus { return app.FileSuccess }
func (s *sink) Info(context.Context, string) (app.FileDescriptor, app.FileStatus) {
	return app.FileDescriptor{}, app.FileSuccess
}

type sinkFile struct {
	r    io.Reader
	s    *sink
	name string
	buf  bytes.Buffer
}

func (f *sinkFile) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *sinkFile) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *sinkFile) Size() uint32                { return 5 }
func (f *sinkFile) Close(abort bool) error {
	if f.s == nil {
		return nil
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if abort {
		f.s.aborted++
	} else {
		f.s.written[f.name] = bytes.Clone(f.buf.Bytes())
	}
	return nil
}

func fileStatus(t *testing.T, f *app.Fragment) app.FileCommandStatus {
	t.Helper()
	st, ok := f.Headers[0].Objects[0].Value.(app.FileCommandStatus)
	if !ok {
		t.Fatalf("no file command status: %v", f)
	}
	return st
}

func transportStatus(t *testing.T, f *app.Fragment) app.FileTransportStatus {
	t.Helper()
	st, ok := f.Headers[0].Objects[0].Value.(app.FileTransportStatus)
	if !ok {
		t.Fatalf("no file transport status: %v", f)
	}
	return st
}

func TestFileWrite(t *testing.T) {
	s := &sink{written: map[string][]byte{}}
	m := newMaster(t, WithFileServer(s))
	seq := uint8(0)
	next := func() uint8 { seq = app.NextSeq(seq); return seq }
	open := func(mode app.FileMode, maxBlock uint16) app.FileCommandStatus {
		t.Helper()
		m.send(req(next(), app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "/f", Mode: mode, Size: 10, MaxBlockSize: maxBlock, RequestID: 1})))
		return fileStatus(t, m.recvFunc(app.FuncResponse))
	}
	write := func(handle, block uint32, last bool, data []byte) app.FileTransportStatus {
		t.Helper()
		m.send(req(next(), app.FuncWrite, app.FreeFormat(app.G70V5, app.FileTransport{Handle: handle, Block: block, Last: last, Data: data})))
		return transportStatus(t, m.recvFunc(app.FuncResponse))
	}
	closeFile := func(fc app.FunctionCode, handle uint32) app.FileCommandStatus {
		t.Helper()
		m.send(req(next(), fc, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: handle, RequestID: 1})))
		return fileStatus(t, m.recvFunc(app.FuncResponse))
	}

	st := open(app.FileModeWrite, 4)
	if st.Status != app.FileSuccess || st.MaxBlockSize != 4 {
		t.Fatalf("open for writing: %+v", st)
	}
	h := st.Handle
	for _, c := range []struct {
		block uint32
		data  string
		want  app.FileStatus
	}{
		{0, "abcd", app.FileSuccess},
		{0, "abcd", app.FileSuccess}, // a repeat of the last block is not written twice
		{2, "efgh", app.FileBlockSequence},
		{1, "efghi", app.FileWriteBlockSize},
		{1, "ef", app.FileSuccess},
	} {
		if got := write(h, c.block, false, []byte(c.data)); got.Status != c.want {
			t.Fatalf("block %d %q: %s, want %s", c.block, c.data, got.Status, c.want)
		}
	}
	if got := write(h+100, 0, true, []byte("x")); got.Status != app.FileInvalidHandle {
		t.Fatalf("unknown handle: %s", got.Status)
	}
	if st := closeFile(app.FuncCloseFile, h); st.Status != app.FileSuccess || string(s.written["/f"]) != "abcdef" {
		t.Fatalf("close: %+v, written %q", st, s.written["/f"])
	}
	if st := closeFile(app.FuncCloseFile, h); st.Status != app.FileInvalidHandle {
		t.Fatalf("close twice: %s", st.Status)
	}
	// A file opened for reading cannot be written; ABORT discards a write.
	r := open(app.FileModeRead, 0)
	if got := write(r.Handle, 0, true, []byte("x")); got.Status != app.FileInvalidHandle {
		t.Fatalf("write to a file opened for reading: %s", got.Status)
	}
	w := open(app.FileModeWrite, 0)
	if w.MaxBlockSize != uint16(transport.DefaultMaxFragment-20) {
		t.Fatalf("default block size %d", w.MaxBlockSize)
	}
	if st := closeFile(app.FuncAbortFile, w.Handle); st.Status != app.FileSuccess || s.aborted != 1 {
		t.Fatalf("abort: %+v, %d aborted", st, s.aborted)
	}
	// At most 16 files are open at once.
	for range 15 {
		open(app.FileModeRead, 0)
	}
	if st := open(app.FileModeRead, 0); st.Status != app.FileTooManyOpen {
		t.Fatalf("seventeenth open: %s", st.Status)
	}
	// A WRITE of another file object is not understood.
	m.send(req(next(), app.FuncWrite, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 1})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINObjectUnknown) {
		t.Fatalf("WRITE of g70v4: %v", f)
	}
}

// TestFileBlockLimits: written blocks fit the receive fragment size, and
// with secure authentication the objects of aggressive mode as well.
func TestFileBlockLimits(t *testing.T) {
	cases := []struct {
		opts []Option
		mode app.FileMode
		want int
	}{
		{nil, app.FileModeRead, transport.DefaultMaxFragment - 20},
		{[]Option{WithMaxFragment(2048, 1024)}, app.FileModeWrite, 1024 - 20},
		{[]Option{WithMaxFragment(1024, 2048)}, app.FileModeRead, 1024 - 20},
		{[]Option{WithSecureAuthentication(SecureAuth{User: secauth.User{Number: 1, Key: testSessionKey}, Critical: []app.FunctionCode{app.FuncDirectOperate}})}, app.FileModeWrite,
			transport.DefaultMaxFragment - 20 - secauth.AggressiveOverhead},
	}
	for i, c := range cases {
		m := newMaster(t, append(c.opts, WithFileServer(FSFileServer{FS: fstest.MapFS{"f": {Data: []byte("x")}}}))...)
		if c.mode != app.FileModeRead {
			m = newMaster(t, append(c.opts, WithFileServer(&sink{written: map[string][]byte{}}))...)
		}
		m.send(req(1, app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "f", Mode: c.mode, Size: 1, RequestID: 1})))
		if st := fileStatus(t, m.recvFunc(app.FuncResponse)); st.Status != app.FileSuccess || int(st.MaxBlockSize) != c.want {
			t.Errorf("case %d: %+v, want block size %d", i, st, c.want)
		}
	}
}

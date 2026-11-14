// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"math"
	"testing"
	"testing/fstest"
	"time"

	"github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// Spec tests of file transfer (IEEE 1815-2012 4.4.17 to 4.4.20, 5.3.8 and
// A.27) at the outstation.

// fileMaster is a master of an outstation serving files, with the
// requests of file transfer.
type fileMaster struct {
	*master
	t   *testing.T
	seq uint8
}

func newFileMaster(t *testing.T, opts ...Option) *fileMaster {
	return &fileMaster{master: newMaster(t, opts...), t: t}
}

func (m *fileMaster) next() uint8 { m.seq = app.NextSeq(m.seq); return m.seq }

func (m *fileMaster) open(c app.FileCommand) app.FileCommandStatus {
	m.t.Helper()
	m.send(req(m.next(), app.FuncOpenFile, app.FreeFormat(app.G70V3, c)))
	return fileStatus(m.t, m.recvFunc(app.FuncResponse))
}

func (m *fileMaster) write(handle, block uint32, data string) app.FileTransportStatus {
	m.t.Helper()
	m.send(req(m.next(), app.FuncWrite, app.FreeFormat(app.G70V5, app.FileTransport{Handle: handle, Block: block, Data: []byte(data)})))
	return transportStatus(m.t, m.recvFunc(app.FuncResponse))
}

func (m *fileMaster) closeFile(fc app.FunctionCode, st app.FileCommandStatus) app.FileCommandStatus {
	m.t.Helper()
	m.send(req(m.next(), fc, app.FreeFormat(app.G70V4, st)))
	return fileStatus(m.t, m.recvFunc(app.FuncResponse))
}

// TestSpec4_4_17_1_1_FileTimeout: 4.4.17.1.1 (p. 67): an outstation shall
// close a file when no request names its handle for a configured time, and
// report it to the master with a file transport status event, status
// HANDLE_EXPIRED (5.3.8 Rule 12, p. 120). That event is in the class
// WithFileTimeout sets and, as an event, asks for confirmation (A.27.6.1,
// p. 679); the handle is invalid after it.
func TestSpec4_4_17_1_1_FileTimeout(t *testing.T) {
	s := &sink{written: map[string][]byte{}}
	m := newFileMaster(t, WithFileServer(s), WithFileTimeout(100*time.Millisecond, 2))
	st := m.open(app.FileCommand{Name: "/w", Mode: app.FileModeWrite, Size: 10, RequestID: 1})
	if st.Status != app.FileSuccess {
		t.Fatalf("open: %+v", st)
	}
	var ev *app.Fragment
	deadline := time.Now().Add(3 * time.Second)
	for ev == nil {
		if time.Now().After(deadline) {
			t.Fatal("no HANDLE_EXPIRED event")
		}
		seq := m.next()
		m.send(req(seq, app.FuncRead, app.AllObjects(app.G60V2)))
		if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
			t.Fatalf("class 1 poll: %s", f)
		}
		m.send(req(m.next(), app.FuncRead, app.AllObjects(app.G60V3)))
		if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
			ev = f
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ev.Control.CON || ev.Headers[0].GV != app.G70V6 {
		t.Fatalf("event response %s", ev)
	}
	if ts := transportStatus(t, ev); ts.Handle != st.Handle || ts.Status != app.FileHandleExpired {
		t.Fatalf("event %+v", ts)
	}
	// Unconfirmed, the event is reported again, read by its object.
	m.send(req(m.next(), app.FuncRead, app.AllObjects(app.G70V6)))
	f := m.recvFunc(app.FuncResponse)
	if len(f.Headers) != 1 || transportStatus(t, f).Status != app.FileHandleExpired {
		t.Fatalf("READ g70v6: %s", f)
	}
	m.send(confirm(m.seq, false))
	m.send(req(m.next(), app.FuncRead, app.ClassHeaders(1, 2, 3)...))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
		t.Fatalf("after the confirmation: %s", f)
	}
	if got := m.write(st.Handle, 0, "ab"); got.Status != app.FileInvalidHandle {
		t.Fatalf("write after the timeout: %s", got.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted != 1 || len(s.written) != 0 {
		t.Fatalf("%d aborted, %d written: the expired file is closed without its data", s.aborted, len(s.written))
	}
}

// TestSpec4_4_17_1_1_FileTimeoutRestartedByRequests: the timeout counts
// from the last request that named the handle (4.4.17.1.1, p. 67).
func TestSpec4_4_17_1_1_FileTimeoutRestartedByRequests(t *testing.T) {
	m := newFileMaster(t, WithFileServer(&sink{written: map[string][]byte{}}), WithFileTimeout(400*time.Millisecond, 1))
	st := m.open(app.FileCommand{Name: "/w", Mode: app.FileModeWrite, RequestID: 1})
	for b := range uint32(5) {
		time.Sleep(100 * time.Millisecond)
		if got := m.write(st.Handle, b, "x"); got.Status != app.FileSuccess {
			t.Fatalf("block %d after %d ms: %s", b, 100*(b+1), got.Status)
		}
	}
	if got := m.closeFile(app.FuncCloseFile, app.FileCommandStatus{Handle: st.Handle}); got.Status != app.FileSuccess {
		t.Fatalf("close: %s", got.Status)
	}
}

// TestSpecWithFileTimeout_Invalid: the timeout is positive and the event
// class one of 1 to 3.
func TestSpecWithFileTimeout_Invalid(t *testing.T) {
	for _, c := range []struct {
		d     time.Duration
		class Class
	}{{0, 1}, {-time.Second, 1}, {time.Second, 0}, {time.Second, 4}} {
		if _, err := New(WithFileTimeout(c.d, c.class)); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Errorf("WithFileTimeout(%v, %d): %v", c.d, c.class, err)
		}
	}
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if s.opts.fileTimeout != DefaultFileTimeout || s.opts.fileClass != 1 {
		t.Fatalf("defaults: %v class %d", s.opts.fileTimeout, s.opts.fileClass)
	}
}

// TestSpec5_3_8_Rule9_HandlesUnique: 5.3.8 Rule 9 (p. 119): the handle of
// an open file shall be unique, and a handle is never 0 (4.4.17.1.1,
// p. 67): the counter skips 0 and the handles in use when it wraps.
func TestSpec5_3_8_Rule9_HandlesUnique(t *testing.T) {
	var h fileHandles
	if got, _ := h.assign("a"); got != 1 {
		t.Fatalf("first handle %d", got)
	}
	h.last = math.MaxUint32
	if got, _ := h.assign("b"); got != 2 {
		t.Fatalf("after the wrap: %d, want 2 (0 and 1 skipped)", got)
	}
	h.release(1)
	h.last = 0
	if got, _ := h.assign("c"); got != 1 {
		t.Fatalf("a released handle is reused: %d", got)
	}
	if !h.isOpen("b") || h.isOpen("d") {
		t.Fatal("isOpen")
	}

	// The handles of two associations come from the same counter.
	srv, err := New(WithMasters(1, 2), WithFileServer(&sink{written: map[string][]byte{}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	a, b := srv.association(1), srv.association(2)
	open := func(as *association) uint32 {
		got := make(chan uint32, 1)
		as.post(func() {
			r := as.file(req(1, app.FuncOpenFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "/f", Mode: app.FileModeRead, RequestID: 1})))
			got <- r.plans[0].headers[0].Objects[0].Value.(app.FileCommandStatus).Handle
		})
		return <-got
	}
	if ha, hb := open(a), open(b); ha == hb {
		t.Fatalf("both associations got handle %d", ha)
	}
}

// TestSpec5_3_8_Rule11_OpenFileNotDeleted: 5.3.8 Rule 11 (p. 120): an
// outstation shall not delete a file that is open; the answer is
// FILE_LOCKED until it is closed.
func TestSpec5_3_8_Rule11_OpenFileNotDeleted(t *testing.T) {
	m := newFileMaster(t, WithFileServer(&sink{written: map[string][]byte{}}))
	st := m.open(app.FileCommand{Name: "/f", Mode: app.FileModeRead, RequestID: 1})
	del := func() app.FileStatus {
		m.send(req(m.next(), app.FuncDeleteFile, app.FreeFormat(app.G70V3, app.FileCommand{Name: "/f", RequestID: 2})))
		return fileStatus(t, m.recvFunc(app.FuncResponse)).Status
	}
	if got := del(); got != app.FileLocked {
		t.Fatalf("delete of an open file: %s", got)
	}
	m.closeFile(app.FuncCloseFile, app.FileCommandStatus{Handle: st.Handle})
	if got := del(); got != app.FileSuccess {
		t.Fatalf("delete after the close: %s", got)
	}
}

// TestSpec4_4_17_3_CloseEchoesRequest: 4.4.17.3 (p. 71) and 4.4.17.5
// (pp. 73-74): the answer to CLOSE_FILE and ABORT_FILE carries the handle,
// size, maximum block size, request identifier and text of the request;
// the status is the outstation's.
func TestSpec4_4_17_3_CloseEchoesRequest(t *testing.T) {
	m := newFileMaster(t, WithFileServer(&sink{written: map[string][]byte{}}))
	for _, fc := range []app.FunctionCode{app.FuncCloseFile, app.FuncAbortFile} {
		st := m.open(app.FileCommand{Name: "/w", Mode: app.FileModeWrite, RequestID: 1})
		c := app.FileCommandStatus{Handle: st.Handle, Size: 77, MaxBlockSize: 33, RequestID: 9, Status: app.FileUndefined, Text: "bye"}
		got := m.closeFile(fc, c)
		c.Status = app.FileSuccess
		if got != c {
			t.Fatalf("%s: %+v, want %+v", fc, got, c)
		}
	}
	c := app.FileCommandStatus{Handle: 999, Size: 1, MaxBlockSize: 2, RequestID: 3, Text: "x"}
	got := m.closeFile(app.FuncCloseFile, c)
	c.Status = app.FileInvalidHandle
	if got != c {
		t.Fatalf("unknown handle: %+v, want %+v", got, c)
	}
}

// TestSpec4_4_17_5_FailedAbort: 4.4.17.5 (p. 74): an outstation that
// cannot abort a file answers CANNOT_ABORT; a close that fails is FATAL
// (Table 11-8, p. 330). The handle is invalid after either.
func TestSpec4_4_17_5_FailedAbort(t *testing.T) {
	m := newFileMaster(t, WithFileServer(faulty{}))
	for _, c := range []struct {
		fc   app.FunctionCode
		want app.FileStatus
	}{{app.FuncAbortFile, app.FileCannotAbort}, {app.FuncCloseFile, app.FileFatal}} {
		st := m.open(app.FileCommand{Name: "/x", Mode: app.FileModeWrite, RequestID: 1})
		got := m.closeFile(c.fc, app.FileCommandStatus{Handle: st.Handle})
		if got.Status != c.want || got.Text != "close failed" {
			t.Fatalf("%s: %+v", c.fc, got)
		}
		if got := m.closeFile(c.fc, app.FileCommandStatus{Handle: st.Handle}); got.Status != app.FileInvalidHandle {
			t.Fatalf("%s again: %s", c.fc, got.Status)
		}
	}
}

// TestSpec4_4_18_InfoCarriesRequestedName: 4.4.18 (p. 75): the file
// descriptor answering GET_FILE_INFO describes the file named in the
// request, by that name.
func TestSpec4_4_18_InfoCarriesRequestedName(t *testing.T) {
	m := newFileMaster(t, WithFileServer(faulty{}))
	m.send(req(1, app.FuncGetFileInfo, app.FreeFormat(app.G70V7, app.FileDescriptor{Name: "/dir/x", RequestID: 4})))
	f := m.recvFunc(app.FuncResponse)
	d, ok := f.Headers[0].Objects[0].Value.(app.FileDescriptor)
	if !ok || d.Name != "/dir/x" || d.RequestID != 4 || d.Size != 3 {
		t.Fatalf("descriptor %s", f)
	}
}

// TestSpec4_4_17_2_1_WriteBeyondSize: 4.4.17.2.1 (pp. 68-69): the master
// writes no more than the size the open declared; octets beyond it are
// refused with BUFFER_OVERRUN (A.27.6.2.2, p. 680) and the file closed
// (5.3.8 Rule 14, p. 120). A size of 0 or 0xFFFFFFFF is not known (5.3.8
// Rule 8, p. 119) and limits nothing.
func TestSpec4_4_17_2_1_WriteBeyondSize(t *testing.T) {
	s := &sink{written: map[string][]byte{}}
	m := newFileMaster(t, WithFileServer(s))
	st := m.open(app.FileCommand{Name: "/w", Mode: app.FileModeWrite, Size: 4, MaxBlockSize: 4, RequestID: 1})
	if got := m.write(st.Handle, 0, "abc"); got.Status != app.FileSuccess {
		t.Fatalf("3 of 4 octets: %s", got.Status)
	}
	if got := m.write(st.Handle, 1, "de"); got.Status != app.FileBufferOverrun {
		t.Fatalf("5 of 4 octets: %s", got.Status)
	}
	if got := m.write(st.Handle, 1, "d"); got.Status != app.FileInvalidHandle {
		t.Fatalf("after the overrun: %s", got.Status)
	}
	for _, size := range []uint32{0, unknownFileSize} {
		st := m.open(app.FileCommand{Name: "/u", Mode: app.FileModeWrite, Size: size, MaxBlockSize: 4, RequestID: 1})
		for b := range uint32(3) {
			if got := m.write(st.Handle, b, "abcd"); got.Status != app.FileSuccess {
				t.Fatalf("size %#x block %d: %s", size, b, got.Status)
			}
		}
		if got := m.closeFile(app.FuncCloseFile, app.FileCommandStatus{Handle: st.Handle}); got.Status != app.FileSuccess {
			t.Fatalf("close: %s", got.Status)
		}
		s.mu.Lock()
		w := string(s.written["/u"])
		s.mu.Unlock()
		if w != "abcdabcdabcd" {
			t.Fatalf("size %#x: wrote %q", size, w)
		}
	}
}

// TestSpecTable11_8_InvalidMode: Table 11-8 (p. 330): INVALID_MODE is the
// status of an open with an operation mode the outstation does not
// support; A.27.3 defines read (1), write (2) and append (3). The file
// server is not asked.
func TestSpecTable11_8_InvalidMode(t *testing.T) {
	m := newFileMaster(t, WithFileServer(faulty{}))
	for _, mode := range []app.FileMode{app.FileModeNull, 4, 0xFFFF} {
		if st := m.open(app.FileCommand{Name: "/nil", Mode: mode, RequestID: 5}); st.Status != app.FileInvalidMode || st.Handle != 0 || st.RequestID != 5 {
			t.Fatalf("mode %d: %+v", mode, st)
		}
	}
}

// TestSpec4_4_18_FSFileServerDescriptors: 4.4.18 (p. 75): the size of a
// directory is the number of its entries; the permissions (5.3.2, p. 113)
// of what FSFileServer serves are read for owner, group and world, and
// execute for a directory.
func TestSpec4_4_18_FSFileServerDescriptors(t *testing.T) {
	s := FSFileServer{FS: fstest.MapFS{"d/a": {Data: []byte("alpha")}, "d/b": {Data: []byte("b")}}}
	d, st := s.Info(context.Background(), "/d")
	exec := app.PermOwnerExecute | app.PermGroupExecute | app.PermWorldExecute
	if st != app.FileSuccess || d.Type != app.FileTypeDirectory || d.Size != 2 || d.Permissions != readPermissions|exec {
		t.Fatalf("directory: %+v %s", d, st)
	}
	f, st := s.Info(context.Background(), "/d/a")
	if st != app.FileSuccess || d.Name != "/d" || f.Type != app.FileTypeSimple || f.Size != 5 || f.Permissions != readPermissions {
		t.Fatalf("file: %+v %s", f, st)
	}
}

// TestSpec4_4_17_1_1_OnlyIdleFileExpires: 4.4.17.1.1 (p. 67): the timeout
// is per file: of two open files only the one that no request named for
// the file timeout is closed and reported with HANDLE_EXPIRED (5.3.8 Rule
// 12, p. 120); the other stays open and is written and closed as usual.
// The test makes the first file's last request an hour old.
func TestSpec4_4_17_1_1_OnlyIdleFileExpires(t *testing.T) {
	s := &sink{written: map[string][]byte{}}
	m := newFileMaster(t, WithFileServer(s), WithFileTimeout(time.Hour, 1))
	idle := m.open(app.FileCommand{Name: "/idle", Mode: app.FileModeWrite, RequestID: 1})
	busy := m.open(app.FileCommand{Name: "/busy", Mode: app.FileModeWrite, RequestID: 2})
	if idle.Status != app.FileSuccess || busy.Status != app.FileSuccess {
		t.Fatalf("open: %+v %+v", idle, busy)
	}
	a := m.srv.association(1)
	onAssoc(t, a, func() bool {
		a.files[idle.Handle].used = time.Now().Add(-2 * time.Hour)
		return true
	})
	var ev *app.Fragment
	eventually(t, "the HANDLE_EXPIRED event", func() bool {
		m.send(req(m.next(), app.FuncRead, app.AllObjects(app.G60V2)))
		if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 0 {
			ev = f
			return true
		}
		return false
	})
	if ts := transportStatus(t, ev); len(ev.Headers[0].Objects) != 1 || ts.Handle != idle.Handle || ts.Status != app.FileHandleExpired {
		t.Fatalf("events %v", ev)
	}
	m.send(confirm(m.seq, false))
	if got := m.write(busy.Handle, 0, "ok"); got.Status != app.FileSuccess {
		t.Fatalf("write to the other file: %s", got.Status)
	}
	if got := m.write(idle.Handle, 0, "x"); got.Status != app.FileInvalidHandle {
		t.Fatalf("write to the expired file: %s", got.Status)
	}
	if got := m.closeFile(app.FuncCloseFile, app.FileCommandStatus{Handle: busy.Handle}); got.Status != app.FileSuccess {
		t.Fatalf("close: %s", got.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted != 1 || string(s.written["/busy"]) != "ok" {
		t.Fatalf("%d aborted, written %q", s.aborted, s.written)
	}
}

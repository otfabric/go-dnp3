// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
)

// FileRequest is an OPEN_FILE request.
type FileRequest struct {
	// Name is the file name as the master sent it.
	Name string
	// Mode is read, write or append.
	Mode app.FileMode
	// Size is the size of the file to write, or 0.
	Size uint32
	// Permissions and Created are what the master asks a new file to get.
	Permissions app.Permissions
	Created     app.Timestamp
	// AuthKey is the key from AUTHENTICATE_FILE, or 0.
	AuthKey uint32
	// Master is the link address of the master.
	Master link.Address
}

// File is an open file. Read is called for files opened for reading,
// Write for files opened for writing or appending.
type File interface {
	io.Reader
	io.Writer
	// Size returns the size of a file opened for reading.
	Size() uint32
	// Close ends the transfer. abort is set for ABORT_FILE and when the
	// master disappeared: a file being written should then be discarded.
	Close(abort bool) error
}

// FileServer serves file transfer (group 70). Its methods are called on
// the goroutine of the master's association. A status other than
// app.FileSuccess refuses the operation.
type FileServer interface {
	Open(ctx context.Context, req FileRequest) (File, app.FileStatus)
	Delete(ctx context.Context, name string, authKey uint32) app.FileStatus
	Info(ctx context.Context, name string) (app.FileDescriptor, app.FileStatus)
}

// FileAuthenticator is an optional interface of a [FileServer]: without
// it AUTHENTICATE_FILE returns the key 0, which Open then receives.
type FileAuthenticator interface {
	Authenticate(ctx context.Context, user, password string) (key uint32, ok bool)
}

// openFile is a file an association has open.
type openFile struct {
	f        File
	name     string
	mode     app.FileMode
	maxBlock int
	// size is the size the open of a write declared, unknownFileSize when
	// the master did not know it, and written the octets written so far.
	size    uint32
	written uint64
	next    uint32 // next block expected (write) or to send (read)
	last    *app.FileTransport
	used    time.Time
}

// unknownFileSize is the size of a file to write whose size the master
// does not know (IEEE 1815-2012 5.3.8 Rule 8, p. 119).
const unknownFileSize = 0xFFFFFFFF

// DefaultFileTimeout is how long an open file may go without a request
// naming its handle before the outstation closes it (IEEE 1815-2012
// 4.4.17.1.1, p. 67), when WithFileTimeout does not set it.
const DefaultFileTimeout = 5 * time.Minute

// fileHandles assigns the handles of open files. They are unique to the
// outstation, across its associations (IEEE 1815-2012 5.3.8 Rule 9,
// p. 119), and never 0 (4.4.17.1.1, p. 67).
type fileHandles struct {
	mu   sync.Mutex
	last uint32
	// open maps the handles in use to the names of their files: a file
	// that is open cannot be deleted (5.3.8 Rule 11, p. 120).
	open map[uint32]string
}

// assign returns a new handle for the file name. The handles in use are
// bounded by the open files of every association, so the search ends.
func (h *fileHandles) assign(name string) uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.open == nil {
		h.open = map[uint32]string{}
	}
	for {
		h.last++
		if _, used := h.open[h.last]; h.last != 0 && !used {
			h.open[h.last] = name
			return h.last
		}
	}
}

// release frees a handle whose file was closed.
func (h *fileHandles) release(handle uint32) {
	h.mu.Lock()
	delete(h.open, handle)
	h.mu.Unlock()
}

// isOpen reports whether a file of that name is open in any association.
// Names are compared as the masters sent them.
func (h *fileHandles) isOpen(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.open {
		if n == name {
			return true
		}
	}
	return false
}

// closeFile closes an open file and makes its handle invalid.
func (a *association) closeFile(handle uint32, abort bool) error {
	of := a.files[handle]
	delete(a.files, handle)
	a.srv.handles.release(handle)
	return of.f.Close(abort)
}

// fileDeadline is when the open file used least recently times out, or
// zero without open files.
func (a *association) fileDeadline() time.Time {
	var next time.Time
	for _, of := range a.files {
		if at := of.used.Add(a.srv.opts.fileTimeout); next.IsZero() || at.Before(next) {
			next = at
		}
	}
	return next
}

// expireFiles closes the files that no request named for the file
// timeout and reports each with a file transport status event, status
// HANDLE_EXPIRED (IEEE 1815-2012 4.4.17.1.1, p. 67; 5.3.8 Rule 12,
// p. 120). The event is in the class of WithFileTimeout; as an event it
// asks for confirmation (A.27.6.1, p. 679).
func (a *association) expireFiles(now time.Time) {
	var evs []event
	for h, of := range a.files {
		if now.Sub(of.used) < a.srv.opts.fileTimeout {
			continue
		}
		a.log.Info("file closed after inactivity", "handle", h, "name", of.name)
		_ = a.closeFile(h, true) // the final state of the file is undefined
		evs = append(evs, event{typ: fileStatusEvent, index: h, class: a.srv.opts.fileClass,
			value: app.FileTransportStatus{Handle: h, Block: of.next, Status: app.FileHandleExpired}})
	}
	if len(evs) > 0 {
		a.events.add(evs)
	}
}

// file handles the file control function codes.
func (a *association) file(req *app.Fragment) *response {
	fsrv := a.srv.opts.files
	if fsrv == nil {
		return &response{iin: app.IINNoFuncCodeSupport}
	}
	if len(req.Headers) != 1 || len(req.Headers[0].Objects) != 1 {
		return &response{iin: app.IINParameterError}
	}
	ctx, cancel := a.srv.handlerContext()
	defer cancel()
	v := req.Headers[0].Objects[0].Value
	ff := func(o app.Value) *response { return headers(app.FreeFormat(app.GV(70, gvOf(o)), o)) }

	switch req.Function {
	case app.FuncOpenFile:
		c, ok := v.(app.FileCommand)
		if !ok {
			return &response{iin: app.IINParameterError}
		}
		st := app.FileCommandStatus{RequestID: c.RequestID}
		if c.Mode != app.FileModeRead && c.Mode != app.FileModeWrite && c.Mode != app.FileModeAppend {
			// Table 11-8 (p. 330): an unsupported or unknown operation
			// mode; A.27.3 defines read, write and append.
			st.Status = app.FileInvalidMode
			return ff(st)
		}
		if len(a.files) >= 16 {
			st.Status = app.FileTooManyOpen
			return ff(st)
		}
		f, status := fsrv.Open(ctx, FileRequest{Name: c.Name, Mode: c.Mode, Size: c.Size, Permissions: c.Permissions,
			Created: c.Created, AuthKey: c.AuthKey, Master: a.master})
		st.Status = status
		if status != app.FileSuccess || f == nil {
			if st.Status == app.FileSuccess {
				st.Status = app.FileFatal
			}
			return ff(st)
		}
		// The block must fit a response (header 4, object header 6, size
		// 2, handle and block number 8) and, written, a request; with
		// secure authentication a request in aggressive mode also
		// carries g120v3 and g120v9.
		limit := a.srv.opts.maxTxFragment - 20
		if c.Mode != app.FileModeRead {
			limit = min(limit, a.srv.opts.maxRxFragment-20)
			if a.srv.opts.auth != nil {
				limit -= secauth.AggressiveOverhead
			}
		}
		// A block travels in a g70v5 object, whose two-octet size also
		// counts the handle and block number: with fragments over 65547
		// octets the object, not the fragment, is the limit.
		limit = min(limit, maxFileBlock)
		maxBlock := int(c.MaxBlockSize)
		if maxBlock == 0 || maxBlock > limit {
			maxBlock = limit
		}
		h := a.srv.handles.assign(c.Name)
		size := uint32(unknownFileSize)
		if c.Mode != app.FileModeRead && c.Size != 0 {
			// A size of 0 is taken as not known, as 0xFFFFFFFF is (5.3.8
			// Rule 8): masters send it for "no size".
			size = c.Size
		}
		a.files[h] = &openFile{f: f, name: c.Name, mode: c.Mode, maxBlock: maxBlock, size: size, used: time.Now()}
		st.Handle, st.MaxBlockSize = h, uint16(min(max(maxBlock, 0), 0xFFFF))
		if c.Mode == app.FileModeRead {
			st.Size = f.Size()
		}
		return ff(st)

	case app.FuncCloseFile, app.FuncAbortFile:
		c, ok := v.(app.FileCommandStatus)
		if !ok {
			return &response{iin: app.IINParameterError}
		}
		// The answer repeats the request's handle, size, maximum block
		// size and text (4.4.17.3, p. 71; 4.4.17.5, pp. 73-74); only the
		// status is the outstation's.
		st := c
		st.Status = app.FileSuccess
		if _, ok := a.files[c.Handle]; !ok {
			st.Status = app.FileInvalidHandle
			return ff(st)
		}
		abort := req.Function == app.FuncAbortFile
		if err := a.closeFile(c.Handle, abort); err != nil {
			// An abort that cannot be done is CANNOT_ABORT (4.4.17.5,
			// p. 74); a close that fails is FATAL (Table 11-8, p. 330).
			st.Status, st.Text = app.FileFatal, err.Error()
			if abort {
				st.Status = app.FileCannotAbort
			}
		}
		return ff(st)

	case app.FuncDeleteFile:
		c, ok := v.(app.FileCommand)
		if !ok {
			return &response{iin: app.IINParameterError}
		}
		if a.srv.handles.isOpen(c.Name) {
			// An open file may not be deleted (5.3.8 Rule 11, p. 120).
			return ff(app.FileCommandStatus{RequestID: c.RequestID, Status: app.FileLocked})
		}
		return ff(app.FileCommandStatus{RequestID: c.RequestID, Status: fsrv.Delete(ctx, c.Name, c.AuthKey)})

	case app.FuncGetFileInfo:
		d, ok := v.(app.FileDescriptor)
		if !ok {
			return &response{iin: app.IINParameterError}
		}
		info, status := fsrv.Info(ctx, d.Name)
		if status != app.FileSuccess {
			return ff(app.FileCommandStatus{RequestID: d.RequestID, Status: status})
		}
		// The descriptor carries the name asked for (4.4.18, p. 75).
		info.RequestID, info.Name = d.RequestID, d.Name
		return ff(info)

	default: // AUTHENTICATE_FILE, the last function the dispatcher routes here
		c, ok := v.(app.FileAuthentication)
		if !ok {
			return &response{iin: app.IINParameterError}
		}
		var key uint32
		if fa, ok := fsrv.(FileAuthenticator); ok {
			k, valid := fa.Authenticate(ctx, c.UserName, c.Password)
			if valid {
				key = k
			}
		}
		return ff(app.FileAuthentication{AuthKey: key})
	}
}

// gvOf is the variation of an answer of file(): an authentication (g70v2),
// a file descriptor (g70v7) or a command status (g70v4).
func gvOf(v app.Value) uint8 {
	switch v.(type) {
	case app.FileAuthentication:
		return 2
	case app.FileDescriptor:
		return 7
	default:
		return 4
	}
}

// readFile answers a READ of g70v5: the master asks for one block. An
// error closes the file and makes its handle invalid (IEEE 1815-2012
// 5.3.8 Rule 13, p. 120; 4.4.17.1.3, pp. 67-68); a request repeating the
// block sent last gets it again.
func (a *association) readFile(h *app.Header, p *readPlan) {
	fail := func(t app.FileTransport, status app.FileStatus, text string) {
		p.items = append(p.items, item{h: app.FreeFormat(app.G70V6,
			app.FileTransportStatus{Handle: t.Handle, Block: t.Block, Status: status, Text: text})})
	}
	for _, o := range h.Objects {
		t, ok := o.Value.(app.FileTransport)
		if !ok {
			// An object without a file transport block, e.g. under a
			// qualifier that carries indices only.
			p.iin |= app.IINParameterError
			continue
		}
		of, ok := a.files[t.Handle]
		if !ok || of.mode != app.FileModeRead {
			fail(t, app.FileInvalidHandle, "")
			continue
		}
		of.used = time.Now()
		switch {
		case of.last != nil && t.Block == of.last.Block:
			// The master repeats a request whose answer it lost.
		case t.Block != of.next:
			_ = a.closeFile(t.Handle, true)
			fail(t, app.FileBlockSequence, "")
			continue
		default:
			buf := make([]byte, of.maxBlock)
			n, err := io.ReadFull(of.f, buf)
			last := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
			if err != nil && !last {
				_ = a.closeFile(t.Handle, true)
				fail(t, app.FileFatal, err.Error())
				continue
			}
			of.last = &app.FileTransport{Handle: t.Handle, Block: t.Block, Last: last, Data: buf[:n]}
			of.next++
		}
		p.items = append(p.items, item{h: app.FreeFormat(app.G70V5, *of.last)})
	}
}

// writeFile handles a WRITE of g70v5 blocks and returns IIN error bits;
// the transport status is the response. An error closes the file and
// makes its handle invalid (5.3.8 Rule 14, p. 120).
func (a *association) writeFile(h app.Header) app.IIN {
	if h.GV != app.G70V5 {
		return app.IINObjectUnknown
	}
	for _, o := range h.Objects {
		t, ok := o.Value.(app.FileTransport)
		if !ok {
			return app.IINParameterError
		}
		st := app.FileTransportStatus{Handle: t.Handle, Block: t.Block, Last: t.Last}
		of, ok := a.files[t.Handle]
		switch {
		case !ok || of.mode == app.FileModeRead || of.mode == app.FileModeNull:
			st.Status = app.FileInvalidHandle
		case t.Block+1 == of.next:
			// A repeated block that was already written.
			of.used = time.Now()
		case t.Block != of.next:
			st.Status = app.FileBlockSequence
		case len(t.Data) > of.maxBlock || (of.size != unknownFileSize && of.written+uint64(len(t.Data)) > uint64(of.size)):
			// A block larger than negotiated, or octets beyond the size
			// the open declared (4.4.17.2.1, pp. 68-69): of the codes of a
			// g70v6 (A.27.6.2.2, p. 680), BUFFER_OVERRUN.
			st.Status = app.FileBufferOverrun
		default:
			of.used = time.Now()
			if _, err := of.f.Write(t.Data); err != nil {
				st.Status, st.Text = app.FileFatal, err.Error()
				break
			}
			of.written += uint64(len(t.Data))
			of.next++
		}
		if ok && st.Status != app.FileSuccess && st.Status != app.FileInvalidHandle {
			_ = a.closeFile(t.Handle, true)
		}
		a.pendingFileStatus = append(a.pendingFileStatus, st)
	}
	return 0
}

// closeFiles aborts the files of a master that went away.
func (a *association) closeFiles() {
	for h := range a.files {
		_ = a.closeFile(h, true)
	}
}

// FSFileServer is a read-only [FileServer] over an fs.FS, for example
// os.DirFS. Directories are served as file descriptor lists, so that a
// master can list them.
type FSFileServer struct {
	// FS is the file system served; "/" is its root.
	FS fs.FS
}

// clean maps a DNP3 file name to an fs.FS path.
func clean(name string) (string, bool) {
	p := path.Clean("/" + strings.ReplaceAll(name, "\\", "/"))
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		p = "."
	}
	return p, fs.ValidPath(p)
}

// Open opens a file or directory for reading.
func (s FSFileServer) Open(_ context.Context, req FileRequest) (File, app.FileStatus) {
	if req.Mode != app.FileModeRead {
		return nil, app.FilePermissionDenied
	}
	p, ok := clean(req.Name)
	if !ok {
		return nil, app.FileNotFound
	}
	info, err := fs.Stat(s.FS, p)
	if err != nil {
		return nil, app.FileNotFound
	}
	if info.IsDir() {
		entries, err := fs.ReadDir(s.FS, p)
		if err != nil {
			return nil, app.FileNotFound
		}
		var b []byte
		for _, e := range entries {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if nb, err := app.AppendFileDescriptor(b, s.descriptor(e.Name(), path.Join(p, e.Name()), fi)); err == nil {
				b = nb
			}
		}
		return &memFile{data: b}, app.FileSuccess
	}
	size, ok := fileSize(info)
	if !ok {
		// The size of a file is four octets (g70v4): a file of 4 GiB or
		// more cannot be described, so it is not opened.
		return nil, app.FileFatal
	}
	f, err := s.FS.Open(p)
	if err != nil {
		return nil, app.FileNotFound
	}
	return &fsFile{f: f, size: size}, app.FileSuccess
}

// Delete refuses: the file system is read-only.
func (FSFileServer) Delete(context.Context, string, uint32) app.FileStatus {
	return app.FilePermissionDenied
}

// Info returns the descriptor of a file or directory.
func (s FSFileServer) Info(_ context.Context, name string) (app.FileDescriptor, app.FileStatus) {
	p, ok := clean(name)
	if !ok {
		return app.FileDescriptor{}, app.FileNotFound
	}
	info, err := fs.Stat(s.FS, p)
	if err != nil {
		return app.FileDescriptor{}, app.FileNotFound
	}
	return s.descriptor(name, p, info), app.FileSuccess
}

// descriptor describes a file or directory of the file system at p. The
// size of a directory is the number of its entries (IEEE 1815-2012 4.4.18,
// p. 75). The permissions are those of every master, which the server does
// not tell apart, in all three classes: read, and execute for a directory
// (5.3.2, p. 113); FSFileServer writes nothing.
func (s FSFileServer) descriptor(name, p string, info fs.FileInfo) app.FileDescriptor {
	size, _ := fileSize(info) // 0xFFFFFFFF for a file of 4 GiB or more
	d := app.FileDescriptor{Name: name, Type: app.FileTypeSimple, Size: size,
		Created: app.TimestampOf(info.ModTime()), Permissions: readPermissions}
	if info.IsDir() {
		entries, _ := fs.ReadDir(s.FS, p)
		d.Type, d.Size = app.FileTypeDirectory, count32(len(entries))
		d.Permissions |= app.PermOwnerExecute | app.PermGroupExecute | app.PermWorldExecute
	}
	return d
}

// readPermissions are the permissions of a file FSFileServer serves.
const readPermissions = app.PermOwnerRead | app.PermGroupRead | app.PermWorldRead

// maxFileBlock is the largest block of a g70v5 object (qualifier 0x5B):
// its size is two octets and includes the handle and block number.
const maxFileBlock = 0xFFFF - 8

// fileSize returns the size of a file in the four octets of g70, and
// false, with the largest size, when it does not fit them.
func fileSize(info fs.FileInfo) (uint32, bool) {
	n := info.Size()
	if n < 0 || n > math.MaxUint32 {
		return math.MaxUint32, false
	}
	return uint32(n), true
}

type fsFile struct {
	f    fs.File
	size uint32
}

func (f *fsFile) Read(p []byte) (int, error) { return f.f.Read(p) }
func (f *fsFile) Write([]byte) (int, error)  { return 0, fs.ErrPermission }
func (f *fsFile) Size() uint32               { return f.size }
func (f *fsFile) Close(bool) error           { return f.f.Close() }

type memFile struct {
	data []byte
	off  int
}

func (m *memFile) Read(p []byte) (int, error) {
	if m.off >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += n
	return n, nil
}
func (m *memFile) Write([]byte) (int, error) { return 0, fs.ErrPermission }
func (m *memFile) Size() uint32              { return count32(len(m.data)) }
func (m *memFile) Close(bool) error          { return nil }

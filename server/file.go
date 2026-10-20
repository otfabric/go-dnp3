// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"path"
	"strings"
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
	mode     app.FileMode
	maxBlock int
	next     uint32 // next block expected (write) or to send (read)
	last     *app.FileTransport
	used     time.Time
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
		maxBlock := int(c.MaxBlockSize)
		if maxBlock == 0 || maxBlock > limit {
			maxBlock = limit
		}
		a.nextHandle++
		h := a.nextHandle
		a.files[h] = &openFile{f: f, mode: c.Mode, maxBlock: maxBlock, used: time.Now()}
		st.Handle, st.MaxBlockSize = h, uint16(maxBlock)
		if c.Mode == app.FileModeRead {
			st.Size = f.Size()
		}
		return ff(st)

	case app.FuncCloseFile, app.FuncAbortFile:
		c, ok := v.(app.FileCommandStatus)
		if !ok {
			return &response{iin: app.IINParameterError}
		}
		st := app.FileCommandStatus{Handle: c.Handle, RequestID: c.RequestID}
		of, ok := a.files[c.Handle]
		if !ok {
			st.Status = app.FileInvalidHandle
			return ff(st)
		}
		delete(a.files, c.Handle)
		if err := of.f.Close(req.Function == app.FuncAbortFile); err != nil {
			st.Status = app.FileFatal
			st.Text = err.Error()
		}
		return ff(st)

	case app.FuncDeleteFile:
		c, ok := v.(app.FileCommand)
		if !ok {
			return &response{iin: app.IINParameterError}
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
		info.RequestID = d.RequestID
		if info.Name == "" {
			info.Name = d.Name
		}
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

// readFile answers a READ of g70v5: the master asks for one block.
func (a *association) readFile(h *app.Header, p *readPlan) {
	for _, o := range h.Objects {
		t := o.Value.(app.FileTransport) // the only value g70v5 decodes to
		of, ok := a.files[t.Handle]
		if !ok || of.mode != app.FileModeRead {
			p.items = append(p.items, item{h: app.FreeFormat(app.G70V6,
				app.FileTransportStatus{Handle: t.Handle, Block: t.Block, Status: app.FileInvalidHandle})})
			continue
		}
		of.used = time.Now()
		switch {
		case of.last != nil && t.Block == of.last.Block:
			// The master repeats a request whose answer it lost.
		case t.Block != of.next:
			p.items = append(p.items, item{h: app.FreeFormat(app.G70V6,
				app.FileTransportStatus{Handle: t.Handle, Block: t.Block, Status: app.FileBlockSequence})})
			continue
		default:
			buf := make([]byte, of.maxBlock)
			n, err := io.ReadFull(of.f, buf)
			last := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
			if err != nil && !last {
				p.items = append(p.items, item{h: app.FreeFormat(app.G70V6,
					app.FileTransportStatus{Handle: t.Handle, Block: t.Block, Status: app.FileFatal, Text: err.Error()})})
				continue
			}
			of.last = &app.FileTransport{Handle: t.Handle, Block: t.Block, Last: last, Data: buf[:n]}
			of.next++
		}
		p.items = append(p.items, item{h: app.FreeFormat(app.G70V5, *of.last)})
	}
}

// writeFile handles a WRITE of g70v5 blocks and returns IIN error bits;
// the transport status is the response.
func (a *association) writeFile(h app.Header) app.IIN {
	if h.GV != app.G70V5 {
		return app.IINObjectUnknown
	}
	for _, o := range h.Objects {
		t := o.Value.(app.FileTransport)
		st := app.FileTransportStatus{Handle: t.Handle, Block: t.Block, Last: t.Last}
		of, ok := a.files[t.Handle]
		switch {
		case !ok || of.mode == app.FileModeRead || of.mode == app.FileModeNull:
			st.Status = app.FileInvalidHandle
		case t.Block+1 == of.next:
			// A repeated block that was already written.
		case t.Block != of.next:
			st.Status = app.FileBlockSequence
		case len(t.Data) > of.maxBlock:
			st.Status = app.FileWriteBlockSize
		default:
			of.used = time.Now()
			if _, err := of.f.Write(t.Data); err != nil {
				st.Status, st.Text = app.FileFatal, err.Error()
				break
			}
			of.next++
		}
		a.pendingFileStatus = append(a.pendingFileStatus, st)
	}
	return 0
}

// closeFiles aborts the files of a master that went away.
func (a *association) closeFiles() {
	for h, of := range a.files {
		_ = of.f.Close(true)
		delete(a.files, h)
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
			if nb, err := app.AppendFileDescriptor(b, descriptor(e.Name(), fi)); err == nil {
				b = nb
			}
		}
		return &memFile{data: b}, app.FileSuccess
	}
	f, err := s.FS.Open(p)
	if err != nil {
		return nil, app.FileNotFound
	}
	return &fsFile{f: f, size: uint32(info.Size())}, app.FileSuccess
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
	return descriptor(name, info), app.FileSuccess
}

func descriptor(name string, info fs.FileInfo) app.FileDescriptor {
	d := app.FileDescriptor{Name: name, Type: app.FileTypeSimple, Size: uint32(info.Size()),
		Created: app.TimestampOf(info.ModTime()), Permissions: app.Permissions(info.Mode().Perm())}
	if info.IsDir() {
		d.Type, d.Size = app.FileTypeDirectory, 0
	}
	return d
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
func (m *memFile) Size() uint32              { return uint32(len(m.data)) }
func (m *memFile) Close(bool) error          { return nil }

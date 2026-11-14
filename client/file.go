// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/secauth"
)

// FileOptions are the optional parameters of a file transfer.
type FileOptions struct {
	// MaxBlockSize is the largest block the client asks for or sends.
	// The outstation may lower it. Zero lets the outstation choose.
	MaxBlockSize uint16
	// AuthKey is the key returned by AuthenticateFile, or 0.
	AuthKey uint32
	// Permissions of a file created by WriteFile.
	Permissions app.Permissions
	// Append makes WriteFile add to the end of the file (mode APPEND)
	// instead of replacing it.
	Append bool
	// Created is the time of creation WriteFile gives the file; zero
	// means the time of the request (IEEE 1815-2012 clause 4.4.17.2.1).
	Created time.Time
}

const fileRequestID = 1

// maxFileBlock is the largest block of a g70v5 object (qualifier 0x5B).
const maxFileBlock = 0xFFFF - 8

// unknownFileSize is the file size of a write whose size is not known
// (IEEE 1815-2012 clause 4.4.17.2.1).
const unknownFileSize = 0xFFFFFFFF

// writeOverhead is what a WRITE of one g70v5 object adds to its block: the
// application header (2), the object header with qualifier 0x5B and a
// one-octet count (4), the object size (2), the handle and the block
// number (8).
const writeOverhead = 2 + 4 + 2 + 8

// maxWriteBlock returns the largest file block a WRITE request may carry
// under WithMaxRequestFragment, 0 without a limit. With aggressive mode
// writes the objects of secure authentication take their room as well.
func (c *Client) maxWriteBlock() int {
	lim := c.opts.maxTxFragment
	if lim == 0 {
		return 0
	}
	b := lim - writeOverhead
	if c.opts.auth != nil && slices.Contains(c.opts.aggressive, app.FuncWrite) {
		b -= secauth.AggressiveOverhead
	}
	return max(b, 1)
}

// fileObject returns the single object of the response of a file
// operation, of the expected type or a command status.
func fileObject(res *Result) (app.Value, error) {
	for _, h := range res.Headers() {
		if h.GV.Group() == 70 && len(h.Objects) == 1 {
			return h.Objects[0].Value, nil
		}
	}
	return nil, fmt.Errorf("%w: file operation answered without a file object", dnp3.ErrProtocol)
}

func statusError(op string, v app.Value) error {
	switch s := v.(type) {
	case app.FileCommandStatus:
		if s.Status != app.FileSuccess {
			return &dnp3.FileError{Op: op, Status: s.Status, Text: s.Text}
		}
	case app.FileTransportStatus:
		if s.Status != app.FileSuccess {
			return &dnp3.FileError{Op: op, Status: s.Status, Text: s.Text}
		}
	}
	return nil
}

// openFile sends OPEN_FILE and returns the outstation's answer. For a
// write it sets the time of creation, and the size and time are zero for a
// read (IEEE 1815-2012 clause 4.4.17.2.1).
func (c *Client) openFile(ctx context.Context, name string, mode app.FileMode, size uint32, o FileOptions) (app.FileCommandStatus, error) {
	cmd := app.FileCommand{Name: name, Mode: mode, Size: size, MaxBlockSize: o.MaxBlockSize, AuthKey: o.AuthKey,
		Permissions: o.Permissions, RequestID: fileRequestID}
	if mode != app.FileModeRead {
		created := o.Created
		if created.IsZero() {
			created = time.Now()
		}
		cmd.Created = app.TimestampOf(created)
		if b := c.maxWriteBlock(); b > 0 && (cmd.MaxBlockSize == 0 || int(cmd.MaxBlockSize) > b) {
			// The block size of a write is the most the master sends in
			// one request (clause 4.4.17.2.1).
			cmd.MaxBlockSize = uint16(min(b, maxFileBlock))
		}
	}
	res, err := c.request(ctx, app.FuncOpenFile, false, app.FreeFormat(app.G70V3, cmd))
	if err != nil {
		return app.FileCommandStatus{}, err
	}
	v, err := fileObject(res)
	if err != nil {
		return app.FileCommandStatus{}, err
	}
	st, ok := v.(app.FileCommandStatus)
	if !ok {
		return st, fmt.Errorf("%w: OPEN_FILE answered with %T", dnp3.ErrProtocol, v)
	}
	return st, statusError("open", st)
}

func (c *Client) closeFile(ctx context.Context, handle uint32, abort bool) error {
	fc, op := app.FuncCloseFile, "close"
	if abort {
		fc, op = app.FuncAbortFile, "abort"
	}
	res, err := c.request(ctx, fc, false, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: handle, RequestID: fileRequestID}))
	if err != nil {
		return err
	}
	v, err := fileObject(res)
	if err != nil {
		return err
	}
	return statusError(op, v)
}

// ReadFile reads the file name from the outstation into w and returns the
// number of octets read.
func (c *Client) ReadFile(ctx context.Context, name string, w io.Writer, o FileOptions) (int64, error) {
	st, err := c.openFile(ctx, name, app.FileModeRead, 0, o)
	if err != nil {
		return 0, err
	}
	var n int64
	for block := uint32(0); ; block++ {
		res, err := c.request(ctx, app.FuncRead, true, app.FreeFormat(app.G70V5, app.FileTransport{Handle: st.Handle, Block: block}))
		if err == nil {
			var v app.Value
			if v, err = fileObject(res); err == nil {
				switch t := v.(type) {
				case app.FileTransport:
					if t.Block != block {
						err = fmt.Errorf("%w: file block %d, asked for %d", dnp3.ErrProtocol, t.Block, block)
						break
					}
					// The writer is the application's: one that does not
					// return normally fails the transfer, which is aborted.
					m, werr := logx.Call(c.log, "io.Writer of ReadFile", func() (int, error) { return w.Write(t.Data) })
					n += int64(m)
					if werr != nil {
						err = werr
						break
					}
					if t.Last {
						return n, c.closeFile(ctx, st.Handle, false)
					}
					continue
				default:
					err = statusError("read", v)
					if err == nil {
						err = fmt.Errorf("%w: file read answered with %T", dnp3.ErrProtocol, v)
					}
				}
			}
		}
		c.abortQuietly(st.Handle)
		return n, err
	}
}

// abortQuietly aborts a transfer that failed, on a fresh context: the
// caller's may be the reason it failed.
func (c *Client) abortQuietly(handle uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.responseTimeout)
	defer cancel()
	if err := c.closeFile(ctx, handle, true); err != nil {
		c.log.Debug("abort of failed file transfer failed", "error", err)
	}
}

// WriteFile writes size octets from r to the file name on the outstation,
// or appends them with FileOptions.Append, and returns the number of
// octets written. It sends no more than size octets of r, unless size is
// 0xFFFFFFFF, an unknown size (IEEE 1815-2012 clause 4.4.17.2.1); a
// shorter r ends the file early. With WithMaxRequestFragment the blocks
// are no larger than fits a request.
func (c *Client) WriteFile(ctx context.Context, name string, r io.Reader, size uint32, o FileOptions) (int64, error) {
	mode := app.FileModeWrite
	if o.Append {
		mode = app.FileModeAppend
	}
	if size != unknownFileSize {
		r = io.LimitReader(r, int64(size))
	}
	st, err := c.openFile(ctx, name, mode, size, o)
	if err != nil {
		return 0, err
	}
	block := int(st.MaxBlockSize)
	if block == 0 {
		block = 1024
	}
	// A block travels in a g70v5 object, whose two-octet size also counts
	// the handle and block number: an outstation announcing more than
	// 65527 gets blocks that fit the object.
	block = min(block, maxFileBlock)
	if c.opts.auth != nil && slices.Contains(c.opts.aggressive, app.FuncWrite) && block > 2*secauth.AggressiveOverhead {
		// An outstation that sized the block for a plain request has no
		// room for the aggressive mode objects.
		block -= secauth.AggressiveOverhead
	}
	if b := c.maxWriteBlock(); b > 0 {
		block = min(block, b)
	}
	buf := make([]byte, block)
	var n int64
	for b := uint32(0); ; b++ {
		// The reader is the application's: one that does not return
		// normally fails the transfer, which is aborted.
		m, rerr := logx.Call(c.log, "io.Reader of WriteFile", func() (int, error) { return io.ReadFull(r, buf) })
		last := errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF)
		if rerr != nil && !last {
			c.abortQuietly(st.Handle)
			return n, rerr
		}
		if !last && n+int64(m) == int64(size) {
			last = true
		}
		res, err := c.request(ctx, app.FuncWrite, false, app.FreeFormat(app.G70V5,
			app.FileTransport{Handle: st.Handle, Block: b, Last: last, Data: buf[:m]}))
		if err == nil {
			var v app.Value
			if v, err = fileObject(res); err == nil {
				err = statusError("write", v)
				if _, ok := v.(app.FileTransportStatus); !ok && err == nil {
					err = fmt.Errorf("%w: file write answered with %T", dnp3.ErrProtocol, v)
				}
			}
		}
		if err != nil {
			c.abortQuietly(st.Handle)
			return n, err
		}
		n += int64(m)
		if last {
			return n, c.closeFile(ctx, st.Handle, false)
		}
	}
}

// maxDirectory bounds the listing ListDirectory collects, in octets: room
// for some 500 000 entries (g70v7 descriptors of 20 octets and a name), far
// beyond a directory an outstation serves over DNP3. A listing that goes on
// beyond it is refused instead of held.
const maxDirectory = 16 << 20

// errDirectoryTooLong is what the listing's buffer returns past maxDirectory.
var errDirectoryTooLong = errors.New("directory listing too long")

// listing is the buffer of ListDirectory: it takes at most max octets.
type listing struct {
	bytes.Buffer
	max int
}

func (l *listing) Write(p []byte) (int, error) {
	if len(p) > l.max-l.Len() {
		return 0, errDirectoryTooLong
	}
	return l.Buffer.Write(p)
}

// ListDirectory reads the directory name and returns its entries. A
// listing longer than 16 MiB is refused with dnp3.ErrProtocol, and the
// transfer aborted.
func (c *Client) ListDirectory(ctx context.Context, name string, o FileOptions) ([]app.FileDescriptor, error) {
	buf := listing{max: maxDirectory}
	if _, err := c.ReadFile(ctx, name, &buf, o); err != nil {
		if errors.Is(err, errDirectoryTooLong) {
			return nil, fmt.Errorf("%w: directory %q: listing longer than %d octets", dnp3.ErrProtocol, name, maxDirectory)
		}
		return nil, err
	}
	ds, err := app.DecodeFileDescriptors(buf.Bytes())
	if err != nil {
		return ds, fmt.Errorf("%w: directory %q: %w", dnp3.ErrProtocol, name, err)
	}
	return ds, nil
}

// FileInfo returns the descriptor of a file or directory.
func (c *Client) FileInfo(ctx context.Context, name string) (app.FileDescriptor, error) {
	res, err := c.request(ctx, app.FuncGetFileInfo, true, app.FreeFormat(app.G70V7, app.FileDescriptor{Name: name, RequestID: fileRequestID}))
	if err != nil {
		return app.FileDescriptor{}, err
	}
	v, err := fileObject(res)
	if err != nil {
		return app.FileDescriptor{}, err
	}
	if d, ok := v.(app.FileDescriptor); ok {
		return d, nil
	}
	if err := statusError("info", v); err != nil {
		return app.FileDescriptor{}, err
	}
	return app.FileDescriptor{}, fmt.Errorf("%w: GET_FILE_INFO answered with %T", dnp3.ErrProtocol, v)
}

// DeleteFile deletes the file name.
func (c *Client) DeleteFile(ctx context.Context, name string, o FileOptions) error {
	res, err := c.request(ctx, app.FuncDeleteFile, false, app.FreeFormat(app.G70V3,
		app.FileCommand{Name: name, Mode: app.FileModeNull, AuthKey: o.AuthKey, RequestID: fileRequestID}))
	if err != nil {
		return err
	}
	v, err := fileObject(res)
	if err != nil {
		return err
	}
	return statusError("delete", v)
}

// AuthenticateFile sends credentials and returns the key to use with the
// following file operations. An outstation that refuses them returns the
// key 0.
func (c *Client) AuthenticateFile(ctx context.Context, user, password string) (uint32, error) {
	res, err := c.request(ctx, app.FuncAuthenticateFile, false, app.FreeFormat(app.G70V2,
		app.FileAuthentication{UserName: user, Password: password}))
	if err != nil {
		return 0, err
	}
	v, err := fileObject(res)
	if err != nil {
		return 0, err
	}
	a, ok := v.(app.FileAuthentication)
	if !ok {
		return 0, fmt.Errorf("%w: AUTHENTICATE_FILE answered with %T", dnp3.ErrProtocol, v)
	}
	if a.AuthKey == 0 {
		return 0, &dnp3.FileError{Op: "authenticate", Status: app.FilePermissionDenied}
	}
	return a.AuthKey, nil
}

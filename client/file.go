// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
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
}

const fileRequestID = 1

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

// openFile sends OPEN_FILE and returns the outstation's answer.
func (c *Client) openFile(ctx context.Context, name string, mode app.FileMode, size uint32, o FileOptions) (app.FileCommandStatus, error) {
	cmd := app.FileCommand{Name: name, Mode: mode, Size: size, MaxBlockSize: o.MaxBlockSize, AuthKey: o.AuthKey,
		Permissions: o.Permissions, RequestID: fileRequestID}
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
					m, werr := w.Write(t.Data)
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

// WriteFile writes size octets from r to the file name on the outstation
// and returns the number of octets written.
func (c *Client) WriteFile(ctx context.Context, name string, r io.Reader, size uint32, o FileOptions) (int64, error) {
	st, err := c.openFile(ctx, name, app.FileModeWrite, size, o)
	if err != nil {
		return 0, err
	}
	block := int(st.MaxBlockSize)
	if block == 0 {
		block = 1024
	}
	if c.opts.auth != nil && slices.Contains(c.opts.aggressive, app.FuncWrite) && block > 2*secauth.AggressiveOverhead {
		// An outstation that sized the block for a plain request has no
		// room for the aggressive mode objects.
		block -= secauth.AggressiveOverhead
	}
	buf := make([]byte, block)
	var n int64
	for b := uint32(0); ; b++ {
		m, rerr := io.ReadFull(r, buf)
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

// ListDirectory reads the directory name and returns its entries.
func (c *Client) ListDirectory(ctx context.Context, name string, o FileOptions) ([]app.FileDescriptor, error) {
	var buf bytes.Buffer
	if _, err := c.ReadFile(ctx, name, &buf, o); err != nil {
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

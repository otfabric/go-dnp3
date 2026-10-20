// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"errors"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// ff is the free-format header of a file object.
func ff(v app.Value) app.Header {
	var variation uint8
	switch v.(type) {
	case app.FileAuthentication:
		variation = 2
	case app.FileCommandStatus:
		variation = 4
	case app.FileTransport:
		variation = 5
	case app.FileTransportStatus:
		variation = 6
	default:
		variation = 7
	}
	return app.FreeFormat(app.GV(70, variation), v)
}

// opened is the answer to OPEN_FILE of an outstation that opened handle 1.
func opened(maxBlock uint16) []app.Header {
	return []app.Header{ff(app.FileCommandStatus{Handle: 1, MaxBlockSize: maxBlock, RequestID: fileRequestID})}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

// TestFileAnswersOutOfProtocol: a file operation answered with the wrong
// object, a wrong block or no object at all fails with ErrProtocol, a
// failure status with a FileError, and a transfer that fails is aborted.
func TestFileAnswersOutOfProtocol(t *testing.T) {
	ctx := testCtx(t)
	var fe *dnp3.FileError
	// read answers OPEN_FILE and ABORT_FILE, and READ with block.
	read := func(block []app.Header) *Client {
		return dialScripted(t, func(r *app.Fragment) (app.IIN, []app.Header) {
			switch r.Function {
			case app.FuncOpenFile:
				return 0, opened(4)
			case app.FuncRead:
				return 0, block
			default:
				return 0, []app.Header{ff(app.FileCommandStatus{Handle: 1})}
			}
		})
	}
	for _, c := range []struct {
		name  string
		block []app.Header
		check func(error) bool
	}{
		{"wrong block", []app.Header{ff(app.FileTransport{Handle: 1, Block: 5, Last: true})}, func(err error) bool { return errors.Is(err, dnp3.ErrProtocol) }},
		{"failure status", []app.Header{ff(app.FileCommandStatus{Handle: 1, Status: app.FileFatal})}, func(err error) bool { return errors.As(err, &fe) }},
		{"descriptor", []app.Header{ff(app.FileDescriptor{Name: "x"})}, func(err error) bool { return errors.Is(err, dnp3.ErrProtocol) }},
		{"no object", nil, func(err error) bool { return errors.Is(err, dnp3.ErrProtocol) }},
	} {
		var buf bytes.Buffer
		if _, err := read(c.block).ReadFile(ctx, "/f", &buf, FileOptions{}); !c.check(err) {
			t.Errorf("read, %s: %v", c.name, err)
		}
	}
	// A writer that fails ends the read.
	c := read([]app.Header{ff(app.FileTransport{Handle: 1, Data: []byte("ab")})})
	if _, err := c.ReadFile(ctx, "/f", failingWriter{}, FileOptions{}); err == nil || err.Error() != "pipe closed" {
		t.Fatalf("failing writer: %v", err)
	}

	// OPEN_FILE answered with nothing, or with a transport status.
	for name, hs := range map[string][]app.Header{
		"nothing":          nil,
		"transport status": {ff(app.FileTransportStatus{Handle: 1})},
	} {
		c := dialScripted(t, func(*app.Fragment) (app.IIN, []app.Header) { return 0, hs })
		if _, err := c.ReadFile(ctx, "/f", &bytes.Buffer{}, FileOptions{}); !errors.Is(err, dnp3.ErrProtocol) {
			t.Errorf("open answered with %s, read: %v", name, err)
		}
		if _, err := c.WriteFile(ctx, "/f", bytes.NewReader([]byte("x")), 1, FileOptions{}); !errors.Is(err, dnp3.ErrProtocol) {
			t.Errorf("open answered with %s, write: %v", name, err)
		}
		if _, err := c.ListDirectory(ctx, "/", FileOptions{}); !errors.Is(err, dnp3.ErrProtocol) {
			t.Errorf("open answered with %s, list: %v", name, err)
		}
	}

	// CLOSE_FILE answered with nothing after the last block.
	c = dialScripted(t, func(r *app.Fragment) (app.IIN, []app.Header) {
		switch r.Function {
		case app.FuncOpenFile:
			return 0, opened(4)
		case app.FuncRead:
			return 0, []app.Header{ff(app.FileTransport{Handle: 1, Last: true, Data: []byte("ab")})}
		default:
			return 0, nil
		}
	})
	if _, err := c.ReadFile(ctx, "/f", &bytes.Buffer{}, FileOptions{}); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("close answered with nothing: %v", err)
	}
}

// TestFileWriteAnswers: the block size an outstation leaves open, a write
// that ends when the size is reached, and a write answered with the wrong
// object.
func TestFileWriteAnswers(t *testing.T) {
	ctx := testCtx(t)
	var blocks [][]byte
	writeAnswer := ff(app.FileTransportStatus{Handle: 1})
	c := dialScripted(t, func(r *app.Fragment) (app.IIN, []app.Header) {
		switch r.Function {
		case app.FuncOpenFile:
			return 0, opened(0)
		case app.FuncWrite:
			blocks = append(blocks, r.Headers[0].Objects[0].Value.(app.FileTransport).Data)
			return 0, []app.Header{writeAnswer}
		default:
			return 0, []app.Header{ff(app.FileCommandStatus{Handle: 1})}
		}
	})
	// No block size from the outstation: blocks of 1024 octets. The
	// reader has more than size; the write stops at size.
	if n, err := c.WriteFile(ctx, "/f", bytes.NewReader(make([]byte, 3000)), 2048, FileOptions{}); err != nil || n != 2048 ||
		len(blocks) != 2 || len(blocks[0]) != 1024 {
		t.Fatalf("write: %d %v, %d blocks", n, err, len(blocks))
	}
	writeAnswer = ff(app.FileCommandStatus{Handle: 1})
	if _, err := c.WriteFile(ctx, "/f", bytes.NewReader([]byte("x")), 1, FileOptions{}); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("write answered with a command status: %v", err)
	}
}

// TestFileCommandAnswers: GET_FILE_INFO, DELETE_FILE and AUTHENTICATE_FILE
// answered with an error, with nothing or with the wrong object.
func TestFileCommandAnswers(t *testing.T) {
	ctx := testCtx(t)
	var iin app.IIN
	var hs []app.Header
	c := dialScripted(t, func(*app.Fragment) (app.IIN, []app.Header) { return iin, hs })
	check := func(name string, want func(error) bool) {
		t.Helper()
		if _, err := c.FileInfo(ctx, "/f"); !want(err) {
			t.Errorf("info, %s: %v", name, err)
		}
		if err := c.DeleteFile(ctx, "/f", FileOptions{}); name != "wrong object" && !want(err) {
			t.Errorf("delete, %s: %v", name, err)
		}
		if _, err := c.AuthenticateFile(ctx, "u", "p"); !want(err) {
			t.Errorf("authenticate, %s: %v", name, err)
		}
	}
	var ie *dnp3.IINError
	iin = app.IINNoFuncCodeSupport
	check("not supported", func(err error) bool { return errors.As(err, &ie) })
	iin = 0
	check("nothing", func(err error) bool { return errors.Is(err, dnp3.ErrProtocol) })
	hs = []app.Header{ff(app.FileTransportStatus{Handle: 1})}
	check("wrong object", func(err error) bool { return errors.Is(err, dnp3.ErrProtocol) })
}

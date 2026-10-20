// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// files is a writable in-memory server.FileServer with credentials.
type files struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *files) Open(_ context.Context, req server.FileRequest) (server.File, app.FileStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch req.Mode {
	case app.FileModeRead:
		if req.Name == "/" {
			names := make([]string, 0, len(s.m))
			for n := range s.m {
				names = append(names, n)
			}
			sort.Strings(names)
			var b []byte
			for _, n := range names {
				b, _ = app.AppendFileDescriptor(b, app.FileDescriptor{Name: n, Type: app.FileTypeSimple, Size: uint32(len(s.m[n]))})
			}
			return &file{r: bytes.NewReader(b), size: len(b)}, app.FileSuccess
		}
		if req.Name == "/garbage-dir" {
			return &file{r: bytes.NewReader([]byte{1, 2, 3}), size: 3}, app.FileSuccess
		}
		data, ok := s.m[req.Name]
		if !ok {
			return nil, app.FileNotFound
		}
		return &file{r: bytes.NewReader(data), size: len(data)}, app.FileSuccess
	case app.FileModeWrite, app.FileModeAppend:
		if req.AuthKey != 0 && req.AuthKey != 42 {
			return nil, app.FilePermissionDenied
		}
		f := &file{s: s, name: req.Name}
		if req.Mode == app.FileModeAppend {
			f.w.Write(s.m[req.Name])
		}
		return f, app.FileSuccess
	default:
		return nil, app.FileInvalidMode
	}
}

func (s *files) Delete(_ context.Context, name string, _ uint32) app.FileStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; !ok {
		return app.FileNotFound
	}
	delete(s.m, name)
	return app.FileSuccess
}

func (s *files) Info(_ context.Context, name string) (app.FileDescriptor, app.FileStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.m[name]
	if !ok {
		return app.FileDescriptor{}, app.FileNotFound
	}
	return app.FileDescriptor{Name: name, Type: app.FileTypeSimple, Size: uint32(len(data))}, app.FileSuccess
}

func (s *files) Authenticate(_ context.Context, user, password string) (uint32, bool) {
	return 42, user == "operator" && password == "secret"
}

func (s *files) get(name string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[name]
}

type file struct {
	r    io.Reader
	size int
	s    *files
	name string
	w    bytes.Buffer
}

func (f *file) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *file) Write(p []byte) (int, error) { return f.w.Write(p) }
func (f *file) Size() uint32                { return uint32(f.size) }
func (f *file) Close(abort bool) error {
	if f.s != nil && !abort {
		f.s.mu.Lock()
		f.s.m[f.name] = bytes.Clone(f.w.Bytes())
		f.s.mu.Unlock()
	}
	return nil
}

func TestFileTransfer(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 400)
	fs := &files{m: map[string][]byte{"/big.bin": big}}
	_, addr := outstation(t, server.WithFileServer(fs))
	c, err := Dial(testCtx(t), addr, WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx := testCtx(t)

	var buf bytes.Buffer
	if n, err := c.ReadFile(ctx, "/big.bin", &buf, FileOptions{MaxBlockSize: 700}); err != nil || n != int64(len(big)) || !bytes.Equal(buf.Bytes(), big) {
		t.Fatalf("read: %d %v", n, err)
	}
	var fe *dnp3.FileError
	if _, err := c.ReadFile(ctx, "/missing", &buf, FileOptions{}); !errors.As(err, &fe) || fe.Status != app.FileNotFound {
		t.Fatalf("missing: %v", err)
	}
	key, err := c.AuthenticateFile(ctx, "operator", "secret")
	if err != nil || key != 42 {
		t.Fatalf("authenticate: %d %v", key, err)
	}
	if _, err := c.AuthenticateFile(ctx, "operator", "wrong"); !errors.As(err, &fe) {
		t.Fatalf("wrong password: %v", err)
	}
	payload := bytes.Repeat([]byte("payload "), 300)
	if n, err := c.WriteFile(ctx, "/up.bin", bytes.NewReader(payload), uint32(len(payload)), FileOptions{AuthKey: key, MaxBlockSize: 256}); err != nil || n != int64(len(payload)) || !bytes.Equal(fs.get("/up.bin"), payload) {
		t.Fatalf("write: %d %v", n, err)
	}
	tail := []byte(" and more")
	if _, err := c.WriteFile(ctx, "/up.bin", bytes.NewReader(tail), uint32(len(tail)), FileOptions{AuthKey: key, Append: true}); err != nil ||
		!bytes.Equal(fs.get("/up.bin"), append(append([]byte(nil), payload...), tail...)) {
		t.Fatalf("append: %v, %d octets", err, len(fs.get("/up.bin")))
	}
	_ = fs.Delete(ctx, "/up.bin", 0)
	if _, err := c.WriteFile(ctx, "/up.bin", bytes.NewReader(payload), uint32(len(payload)), FileOptions{AuthKey: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteFile(ctx, "/x", bytes.NewReader([]byte{1}), 1, FileOptions{AuthKey: 7}); !errors.As(err, &fe) || fe.Status != app.FilePermissionDenied {
		t.Fatalf("write with a wrong key: %v", err)
	}
	// A reader that fails aborts the transfer.
	if _, err := c.WriteFile(ctx, "/broken", io.MultiReader(bytes.NewReader(make([]byte, 300)), failing{}), 600, FileOptions{MaxBlockSize: 256}); err == nil {
		t.Fatal("write from a failing reader succeeded")
	}
	if info, err := c.FileInfo(ctx, "/up.bin"); err != nil || info.Size != uint32(len(payload)) {
		t.Fatalf("info: %+v %v", info, err)
	}
	if _, err := c.FileInfo(ctx, "/missing"); !errors.As(err, &fe) {
		t.Fatalf("info of a missing file: %v", err)
	}
	if entries, err := c.ListDirectory(ctx, "/", FileOptions{}); err != nil || len(entries) != 2 {
		t.Fatalf("list: %+v %v", entries, err)
	}
	if _, err := c.ListDirectory(ctx, "/garbage-dir", FileOptions{}); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("directory that does not decode: %v", err)
	}
	if err := c.DeleteFile(ctx, "/up.bin", FileOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteFile(ctx, "/up.bin", FileOptions{}); !errors.As(err, &fe) {
		t.Fatalf("delete twice: %v", err)
	}
	// Without a file server the outstation does not support them.
	_, plain := outstation(t)
	p, err := Dial(testCtx(t), plain, WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	var ie *dnp3.IINError
	if _, err := p.FileInfo(ctx, "/x"); !errors.As(err, &ie) {
		t.Fatalf("no file server: %v", err)
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

// TestFileWriteAggressiveMode: blocks of the largest size the outstation
// allows still fit a request once aggressive mode adds its objects.
func TestFileWriteAggressiveMode(t *testing.T) {
	key := []byte("pre-shared session key 32 octets")
	fs := &files{m: map[string][]byte{}}
	accept := server.HandlerFunc(func(context.Context, server.Command, server.OperateType) app.CommandStatus { return app.StatusSuccess })
	_, addr := outstation(t, server.WithFileServer(fs), server.WithHandler(accept),
		server.WithSecureAuthentication(server.SecureAuth{User: secauth.User{Number: 1, Key: key}}))
	c, err := Dial(testCtx(t), addr, WithAutoIntegrity(false), WithAutoClearRestart(false),
		WithSecureAuthentication(secauth.User{Number: 1, Key: key}), WithAggressiveMode())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// A first challenge, so that aggressive mode is in use for the write.
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0xA5}, 6000)
	if _, err := c.WriteFile(testCtx(t), "/big.bin", bytes.NewReader(data), uint32(len(data)), FileOptions{}); err != nil {
		t.Fatalf("write of full-size blocks in aggressive mode: %v", err)
	}
	if !bytes.Equal(fs.get("/big.bin"), data) {
		t.Fatal("file content differs")
	}
}

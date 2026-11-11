// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"io/fs"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// bigFS holds one file, "big", of 4 GiB, which it never reads.
type bigFS struct{}

type bigInfo struct{}

func (bigInfo) Name() string       { return "big" }
func (bigInfo) Size() int64        { return 1 << 32 }
func (bigInfo) Mode() fs.FileMode  { return 0o644 }
func (bigInfo) ModTime() time.Time { return time.Unix(1_700_000_000, 0) }
func (bigInfo) IsDir() bool        { return false }
func (bigInfo) Sys() any           { return nil }

type bigFile struct{}

func (bigFile) Stat() (fs.FileInfo, error) { return bigInfo{}, nil }
func (bigFile) Read([]byte) (int, error)   { return 0, fs.ErrInvalid }
func (bigFile) Close() error               { return nil }

func (bigFS) Open(name string) (fs.File, error) {
	if name != "big" {
		return nil, fs.ErrNotExist
	}
	return bigFile{}, nil
}

// TestFSFileServerLargeFile: a file whose size does not fit the four
// octets of g70v4 is not opened, rather than opened with its size modulo
// 2^32, and its descriptor gives the largest size.
func TestFSFileServerLargeFile(t *testing.T) {
	s := FSFileServer{FS: bigFS{}}
	if f, st := s.Open(context.Background(), FileRequest{Name: "/big", Mode: app.FileModeRead}); st != app.FileFatal || f != nil {
		t.Fatalf("open of a 4 GiB file: %v %v, want FILE_FATAL", f, st)
	}
	d, st := s.Info(context.Background(), "/big")
	if st != app.FileSuccess || d.Size != math.MaxUint32 {
		t.Fatalf("info of a 4 GiB file: %+v %v, want size 0xFFFFFFFF", d, st)
	}
	// The permissions of every master: read in all three classes (IEEE
	// 1815-2012 5.3.2), whatever the mode bits.
	if d.Permissions != readPermissions {
		t.Fatalf("permissions %v", d.Permissions)
	}
}

// TestCoversRangeAtTop: a static range ending at index 0xFFFFFFFF is
// walked to its end and no further.
func TestCoversRangeAtTop(t *testing.T) {
	srv, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	db := srv.Database()
	for _, i := range []uint32{math.MaxUint32 - 1, math.MaxUint32} {
		if err := db.AddBinaryInput(i, PointConfig{}, app.Binary{Flags: app.FlagOnline}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan bool, 3)
	go func() {
		done <- db.covers(BinaryInput, selector{start: math.MaxUint32 - 1, stop: math.MaxUint32})
		done <- db.covers(BinaryInput, selector{start: math.MaxUint32, stop: math.MaxUint32})
		done <- !db.covers(BinaryInput, selector{start: 0, stop: math.MaxUint32})
	}()
	for range 3 {
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("wrong coverage of a range at the top of the index space")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("covers did not end")
		}
	}
}

// TestWriteAttributeSetOutOfRange: a WRITE of an attribute of a set over
// 65535 is refused, even when the set modulo 2^16 exists.
func TestWriteAttributeSetOutOfRange(t *testing.T) {
	m := newMaster(t, WithAttributeSet(0, map[uint8]app.Attribute{250: app.StringAttribute("x")}, 250))
	h := app.Header{GV: app.GV(0, 250), Qualifier: app.Qual4ByteStartStop, Start: 0x10000, Stop: 0x10000,
		Objects: []app.Object{{Index: 0x10000, Value: app.StringAttribute("y")}}}
	m.send(req(1, app.FuncWrite, h))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) {
		t.Fatalf("WRITE of set 0x10000: %v, want PARAMETER_ERROR", f)
	}
}

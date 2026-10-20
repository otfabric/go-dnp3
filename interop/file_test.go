//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
)

// File transfer (group 70) against the files fixture, both directions.

const filesFixture = "/fixtures/files/fixture.json"

// fixtureFiles returns the files fixture's files by name.
func fixtureFiles(f *fixture) map[string][]byte {
	out := map[string][]byte{}
	for _, ff := range f.Files {
		out[ff.Name] = ff.data()
	}
	return out
}

func fileStatus(err error) app.FileStatus {
	var fe *dnp3.FileError
	if errors.As(err, &fe) {
		return fe.Status
	}
	return 255
}

func TestClientFiles(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "fileServer")
			f := a.fixtureNamed(t, "files")
			want := fixtureFiles(f)
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", filesFixture}})
			c := dialRef(t, s)
			ctx := tctx(t)

			for _, name := range []string{"/readme.txt", "/data/blocks.bin"} {
				var buf bytes.Buffer
				if _, err := c.ReadFile(ctx, name, &buf, client.FileOptions{}); err != nil {
					t.Fatalf("read %s: %v", name, err)
				}
				if !bytes.Equal(buf.Bytes(), want[name]) {
					t.Errorf("%s: %d octets, the fixture has %d", name, buf.Len(), len(want[name]))
				}
			}
			d, err := c.FileInfo(ctx, "/readme.txt")
			if err != nil {
				t.Fatalf("info: %v", err)
			}
			if d.Type != app.FileTypeSimple || int(d.Size) != len(want["/readme.txt"]) {
				t.Errorf("info of /readme.txt: %+v", d)
			}
			entries, err := c.ListDirectory(ctx, "/", client.FileOptions{})
			if err != nil {
				t.Fatalf("list /: %v", err)
			}
			names := map[string]app.FileType{}
			for _, e := range entries {
				names[strings.TrimPrefix(e.Name, "/")] = e.Type
			}
			if names["readme.txt"] != app.FileTypeSimple {
				t.Errorf("listing of / without readme.txt: %v", entries)
			}
			if typ, ok := names["data"]; !ok || typ != app.FileTypeDirectory {
				t.Errorf("listing of / without the directory data: %v", entries)
			}

			// Write a file of several blocks, read it back, delete it.
			content := bytes.Repeat([]byte("go-dnp3 "), 300)
			if _, err := c.WriteFile(ctx, "/logs/go-dnp3.txt", bytes.NewReader(content), uint32(len(content)), client.FileOptions{}); err != nil {
				t.Fatalf("write: %v", err)
			}
			var back bytes.Buffer
			if _, err := c.ReadFile(ctx, "/logs/go-dnp3.txt", &back, client.FileOptions{}); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if !bytes.Equal(back.Bytes(), content) {
				t.Errorf("read back %d octets, wrote %d", back.Len(), len(content))
			}
			if err := c.DeleteFile(ctx, "/logs/go-dnp3.txt", client.FileOptions{}); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if _, err := c.ReadFile(ctx, "/logs/go-dnp3.txt", &back, client.FileOptions{}); fileStatus(err) != app.FileNotFound {
				t.Errorf("read of a deleted file: %v", err)
			}
			if _, err := c.ReadFile(ctx, "/missing.txt", &back, client.FileOptions{}); fileStatus(err) != app.FileNotFound {
				t.Errorf("read of a missing file: %v", err)
			}
			// The outstation reports what it answered.
			s.waitEvent(t, "file write", func(e event) bool {
				return e["event"] == "file" && e["action"] == "write" && e["name"] == "/logs/go-dnp3.txt" && e["status"] == "SUCCESS"
			})
		})
	}
}

func TestServerFiles(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "fileClient")
			f := a.fixtureNamed(t, "files")
			want := fixtureFiles(f)
			st, err := newStation(f)
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = st.srv.Serve(l) }()
			t.Cleanup(func() { _ = st.srv.Close() })
			port := l.Addr().(*net.TCPAddr).Port

			for _, name := range []string{"/readme.txt", "/data/blocks.bin"} {
				r := runClient(t, a, port, "file-get", "--name", name)
				if !r.OK || r.File == nil {
					t.Fatalf("file-get %s failed: %s", name, r.errorCode())
				}
				if r.File.Content != hex.EncodeToString(want[name]) {
					t.Errorf("file-get %s: %d octets of content, the fixture has %d", name, len(r.File.Content)/2, len(want[name]))
				}
			}
			r := runClient(t, a, port, "file-info", "--name", "/readme.txt")
			if !r.OK || r.File == nil || r.File.Type != "file" || int(r.File.Size) != len(want["/readme.txt"]) {
				t.Errorf("file-info /readme.txt: ok=%v %s %+v", r.OK, r.errorCode(), r.File)
			}
			r = runClient(t, a, port, "file-ls", "--name", "/")
			if !r.OK {
				t.Fatalf("file-ls / failed: %s", r.errorCode())
			}
			got := map[string]string{}
			for _, e := range r.Files {
				got[e.Name] = e.Type
			}
			if got["readme.txt"] != "file" || got["data"] != "directory" || got["logs"] != "directory" {
				t.Errorf("file-ls /: %+v", r.Files)
			}
			r = runClient(t, a, port, "file-get", "--name", "/missing.txt")
			if r.OK || r.FileStatus == nil || *r.FileStatus != "FILE_NOT_FOUND" {
				t.Errorf("file-get of a missing file: ok=%v status=%v", r.OK, r.FileStatus)
			}

			content := bytes.Repeat([]byte{0xA5, 0x5A, 0x00, 0xFF}, 700)
			r = runClient(t, a, port, "file-put", "--name", "/logs/ref.bin", "--content", hex.EncodeToString(content))
			if !r.OK {
				t.Fatalf("file-put failed: %s", r.errorCode())
			}
			if b, ok := st.files.get("/logs/ref.bin"); !ok || !bytes.Equal(b, content) {
				t.Fatalf("file-put stored %d octets, sent %d", len(b), len(content))
			}
			if !a.capabilities(t).Features["fileDeleteClient"] {
				return
			}
			if r := runClient(t, a, port, "file-delete", "--name", "/logs/ref.bin"); !r.OK {
				t.Fatalf("file-delete failed: %s", r.errorCode())
			}
			if _, ok := st.files.get("/logs/ref.bin"); ok {
				t.Fatal("file-delete left the file")
			}
		})
	}
}

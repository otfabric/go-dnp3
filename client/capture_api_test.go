// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/capture"
)

// The API replays run the client's procedures (file transfer, select
// before operate, time synchronization, delay measurement, restarts)
// against recorded outstations: the replay outstation answers the client's
// n-th request with the recorded responses of the n-th recorded request of
// the procedure, its sequence number replaced by the client's (the only
// octet changed). The client's requests are then compared with the
// recorded ones, the dynamic fields excepted: the application sequence
// number, the file request ID (go-dnp3 sends 1; the recorded masters
// count), the creation time of a file command and the time of g50 objects.

// apiReplay starts a client against the recorded exchanges of a file's
// first conversation that keep accepts, and returns the requests the
// client sent when done is called.
func apiReplay(t *testing.T, id string, keep func(capture.Exchange) bool) (*Client, []capture.Exchange, func() []*app.Fragment) {
	t.Helper()
	recs, err := capture.Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := capture.Get(recs, id)
	if !ok || len(rec.Conversations) == 0 {
		t.Fatalf("capture %s not found", id)
	}
	s := rec.Conversations[0]
	master, outstation, _ := capture.Addresses(s)
	var exs []capture.Exchange
	for _, ex := range capture.Exchanges(s) {
		if keep == nil || keep(ex) {
			exs = append(exs, ex)
		}
	}
	c, o, closeAll := dialReplay(t, master, outstation)
	var sent []*app.Fragment
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for _, ex := range exs {
			var b []byte
			for b == nil {
				select {
				case <-stop:
					return
				default:
				}
				b, _ = o.next(100*time.Millisecond, false)
			}
			f, err := app.Decode(b)
			if err != nil {
				t.Errorf("client request % x: %v", b, err)
				return
			}
			sent = append(sent, f)
			seq := b[0] & 0x0F
			for _, r := range ex.Responses {
				if err := o.send(withSeq(r.Raw, seq)); err != nil {
					return
				}
				seq = app.NextSeq(seq)
			}
		}
	}()
	return c, exs, func() []*app.Fragment {
		close(stop)
		<-finished
		closeAll()
		return sent
	}
}

// normalized returns a copy of a request with its dynamic fields cleared
// and its legitimate encoding choices made uniform: the width of an
// index-prefixed qualifier (go-dnp3 picks the smallest that holds the
// indexes, IEEE 1815-2012 clause 4.4.4.3; the recorded masters of
// select-operate-and-responses send 0x28 for index 0) and the size in a
// g70v3 opened for writing when the recorded master sent 0 ("unknown",
// zeek-file-write; go-dnp3 sends the size it is given).
func normalized(f *app.Fragment, recorded *app.Fragment) app.Fragment {
	n := *f
	n.Control.Seq = 0
	n.Headers = slices.Clone(f.Headers)
	for i := range n.Headers {
		h := &n.Headers[i]
		if h.Qualifier == app.Qual1ByteIndexCount || h.Qualifier == app.Qual4ByteIndexCount {
			h.Qualifier = app.Qual2ByteIndexCount
		}
		h.Objects = slices.Clone(h.Objects)
		for j := range h.Objects {
			switch v := h.Objects[j].Value.(type) {
			case app.FileCommand:
				v.RequestID, v.Created = 0, 0
				if recordedSize(recorded) == 0 {
					v.Size = 0
				}
				h.Objects[j].Value = v
			case app.FileCommandStatus:
				v.RequestID = 0
				h.Objects[j].Value = v
			case app.AbsoluteTime:
				v.Time = 0
				h.Objects[j].Value = v
			}
		}
	}
	return n
}

// recordedSize returns the size of the recorded g70v3 file command.
func recordedSize(f *app.Fragment) uint32 {
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			if fc, ok := o.Value.(app.FileCommand); ok {
				return fc.Size
			}
		}
	}
	return 1
}

// sameRequests compares the client's requests with the recorded ones under
// the replay's rules.
func sameRequests(t *testing.T, sent []*app.Fragment, exs []capture.Exchange) {
	t.Helper()
	if len(sent) != len(exs) {
		t.Errorf("client sent %d requests, recorded %d", len(sent), len(exs))
	}
	for i := range min(len(sent), len(exs)) {
		rec := exs[i].Request.Frag
		got, want := normalized(sent[i], rec), normalized(rec, rec)
		a, _ := got.Encode()
		b, _ := want.Encode()
		if !bytes.Equal(a, b) {
			t.Errorf("request %d: client %s\n % x\n recorded %s (frame %d)\n % x", i, sent[i], a, exs[i].Request.Frag, exs[i].Request.Frame, b)
		}
	}
}

func fileExchange(ex capture.Exchange) bool {
	switch ex.Request.Frag.Function {
	case app.FuncOpenFile, app.FuncCloseFile, app.FuncDeleteFile:
		return true
	case app.FuncRead, app.FuncWrite:
		return len(ex.Request.Frag.Headers) > 0 && ex.Request.Frag.Headers[0].GV.Group() == 70
	default:
		return false
	}
}

// recordedFile returns the data of the g70v5 blocks of the responses
// (read) or requests (write) of the exchanges.
func recordedFile(exs []capture.Exchange, requests bool) []byte {
	var out []byte
	for _, ex := range exs {
		frags := []capture.Fragment{ex.Request}
		if !requests {
			frags = ex.Responses
		}
		for _, f := range frags {
			for _, h := range f.Frag.Headers {
				for _, o := range h.Objects {
					if ft, ok := o.Value.(app.FileTransport); ok && h.GV == app.G70V5 {
						out = append(out, ft.Data...)
					}
				}
			}
		}
	}
	return out
}

func TestCaptureClientReadFile(t *testing.T) {
	for _, tc := range []struct{ id, name string }{
		{"file-read", "./testfile.txt"},
		{"zeek-file-read", "./test.xml"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c, exs, done := apiReplay(t, tc.id, fileExchange)
			var buf bytes.Buffer
			n, err := c.ReadFile(t.Context(), tc.name, &buf, FileOptions{MaxBlockSize: 1024})
			sent := done()
			if err != nil {
				t.Fatal(err)
			}
			want := recordedFile(exs, false)
			if n != int64(len(want)) || !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("read %d octets %q, recorded %d", n, buf.Bytes(), len(want))
			}
			sameRequests(t, sent, exs)
		})
	}
}

func TestCaptureClientListDirectory(t *testing.T) {
	c, exs, done := apiReplay(t, "file-list-directory", fileExchange)
	got, err := c.ListDirectory(t.Context(), ".", FileOptions{MaxBlockSize: 1024})
	sent := done()
	if err != nil {
		t.Fatal(err)
	}
	want, err := app.DecodeFileDescriptors(recordedFile(exs, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(want) == 0 || !slices.Equal(got, want) {
		t.Errorf("client listed %d entries, recorded %d", len(got), len(want))
	}
	// The recorded master opened the directory with permissions
	// rwxrwxrwx; go-dnp3 sends none for a read (IEEE 1815-2012 clause
	// A.42.3: permissions apply to a file being created).
	for _, f := range sent {
		for i, h := range f.Headers {
			for j, o := range h.Objects {
				if fc, ok := o.Value.(app.FileCommand); ok {
					fc.Permissions = 0o777
					f.Headers[i].Objects[j].Value = fc
				}
			}
		}
	}
	sameRequests(t, sent, exs)
}

func TestCaptureClientWriteFile(t *testing.T) {
	for _, tc := range []struct {
		id, name string
		perm     app.Permissions
	}{
		{"file-write", "./helloworld.txt", 0o777},
		{"zeek-file-write", "C:/temp/DNPDeviceConfiguration written to Remote Device.xml", 0o777},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c, exs, done := apiReplay(t, tc.id, fileExchange)
			data := recordedFile(exs, true)
			n, err := c.WriteFile(t.Context(), tc.name, bytes.NewReader(data), uint32(len(data)), FileOptions{MaxBlockSize: 1024, Permissions: tc.perm})
			sent := done()
			if err != nil {
				t.Fatal(err)
			}
			if n != int64(len(data)) {
				t.Errorf("wrote %d octets, recorded %d", n, len(data))
			}
			sameRequests(t, sent, exs)
		})
	}
}

func TestCaptureClientDeleteFile(t *testing.T) {
	for _, tc := range []struct{ id, name string }{
		{"file-delete", "./helloworld.txt"},
		{"zeek-file-del", "C:/temp/DNPDeviceConfiguration written to Remote Device.xml"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c, exs, done := apiReplay(t, tc.id, fileExchange)
			err := c.DeleteFile(t.Context(), tc.name, FileOptions{})
			sent := done()
			if err != nil {
				t.Fatal(err)
			}
			sameRequests(t, sent, exs)
		})
	}
}

func TestCaptureClientSelectOperate(t *testing.T) {
	c, exs, done := apiReplay(t, "select-operate-and-responses", nil)
	st, err := c.Operate(t.Context(), SelectBeforeOperate, CROB(0, app.OpLatchOn, 100, 100))
	sent := done()
	if err != nil || !slices.Equal(st, []app.CommandStatus{app.StatusSuccess}) {
		t.Fatalf("statuses %v, %v", st, err)
	}
	sameRequests(t, sent, exs)
}

func TestCaptureClientTimeSync(t *testing.T) {
	for _, tc := range []struct {
		id string
		p  TimeSync
	}{
		{"lan-time-sync", TimeSyncLAN},
		{"serial-time-sync", TimeSyncNonLAN},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c, exs, done := apiReplay(t, tc.id, nil)
			err := c.SyncTime(t.Context(), tc.p)
			sent := done()
			if err != nil {
				t.Fatal(err)
			}
			sameRequests(t, sent, exs)
		})
	}
}

func TestCaptureClientDelayMeasure(t *testing.T) {
	c, exs, done := apiReplay(t, "zeek-del-measure", nil)
	processing, _, err := c.DelayMeasure(t.Context())
	sent := done()
	if err != nil {
		t.Fatal(err)
	}
	if processing != time.Millisecond {
		t.Errorf("processing delay %v, recorded 1 ms", processing)
	}
	sameRequests(t, sent, exs)
}

func TestCaptureClientRestart(t *testing.T) {
	for _, tc := range []struct {
		id   string
		cold bool
	}{
		{"cold-restart-and-response", true},
		{"warm-restart-and-response", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c, exs, done := apiReplay(t, tc.id, nil)
			var err error
			if tc.cold {
				_, err = c.ColdRestart(t.Context())
			} else {
				_, err = c.WarmRestart(t.Context())
			}
			sent := done()
			// The recorded outstation does not support restarts (IIN2.0).
			var iinErr *dnp3.IINError
			if !errors.As(err, &iinErr) || iinErr.IIN&app.IINNoFuncCodeSupport == 0 {
				t.Fatalf("err %v, want IIN2.0", err)
			}
			if !strings.Contains(err.Error(), "NO_FUNC_CODE_SUPPORT") {
				t.Errorf("error %q", err)
			}
			sameRequests(t, sent, exs)
		})
	}
}

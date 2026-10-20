// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

type linkFrame = link.Frame

// recorder is a client.Handler that keeps what it receives.
type recorder struct {
	mu     sync.Mutex
	ms     []client.Measurement
	infos  []client.ResponseInfo
	signal chan struct{}
}

func newRecorder() *recorder { return &recorder{signal: make(chan struct{}, 1)} }

func (r *recorder) HandleMeasurements(info client.ResponseInfo, ms []client.Measurement) {
	r.mu.Lock()
	r.ms = append(r.ms, ms...)
	for range ms {
		r.infos = append(r.infos, info)
	}
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// waitFor waits until pred holds for the unsolicited measurements.
func (r *recorder) waitFor(t *testing.T, what string, pred func(ms []client.Measurement) bool) []client.Measurement {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		var uns []client.Measurement
		for i, m := range r.ms {
			if r.infos[i].Unsolicited {
				uns = append(uns, m)
			}
		}
		r.mu.Unlock()
		if pred(uns) {
			return uns
		}
		select {
		case <-r.signal:
		case <-deadline:
			t.Fatalf("timed out waiting for %s; have %d unsolicited measurements", what, len(uns))
		}
	}
}

type pair struct {
	srv *server.Server
	db  *server.Database
	c   *client.Client
	rec *recorder
	l   net.Listener
}

// newPair starts a server with sopts and a client with copts connected to
// it; setup runs on the database before the client connects.
func newPair(t *testing.T, setup func(db *server.Database), sopts []server.Option, copts ...client.Option) *pair {
	t.Helper()
	srv, err := server.New(append([]server.Option{server.WithMasters(1)}, sopts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(srv.Database())
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	rec := newRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, l.Addr().String(), append([]client.Option{
		client.WithHandler(rec), client.WithResponseTimeout(2 * time.Second),
		// The automatic integrity poll after a restart would take the
		// events the tests poll for; TestAutomaticIntegrity covers it.
		client.WithAutoIntegrity(false),
	}, copts...)...)
	if err != nil {
		_ = srv.Close()
		t.Fatal(err)
	}
	p := &pair{srv: srv, db: srv.Database(), c: c, rec: rec, l: l}
	t.Cleanup(func() {
		_ = c.Close()
		_ = srv.Close()
	})
	return p
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// byKey indexes measurements by group and index.
func byKey(ms []client.Measurement) map[[2]uint32]client.Measurement {
	out := make(map[[2]uint32]client.Measurement)
	for _, m := range ms {
		out[[2]uint32{uint32(m.GV.Group()), m.Index}] = m
	}
	return out
}

func gvs(ms []client.Measurement) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.GV.String())
	}
	return out
}

// memFS is a writable in-memory server.FileServer.
type memFS struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newMemFS() *memFS { return &memFS{files: map[string][]byte{}} }

func (m *memFS) Open(_ context.Context, req server.FileRequest) (server.File, app.FileStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch req.Mode {
	case app.FileModeRead:
		if req.Name == "/" {
			var b []byte
			names := make([]string, 0, len(m.files))
			for n := range m.files {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				b, _ = app.AppendFileDescriptor(b, app.FileDescriptor{Name: n, Type: app.FileTypeSimple, Size: uint32(len(m.files[n]))})
			}
			return &memFile{r: bytes.NewReader(b), size: uint32(len(b))}, app.FileSuccess
		}
		data, ok := m.files[req.Name]
		if !ok {
			return nil, app.FileNotFound
		}
		return &memFile{r: bytes.NewReader(data), size: uint32(len(data))}, app.FileSuccess
	case app.FileModeWrite:
		if req.AuthKey != 0 && req.AuthKey != 42 {
			return nil, app.FilePermissionDenied
		}
		return &memFile{fs: m, name: req.Name}, app.FileSuccess
	default:
		return nil, app.FileInvalidMode
	}
}

func (m *memFS) Delete(_ context.Context, name string, _ uint32) app.FileStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[name]; !ok {
		return app.FileNotFound
	}
	delete(m.files, name)
	return app.FileSuccess
}

func (m *memFS) Info(_ context.Context, name string) (app.FileDescriptor, app.FileStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[name]
	if !ok {
		return app.FileDescriptor{}, app.FileNotFound
	}
	return app.FileDescriptor{Name: name, Type: app.FileTypeSimple, Size: uint32(len(data)), Permissions: 0o644}, app.FileSuccess
}

func (m *memFS) Authenticate(_ context.Context, user, password string) (uint32, bool) {
	return 42, user == "operator" && password == "secret"
}

type memFile struct {
	r    io.Reader
	size uint32
	fs   *memFS
	name string
	buf  bytes.Buffer
}

func (f *memFile) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *memFile) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *memFile) Size() uint32                { return f.size }
func (f *memFile) Close(abort bool) error {
	if f.fs != nil && !abort {
		f.fs.mu.Lock()
		f.fs.files[f.name] = bytes.Clone(f.buf.Bytes())
		f.fs.mu.Unlock()
	}
	return nil
}

// relay is a server.Handler that records controls and answers with a
// fixed status.
type relay struct {
	mu       sync.Mutex
	status   app.CommandStatus
	selects  []server.Command
	operates []server.Command
	ops      []server.OperateType
	restarts []bool
	times    []time.Time
}

func (r *relay) Select(_ context.Context, c server.Command) app.CommandStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selects = append(r.selects, c)
	return r.status
}

func (r *relay) Operate(_ context.Context, c server.Command, op server.OperateType) app.CommandStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.operates = append(r.operates, c)
	r.ops = append(r.ops, op)
	return r.status
}

func (r *relay) Restart(_ context.Context, cold bool) (time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restarts = append(r.restarts, cold)
	if cold {
		return 90 * time.Second, nil
	}
	return 1500 * time.Millisecond, nil
}

func (r *relay) SetTime(_ context.Context, t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.times = append(r.times, t)
}

func (r *relay) snapshot() (sel, op []server.Command, ops []server.OperateType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]server.Command(nil), r.selects...), append([]server.Command(nil), r.operates...), append([]server.OperateType(nil), r.ops...)
}

// countingMetrics counts the callbacks it receives.
type countingMetrics struct {
	dnp3.NopMetrics
	mu                                  sync.Mutex
	connects, framesSent, framesRcvd    int
	fragsSent, fragsRcvd                int
	requests, requestsDone, retries     int
	handled, unsolicited, eventsDropped int
}

func (m *countingMetrics) inc(p *int) { m.mu.Lock(); *p++; m.mu.Unlock() }

func (m *countingMetrics) OnConnect(net.Addr)                          { m.inc(&m.connects) }
func (m *countingMetrics) OnFrameSent(net.Addr, *linkFrame, int)       { m.inc(&m.framesSent) }
func (m *countingMetrics) OnFrameReceived(net.Addr, *linkFrame, int)   { m.inc(&m.framesRcvd) }
func (m *countingMetrics) OnFragmentSent(net.Addr, *app.Fragment, int) { m.inc(&m.fragsSent) }
func (m *countingMetrics) OnFragmentReceived(net.Addr, *app.Fragment, int) {
	m.inc(&m.fragsRcvd)
}
func (m *countingMetrics) OnRequest(net.Addr, uint16, app.FunctionCode) { m.inc(&m.requests) }
func (m *countingMetrics) OnRequestDone(net.Addr, uint16, app.FunctionCode, time.Duration, error) {
	m.inc(&m.requestsDone)
}
func (m *countingMetrics) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) { m.inc(&m.retries) }
func (m *countingMetrics) OnHandled(net.Addr, app.FunctionCode, time.Duration)    { m.inc(&m.handled) }
func (m *countingMetrics) OnEventsDiscarded(int, int)                             { m.inc(&m.eventsDropped) }
func (m *countingMetrics) OnUnsolicited(net.Addr, int, error)                     { m.inc(&m.unsolicited) }

func (m *countingMetrics) get(p *int) int { m.mu.Lock(); defer m.mu.Unlock(); return *p }

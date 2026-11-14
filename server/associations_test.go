// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// decodeErrors records the errors given to OnDecodeError, in order.
type decodeErrors struct {
	dnp3.NopMetrics
	errs chan error
}

func newDecodeErrors() *decodeErrors { return &decodeErrors{errs: make(chan error, 64)} }

func (m *decodeErrors) OnDecodeError(_ net.Addr, err error) { m.errs <- err }

// next waits for the next error given to OnDecodeError.
func (m *decodeErrors) next(t *testing.T) error {
	t.Helper()
	select {
	case err := <-m.errs:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("OnDecodeError was not called")
		return nil
	}
}

// pipeMasters is the masters' end of a pipe the outstation serves with
// ServeConn: one channel, with a session for each master address, as on a
// multi-drop line.
type pipeMasters struct {
	t  *testing.T
	ch *channel.Channel
	mu sync.Mutex
	in map[link.Address]chan *app.Fragment
}

func newPipeMasters(t *testing.T, srv *Server) *pipeMasters {
	t.Helper()
	near, far := net.Pipe()
	served := make(chan error, 1)
	go func() { served <- srv.ServeConn(near, nil) }()
	m := &pipeMasters{t: t, ch: channel.New(far, channel.Config{}), in: map[link.Address]chan *app.Fragment{}}
	m.ch.Start()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-served; err != nil {
			t.Errorf("ServeConn after Close: %v", err)
		}
		m.ch.Close(nil)
		<-m.ch.Done()
	})
	return m
}

// read sends a READ of class 0 from master a and returns the response.
func (m *pipeMasters) read(a link.Address, seq uint8) *app.Fragment {
	m.t.Helper()
	m.send(a, seq)
	select {
	case f := <-m.inbox(a):
		return f
	case <-time.After(5 * time.Second):
		m.t.Fatalf("no response to master %d", a)
		return nil
	}
}

// send sends a READ of class 0 from master a.
func (m *pipeMasters) send(a link.Address, seq uint8) {
	m.t.Helper()
	in := m.inbox(a)
	sess := m.ch.Session(a, 10)
	if sess == nil {
		sess = m.ch.AddSession(channel.SessionConfig{Local: a, Remote: 10, Master: true,
			OnFragment: func(b []byte, _ link.Address) {
				if f, err := app.Decode(b); err == nil && f.Function == app.FuncResponse {
					in <- f
				}
			}})
	}
	b, err := req(seq, app.FuncRead, app.ClassHeaders(0)...).Encode()
	if err != nil {
		m.t.Fatal(err)
	}
	if err := sess.Send(context.Background(), b); err != nil {
		m.t.Fatal(err)
	}
}

func (m *pipeMasters) inbox(a link.Address) chan *app.Fragment {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.in[a] == nil {
		m.in[a] = make(chan *app.Fragment, 8)
	}
	return m.in[a]
}

// masterSet returns the addresses of the server's associations.
func (s *Server) masterSet() map[link.Address]bool {
	out := map[link.Address]bool{}
	for _, a := range s.associations() {
		out[a.master] = true
	}
	return out
}

// TestMaxAssociationsOption: the limit is at least 1 and, with WithMasters,
// at least their number, duplicates counted once; by default it is that
// number, else 16.
func TestMaxAssociationsOption(t *testing.T) {
	for _, tc := range []struct {
		opts []Option
		want int // 0: New fails with dnp3.ErrInvalidOption
	}{
		{nil, 16},
		{[]Option{WithMaxAssociations(-1)}, 0},
		{[]Option{WithMaxAssociations(0)}, 0},
		{[]Option{WithMaxAssociations(1)}, 1},
		{[]Option{WithMaxAssociations(65520)}, 65520},
		{[]Option{WithMasters(1, 2, 3)}, 3},
		{[]Option{WithMasters(1, 2, 2, 3)}, 3},
		{[]Option{WithMasters(1, 2, 3), WithMaxAssociations(2)}, 0},
		{[]Option{WithMaxAssociations(2), WithMasters(1, 2, 3)}, 0},
		{[]Option{WithMasters(1, 2, 3), WithMaxAssociations(3)}, 3},
		{[]Option{WithMasters(1, 2, 3), WithMaxAssociations(4)}, 4},
	} {
		srv, err := New(tc.opts...)
		if tc.want == 0 {
			if !errors.Is(err, dnp3.ErrInvalidOption) {
				t.Errorf("%d options: %v, want ErrInvalidOption", len(tc.opts), err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if srv.maxAssocs != tc.want {
			t.Errorf("limit %d, want %d", srv.maxAssocs, tc.want)
		}
		_ = srv.Close()
	}
}

// TestMaxAssociationsLimit: of n masters that speak in turn, the outstation
// answers the first limit; a frame of a master beyond them is dropped
// before any association is made for it, logged at debug level and
// reported to OnDecodeError, and the masters it holds are answered as
// before. With WithMasters the limit is their number: a further address is
// not among them and gets no association either.
func TestMaxAssociationsLimit(t *testing.T) {
	type limitCase struct {
		name    string
		opts    []Option
		limit   int
		masters bool // WithMasters(1..limit)
	}
	var cases []limitCase
	for _, base := range []limitCase{
		{name: "default", limit: 16},
		{name: "explicit", opts: []Option{WithMaxAssociations(4)}, limit: 4},
		{name: "masters", limit: 3, masters: true},
	} {
		for _, d := range []int{-1, 0, 1} {
			tc := base
			tc.name = fmt.Sprintf("%s/%d", base.name, base.limit+d)
			tc.opts = append([]Option(nil), base.opts...)
			if tc.masters {
				var ms []link.Address
				for a := range tc.limit {
					ms = append(ms, link.Address(a+1))
				}
				tc.opts = append(tc.opts, WithMasters(ms...))
			}
			cases = append(cases, tc)
		}
	}
	for i, tc := range cases {
		n := tc.limit + i%3 - 1 // limit-1, limit, limit+1
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			var logMu sync.Mutex
			metrics := newDecodeErrors()
			srv, err := New(append(tc.opts, WithMetrics(metrics),
				WithLogger(dnp3.NewSlogLogger(slog.NewTextHandler(lockedWriter{&logMu, &logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))))...)
			if err != nil {
				t.Fatal(err)
			}
			m := newPipeMasters(t, srv)
			for a := 1; a <= n; a++ {
				if a <= tc.limit {
					if f := m.read(link.Address(a), 0); f.IIN&dnp3.IINErrorBits != 0 {
						t.Fatalf("master %d answered with %s", a, f.IIN)
					}
					continue
				}
				m.send(link.Address(a), 0)
				if !tc.masters {
					if err := metrics.next(t); !errors.Is(err, errTooManyAssociations) {
						t.Fatalf("OnDecodeError(%v), want errTooManyAssociations", err)
					}
				}
			}
			// The masters held are answered as before.
			if f := m.read(1, 1); f.IIN&dnp3.IINErrorBits != 0 {
				t.Fatalf("master 1 after the others: %s", f.IIN)
			}
			want := min(n, tc.limit)
			if tc.masters {
				want = tc.limit // made by New
			}
			got := srv.masterSet()
			if len(got) != want || got[link.Address(tc.limit+1)] {
				t.Fatalf("associations of masters %v, want %d, none of master %d", got, want, tc.limit+1)
			}
			logMu.Lock()
			dropped := strings.Count(logs.String(), "association limit reached")
			logMu.Unlock()
			if wantDropped := max(n-tc.limit, 0); !tc.masters && dropped != wantDropped {
				t.Errorf("%d debug entries of a dropped frame, want %d", dropped, wantDropped)
			}
			if tc.masters && dropped != 0 {
				t.Errorf("a master outside WithMasters counted against the limit")
			}
			select {
			case err := <-metrics.errs:
				t.Errorf("OnDecodeError(%v) for a master within the limit", err)
			default:
			}
		})
	}
}

// lockedWriter serializes the writes of the outstation's goroutines.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// TestMaxAssociationsFreedWhenEnded: an association frees its place when
// it ends; a new master then gets one. Close ends them all.
func TestMaxAssociationsFreedWhenEnded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv, err := New(WithMaxAssociations(2))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = srv.Close() }()
		a1, a2 := srv.association(1), srv.association(2)
		if a1 == nil || a2 == nil {
			t.Fatal("associations within the limit not made")
		}
		if srv.association(3) != nil {
			t.Fatal("an association beyond the limit was made")
		}
		if srv.association(1) != a1 {
			t.Fatal("the association of a master that has one was not returned")
		}
		a1.close()
		synctest.Wait()
		if got := srv.masterSet(); len(got) != 1 || !got[2] {
			t.Fatalf("after an association ended: masters %v, want 2 only", got)
		}
		if srv.association(3) == nil {
			t.Fatal("the place of the association that ended was not freed")
		}
		_ = srv.Close()
		if got := srv.masterSet(); len(got) != 0 || srv.association(4) != nil {
			t.Fatalf("after Close: masters %v", got)
		}
	})
}

// TestMaxAssociationsBudget: a stream of new master addresses no longer
// grows the outstation: once it holds the limit, a frame of a new address
// allocates nothing and adds neither an association nor a session.
func TestMaxAssociationsBudget(t *testing.T) {
	srv, err := New()
	if err != nil {
		t.Fatal(err)
	}
	near, far := net.Pipe()
	ch := channel.New(near, channel.Config{})
	ch.Start()
	t.Cleanup(func() {
		ch.Close(nil)
		<-ch.Done()
		_ = far.Close()
		_ = srv.Close()
	})
	for a := range link.Address(16) {
		if srv.bind(ch, a+1) == nil {
			t.Fatalf("master %d within the limit not taken", a+1)
		}
	}
	next := link.Address(100)
	allocs := testing.AllocsPerRun(1000, func() {
		if srv.bind(ch, next) != nil {
			t.Fatal("a master beyond the limit was taken")
		}
		next++
	})
	if allocs > 0 {
		t.Errorf("%.1f allocations per frame of a new master beyond the limit, want 0", allocs)
	}
	if n, s := len(srv.associations()), len(ch.Sessions()); n != 16 || s != 16 {
		t.Errorf("after %d new masters: %d associations and %d sessions, want 16 each", next-100, n, s)
	}
}

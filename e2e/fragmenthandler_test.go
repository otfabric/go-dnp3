// SPDX-License-Identifier: MIT

package e2e

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// fragmentLog is a client.Handler and a client.FragmentHandler that checks
// what holds of every delivery: HandleMeasurements follows the
// HandleFragment of its fragment, with the same ResponseInfo and that
// fragment's measurements, and no fragment with measurements goes without
// its HandleMeasurements.
type fragmentLog struct {
	mu       sync.Mutex
	last     *app.Fragment // the fragment whose measurements are due
	lastInfo client.ResponseInfo
	frags    []*app.Fragment
	infos    []client.ResponseInfo
	errs     []error
	signal   chan struct{}
}

func newFragmentLog() *fragmentLog { return &fragmentLog{signal: make(chan struct{}, 1)} }

func (l *fragmentLog) HandleFragment(info client.ResponseInfo, f *app.Fragment) {
	l.mu.Lock()
	if l.last != nil {
		l.errs = append(l.errs, fmt.Errorf("fragment seq %d: no measurements after it", l.lastInfo.Seq))
	}
	l.last = nil
	if len(client.Measurements(f)) > 0 {
		l.last, l.lastInfo = f, info
	}
	l.frags = append(l.frags, f)
	l.infos = append(l.infos, info)
	l.mu.Unlock()
	select {
	case l.signal <- struct{}{}:
	default:
	}
}

func (l *fragmentLog) HandleMeasurements(info client.ResponseInfo, ms []client.Measurement) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.last == nil:
		l.errs = append(l.errs, fmt.Errorf("measurements of seq %d without their fragment first", info.Seq))
	case info != l.lastInfo:
		l.errs = append(l.errs, fmt.Errorf("measurements with %+v after the fragment with %+v", info, l.lastInfo))
	case !reflect.DeepEqual(ms, client.Measurements(l.last)):
		l.errs = append(l.errs, fmt.Errorf("seq %d: %d measurements, not those of the fragment", info.Seq, len(ms)))
	}
	l.last = nil
}

// waitFor waits until pred holds for the fragments delivered so far.
func (l *fragmentLog) waitFor(t *testing.T, what string, pred func([]*app.Fragment, []client.ResponseInfo) bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		l.mu.Lock()
		ok := pred(l.frags, l.infos)
		l.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-l.signal:
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// check reports the deliveries that broke the order.
func (l *fragmentLog) check(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, err := range l.errs {
		t.Error(err)
	}
}

// TestFragmentHandler: against the outstation, a FragmentHandler gets the
// null unsolicited response every connection starts with, which has no
// measurements, with its IIN (DEVICE_RESTART), and every fragment of a
// multi-fragment integrity poll, the same fragments as the Result, in
// order, each before its measurements.
func TestFragmentHandler(t *testing.T) {
	fl := newFragmentLog()
	p := newPair(t, func(db *server.Database) {
		fullDatabase(db)
		for i := range uint32(60) {
			_ = db.AddAnalogInput(100+i, server.PointConfig{}, app.Analog{Value: float64(i), Flags: app.FlagOnline})
		}
	}, []server.Option{server.WithUnsolicited(server.Unsolicited{Enabled: true}), server.WithMaxFragment(249, 2048)},
		// Without the WRITE that clears DEVICE_RESTART, the poll is the
		// only solicited response.
		client.WithHandler(fl), client.WithAutoClearRestart(false))

	fl.waitFor(t, "the null unsolicited response", func(fs []*app.Fragment, is []client.ResponseInfo) bool {
		return len(fs) > 0
	})
	fl.mu.Lock()
	null, info := fl.frags[0], fl.infos[0]
	fl.mu.Unlock()
	if !info.Unsolicited || !info.IIN.Has(app.IINDeviceRestart) || len(null.Headers) != 0 {
		t.Fatalf("first fragment %+v, %d headers: want the null unsolicited response with DEVICE_RESTART", info, len(null.Headers))
	}

	res, err := p.c.IntegrityPoll(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fragments) < 2 {
		t.Fatalf("integrity poll in %d fragments, want several", len(res.Fragments))
	}
	var solicited []*app.Fragment
	var infos []client.ResponseInfo
	fl.waitFor(t, "the fragments of the poll", func(fs []*app.Fragment, is []client.ResponseInfo) bool {
		solicited, infos = nil, nil
		for i, f := range fs {
			if !is[i].Unsolicited {
				solicited = append(solicited, f)
				infos = append(infos, is[i])
			}
		}
		return len(solicited) >= len(res.Fragments)
	})
	for i, f := range res.Fragments {
		if solicited[i] != f {
			t.Errorf("fragment %d delivered is not the Result's", i)
		}
		if infos[i].FIR != (i == 0) || infos[i].FIN != (i == len(res.Fragments)-1) || infos[i].Seq != f.Control.Seq {
			t.Errorf("fragment %d: %+v", i, infos[i])
		}
	}
	fl.check(t)
}

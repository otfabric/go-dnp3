// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/capture"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// The server replay sends the requests of recorded masters to go-dnp3's
// outstation and compares its answers with the recorded outstations'
// (testdata/captures/README.md).
//
// The outstation's database is built from the recording: a point for
// every point the recorded outstation reported or the master commanded,
// with the first value and the static variation recorded. The recorded
// outstations' configuration is otherwise unknown, so the answers are
// compared under these rules:
//   - whether the request is answered at all (no-ack functions, broadcasts
//     and requests the recorded outstation left unanswered);
//   - the response's FIR and sequence number (the request's);
//   - the request error bits IIN2.0 (NO_FUNC_CODE_SUPPORT), IIN2.1
//     (OBJECT_UNKNOWN) and IIN2.2 (PARAMETER_ERROR);
//   - for SELECT, OPERATE and DIRECT_OPERATE, the echoed objects and their
//     status.
// IIN1 (restart, need time, events), the data values and the variations
// chosen are the outstation's state and configuration and are not
// compared. Every difference must be listed in serverReplayExpected with
// its classification.

const capturesDir = "../testdata/captures"

// replayDB builds the database of a stream from what the recorded
// outstation reported: a point for every point it sent, and an output for
// every control it echoed with SUCCESS.
func replayDB(t *testing.T, db *Database, s capture.Stream) {
	t.Helper()
	type key struct {
		pt  PointType
		idx uint32
	}
	added := map[key]bool{}
	add := func(gv app.GroupVariation, idx uint32, v app.Value) {
		var pt PointType
		var init app.Value
		static := uint8(0)
		switch g := gv.Group(); g {
		case 1, 2:
			pt, init = BinaryInput, app.Binary{Flags: app.FlagOnline}
		case 3, 4:
			pt, init = DoubleBitInput, app.DoubleBitBinary{Flags: app.FlagOnline}
		case 10, 11, 12, 13:
			pt, init = BinaryOutput, app.Binary{Flags: app.FlagOnline}
		case 20, 22:
			pt, init = Counter, app.Counter{Flags: app.FlagOnline}
		case 21, 23:
			pt, init = FrozenCounter, app.Counter{Flags: app.FlagOnline}
		case 30, 32:
			pt, init = AnalogInput, app.Analog{Flags: app.FlagOnline}
		case 31, 33:
			pt, init = FrozenAnalogInput, app.Analog{Flags: app.FlagOnline}
		case 40, 41, 42, 43:
			pt, init = AnalogOutput, app.Analog{Flags: app.FlagOnline}
		default:
			return
		}
		switch g := gv.Group(); g {
		case 1, 3, 10, 20, 21, 30, 31, 40:
			static = gv.Variation()
			switch val := v.(type) {
			case app.Binary:
				val.Time = 0
				init = val
			case app.DoubleBitBinary:
				val.Time = 0
				init = val
			case app.Counter:
				val.Time = 0
				init = val
			case app.Analog:
				val.Time = 0
				init = val
			}
		}
		k := key{pt, idx}
		if added[k] {
			return
		}
		added[k] = true
		if err := db.Add(pt, idx, PointConfig{Class: 1, StaticVariation: static}, init); err != nil {
			// A variation the database does not offer as static (for
			// example a packed g1v1): keep the type's default.
			if err := db.Add(pt, idx, PointConfig{Class: 1}, init); err != nil {
				t.Logf("point %s %d: %v", pt, idx, err)
			}
		}
	}
	for _, f := range s.Fragments {
		if f.Frag == nil || f.Err != nil || !f.Frag.Function.IsResponse() {
			continue
		}
		for _, h := range f.Frag.Headers {
			for _, o := range h.Objects {
				switch v := o.Value.(type) {
				case nil:
					continue
				case app.CROB:
					if v.Status != app.StatusSuccess {
						continue
					}
				case app.AnalogOutput:
					if v.Status != app.StatusSuccess {
						continue
					}
				}
				add(h.GV, o.Index, o.Value)
			}
		}
	}
}

// replayHandler accepts every control of an output in the database and
// every restart, time and application function: the replay outstation
// supports what the recorded ones did, so that the comparison is of the
// protocol, not of the configuration.
type replayHandler struct {
	NopHandler
	db *Database
}

func (h replayHandler) status(c Command) app.CommandStatus {
	t := BinaryOutput
	if c.GV.Group() == 41 {
		t = AnalogOutput
	}
	if h.db == nil {
		return app.StatusSuccess
	}
	if _, ok := h.db.Get(t, c.Index); !ok {
		return app.StatusNotSupported
	}
	return app.StatusSuccess
}

func (h replayHandler) Select(_ context.Context, c Command) app.CommandStatus { return h.status(c) }
func (h replayHandler) Operate(_ context.Context, c Command, _ OperateType) app.CommandStatus {
	return h.status(c)
}

func (replayHandler) Restart(context.Context, bool) (time.Duration, error) { return time.Second, nil }
func (replayHandler) SetTime(context.Context, time.Time)                   {}
func (replayHandler) Application(context.Context, app.FunctionCode, []app.Header) app.IIN {
	return 0
}

// replayMaster is the master side of the pipe.
type replayMaster struct {
	conn               net.Conn
	master, outstation link.Address
	seg                transport.Segmenter
	frags              chan *app.Fragment
}

func (m *replayMaster) read() {
	defer close(m.frags)
	r := link.NewReader(m.conn)
	ra := transport.NewReassembler(1 << 16)
	for {
		f, err := r.ReadFrame()
		if err != nil {
			if errors.Is(err, link.ErrFraming) {
				continue
			}
			return
		}
		if !f.Function.HasData() {
			continue
		}
		b, err := ra.Add(f.Data)
		if err != nil || b == nil {
			continue
		}
		if frag, err := app.Decode(b); err == nil {
			m.frags <- frag
		}
	}
}

func (m *replayMaster) send(frag []byte, dest link.Address) error {
	for _, seg := range m.seg.Segment(frag) {
		f := link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: dest, Src: m.master, Data: seg}
		b, err := f.Encode()
		if err != nil {
			return err
		}
		if _, err := m.conn.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// answer collects the outstation's response to the request with sequence
// number seq: its fragments up to FIN, each confirmed when it asks for it.
// Unsolicited responses are confirmed and dropped.
func (m *replayMaster) answer(seq uint8, wait time.Duration) []*app.Fragment {
	var out []*app.Fragment
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case f, ok := <-m.frags:
			if !ok {
				return out
			}
			if f.Control.CON {
				c := &app.Fragment{Control: app.Control{FIR: true, FIN: true, UNS: f.Control.UNS, Seq: f.Control.Seq}, Function: app.FuncConfirm}
				b, _ := c.Encode()
				_ = m.send(b, m.outstation)
			}
			if f.Function != app.FuncResponse {
				continue
			}
			if len(out) == 0 && (!f.Control.FIR || f.Control.Seq != seq) {
				continue // a late answer to an earlier request
			}
			out = append(out, f)
			if f.Control.FIN {
				return out
			}
			timer.Reset(wait)
		case <-timer.C:
			return out
		}
	}
}

const iin2Errors = app.IINNoFuncCodeSupport | app.IINObjectUnknown | app.IINParameterError

// serverDiff is one difference of the outstation's answer to a recorded
// request.
type serverDiff struct {
	file  string
	frame int
	what  string
}

func (d serverDiff) String() string { return fmt.Sprintf("%s frame %d: %s", d.file, d.frame, d.what) }

func TestCaptureServerReplay(t *testing.T) {
	recs, err := capture.Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var diffs []serverDiff
	var requests, answered int
	for _, r := range recs {
		for si, s := range r.Conversations {
			master, outstation, ok := capture.Addresses(s)
			if !ok {
				continue
			}
			exs := capture.Exchanges(s)
			if len(exs) == 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", r.File.ID, si), func(t *testing.T) {
				d, n, a := replayServer(t, r.File.ID, master, outstation, s, exs)
				diffs = append(diffs, d...)
				requests += n
				answered += a
			})
		}
	}
	got := map[string]string{}
	for _, d := range diffs {
		got[fmt.Sprintf("%s:%d", d.file, d.frame)] = d.what
	}
	for k, what := range got {
		if _, ok := serverReplayExpected[k]; !ok {
			t.Errorf("unclassified difference %s: %s", k, what)
		}
	}
	for k, why := range serverReplayExpected {
		if _, ok := got[k]; !ok {
			t.Errorf("classified difference %s (%s) no longer occurs", k, why)
		}
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("replayed %d requests (%d answered); %d classified differences", requests, answered, len(keys))
	if testing.Verbose() {
		for _, k := range keys {
			t.Logf("  %s: %s", k, got[k])
		}
	}
}

func replayServer(t *testing.T, file string, master, outstation link.Address, s capture.Stream, exs []capture.Exchange) (diffs []serverDiff, requests, answered int) {
	t.Helper()
	h := &replayHandler{}
	opts := []Option{WithAddress(outstation), WithHandler(h), WithMaxFragment(2048, 1<<16),
		WithUnsolicited(Unsolicited{Enabled: true}), WithFileServer(FSFileServer{FS: fstest.MapFS{}})}
	if strings.HasPrefix(file, "conformance-") {
		// The opendnp3 3.0 outstation of the conformance captures accepts
		// four controls per request (procedures 8.2.4.2 and 8.4.4.2 send
		// five and get TOO_MANY_OBJS for the fifth).
		opts = append(opts, WithMaxControls(4))
	}
	srv, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	h.db = srv.Database()
	replayDB(t, srv.Database(), s)
	cs, ss := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(ss, nil) }()
	m := &replayMaster{conn: cs, master: master, outstation: outstation, frags: make(chan *app.Fragment, 64)}
	go m.read()
	defer func() {
		_ = srv.Close()
		_ = cs.Close()
		if err := <-done; err != nil {
			t.Logf("ServeConn: %v", err)
		}
	}()
	diff := func(frame int, format string, args ...any) {
		diffs = append(diffs, serverDiff{file, frame, fmt.Sprintf(format, args...)})
	}
	for _, ex := range exs {
		req := ex.Request
		requests++
		if err := m.send(req.Raw, req.Dest); err != nil {
			t.Fatal(err)
		}
		wait := time.Second
		if len(ex.Responses) == 0 {
			wait = 100 * time.Millisecond
		}
		ours := m.answer(req.Frag.Control.Seq, wait)
		if len(ours) > 0 {
			answered++
		}
		switch {
		case len(ours) == 0 && len(ex.Responses) == 0:
			continue
		case len(ours) == 0:
			diff(req.Frame, "%s: no answer; recorded %s", req.Frag, ex.Responses[0].Frag)
			continue
		case len(ex.Responses) == 0:
			diff(req.Frame, "%s: answered %s; recorded no answer", req.Frag, ours[0])
			continue
		}
		first, rec := ours[0], ex.Responses[0].Frag
		var what []string
		if !first.Control.FIR || first.Control.Seq != req.Frag.Control.Seq {
			what = append(what, fmt.Sprintf("first fragment %s", first.Control))
		}
		last, recLast := ours[len(ours)-1], ex.Responses[len(ex.Responses)-1].Frag
		if a, b := (first.IIN|last.IIN)&iin2Errors, (rec.IIN|recLast.IIN)&iin2Errors; a != b {
			what = append(what, fmt.Sprintf("IIN2 errors %s, recorded %s", a, b))
		}
		switch req.Frag.Function {
		case app.FuncSelect, app.FuncOperate, app.FuncDirectOperate:
			if !reflect.DeepEqual(first.Headers, rec.Headers) {
				what = append(what, fmt.Sprintf("echo %v, recorded %v", headerText(first.Headers), headerText(rec.Headers)))
			}
		default:
		}
		if len(what) > 0 {
			diff(req.Frame, "%s: %s", req.Frag, strings.Join(what, "; "))
		}
	}
	return diffs, requests, answered
}

func headerText(hs []app.Header) []string {
	var out []string
	for _, h := range hs {
		s := h.String()
		for _, o := range h.Objects {
			s += fmt.Sprintf(" [%d]%v", o.Index, o.Value)
		}
		out = append(out, s)
	}
	return slices.Clip(out)
}

// serverReplayExpected are the classified differences between go-dnp3's
// outstation and the recorded ones, by "file id:frame of the request".
var serverReplayExpected = map[string]string{
	"auth-change-session-keys:4":                 whyRestart,
	"auth-change-session-keys:6":                 whyRestart,
	"auth-control-challenge-response:1":          whyRestart,
	"auth-control-challenge-response:3":          whySa,
	"cold-restart-and-response:4":                whyRestart,
	"conformance-6-1-2:8":                        whyRestart,
	"conformance-6-1-2:10":                       whyRestart,
	"conformance-6-1-2:62":                       whyRestart,
	"conformance-6-1-2:72":                       whyRestart,
	"conformance-6-6-2-5:4":                      whyRestart,
	"conformance-6-6-2-5:6":                      whyRestart,
	"conformance-8-11-2-5:46":                    whyOrder,
	"conformance-8-11-2-5:54":                    whyOrder,
	"conformance-8-11-2-6:12":                    whyUnsol,
	"conformance-8-11-2-6:16":                    whyUnsol,
	"conformance-8-13-2-3:4":                     whyEmpty,
	"conformance-8-16-1-2-3:4":                   whyEmpty,
	"conformance-8-2-1-2-4:8":                    whyTimeout,
	"conformance-8-21-2-2:4":                     whyEmpty,
	"conformance-8-4-1-2-4:8":                    whyTimeout,
	"dataset-exchange:1":                         whyDataset,
	"dataset-exchange:3":                         whyDataset,
	"dataset-exchange:5":                         whyDataset,
	"direct-operate-analog-output:1":             whyRestart,
	"direct-operate-crob-malform-but-good-crc:1": whyRestart,
	"igbe-ddca-smart-grid-attacks:21880":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:21934":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:21982":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22027":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22070":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22117":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22164":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22207":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22254":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22304":         whyIgbe,
	"igbe-ddca-smart-grid-attacks:22373":         whyIgbe,
	"operate-aggressive-mode:1":                  whyAggr,
	"test-data-part1:163":                        whyRestart,
	"test-data-part1:166":                        whyRestart,
	"test-data-part2:19":                         whyG255,
	"test-data-part2:22":                         whyG255,
	"test-data-part2:25":                         whyG255,
	"test-data-part2:28":                         whyG255,
	"test-data-part2:31":                         whyG255,
	"warm-restart-and-response:4":                whyRestart,
	"write-binary-output:1":                      whyRestart,
	"write-vto-empty-string:2":                   whyRestart,
	"zeek-test-data-merged:163":                  whyRestart,
	"zeek-test-data-merged:166":                  whyRestart,
	"zeek-test-data-merged:200":                  whyG255,
	"zeek-test-data-merged:203":                  whyG255,
	"zeek-test-data-merged:206":                  whyG255,
	"zeek-test-data-merged:209":                  whyG255,
	"zeek-test-data-merged:212":                  whyG255,
}

// The classifications of serverReplayExpected.
const (
	whyAggr    = "unsupported configuration: aggressive mode secure authentication (g120v3/g120v9) without keys; the replay outstation has no secure authentication and answers IIN2.1"
	whyDataset = "unsupported feature: data sets (g0v213/g0v215 attributes, g85/g86) are not served by go-dnp3's outstation (LIMITATIONS.md)"
	whyEmpty   = "legitimate protocol variation: a READ of a point type with no points. The 2020 runner expects an empty response; go-dnp3 answers IIN2.1 as TB2016-001 and the DNP3 IED certification procedure 3.1r1 (Table 11-1) require"
	whyG255    = "vendor/implementation-specific difference: READ of an undefined group; the recorded outstation sets IIN2.1 and IIN2.2, go-dnp3 IIN2.1"
	whyIgbe    = "vendor/implementation-specific difference: injected COLD_RESTART of the attack scenario; the recorded outstation does not support it (IIN2.0), the replay outstation does"
	whyOrder   = "timing not reproduced: the procedure sends the next request before the answer (8.11.2.5, an outstanding unsolicited response); the replay waits for each answer"
	whyRestart = "vendor/implementation-specific difference: the recorded outstation does not support the restart (IIN2.0); the replay outstation does"
	whySa      = "unsupported configuration: secure authentication with keys not in the recording; the replay outstation runs without it (IIN2.0 for g120 requests)"
	whyTimeout = "timing not reproduced: the runner waited past the select timeout before OPERATE (TIMEOUT); the replay sends OPERATE at once"
	whyUnsol   = "vendor/implementation-specific difference: the recorded outstation runs this procedure without unsolicited responses (IIN2.0); the replay outstation has them"
)

// SPDX-License-Identifier: MIT

package client

import (
	"errors"
	"slices"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Two binary input events (g2v1) for index 0 and index 1: fragments that
// differ in their objects.
var (
	event0 = []byte{0x02, 0x01, 0x17, 0x01, 0x00, 0x81}
	event1 = []byte{0x02, 0x01, 0x17, 0x01, 0x01, 0x81}
)

// ctl returns an application control octet's fields.
func ctl(fir, fin, con bool, seq uint8) app.Control {
	return app.Control{FIR: fir, FIN: fin, CON: con, Seq: seq & 0x0F}
}

// confirms returns the confirmations the master sent so far.
func (o *specOutstation) confirms() []app.Control {
	var out []app.Control
	for _, f := range o.sent() {
		if f.f.Function == app.FuncConfirm {
			out = append(out, f.f.Control)
		}
	}
	return out
}

// TestSpec4_3_Rule14_SequenceIncrements: IEEE 1815-2012 clause 4.3 Rule 14
// (printed page 39): "For each new, non-retry request fragment it sends, a
// master shall increment the SEQ number by one count (modulo 16) from its
// previous request fragment." The count goes on across a wrap, a broadcast
// and a request the client refuses before sending it (WithMaxRequestFragment
// or an invalid command), which leaves no gap.
func TestSpec4_3_Rule14_SequenceIncrements(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		if req.f.Function.NoAck() {
			return nil
		}
		return [][]byte{empty(req, 0)}
	})
	c := specDial(t, o, append(quiet, WithMaxRequestFragment(249))...)
	tooLong := make([]app.Header, 100) // 2 + 3*100 octets
	for i := range tooLong {
		tooLong[i] = app.AllObjects(app.G1V0)
	}
	for i := range 20 {
		switch i {
		case 5:
			if _, err := c.Read(testCtx(t), tooLong...); !errors.Is(err, dnp3.ErrInvalidOption) {
				t.Fatalf("oversize request: %v", err)
			}
		case 9:
			if _, err := c.Operate(testCtx(t), DirectOperate, Command{Index: 0, Value: app.CROB{Queue: true}}); !errors.Is(err, dnp3.ErrInvalidOption) {
				t.Fatalf("invalid command: %v", err)
			}
		case 12:
			crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
			if err := c.Broadcast(testCtx(t), link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, crob); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Read(testCtx(t), app.ClassHeaders(0)...); err != nil {
			t.Fatal(err)
		}
	}
	var seqs []uint8
	for _, f := range o.sent() {
		seqs = append(seqs, f.f.Control.Seq)
	}
	if len(seqs) != 21 {
		t.Fatalf("%d requests, want 21 (20 reads and a broadcast): %v", len(seqs), o.requests())
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != app.NextSeq(seqs[i-1]) {
			t.Fatalf("sequence numbers %v", seqs)
		}
	}
}

// TestSpec4_3_Rule11_RequestsWithoutCON: clause 4.3 Rule 11 (p. 39):
// "Masters shall never request Application Layer confirmation; i.e., they
// shall not set the CON bit in request messages", and clause 4.2.2.4.4
// (p. 22) sets UNS only in unsolicited responses and their confirmations.
// Every request is a single fragment (Rule 4: FIR and FIN).
func TestSpec4_3_Rule11_RequestsWithoutCON(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		switch {
		case req.f.Function.NoAck():
			return nil
		case req.f.Function == app.FuncSelect || req.f.Function == app.FuncOperate:
			return [][]byte{echo(req, 0)}
		case req.f.Function == app.FuncDelayMeasure:
			return [][]byte{frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, 0, []byte{0x34, 0x02, 0x07, 0x01, 0x00, 0x00})}
		}
		return [][]byte{empty(req, 0)}
	})
	c := specDial(t, o, quiet...)
	ctx := testCtx(t)
	steps := []func() error{
		func() error { _, err := c.IntegrityPoll(ctx); return err },
		func() error { _, err := c.Operate(ctx, SelectBeforeOperate, CROB(0, app.OpLatchOn, 0, 0)); return err },
		func() error { _, err := c.Operate(ctx, DirectOperateNoAck, CROB(0, app.OpLatchOn, 0, 0)); return err },
		func() error { return c.SyncTime(ctx, TimeSyncLAN) },
		func() error { return c.SyncTime(ctx, TimeSyncNonLAN) },
		func() error { return c.ClearRestart(ctx) },
		func() error { return c.EnableUnsolicited(ctx) },
		func() error {
			crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
			return c.Broadcast(ctx, link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, crob)
		},
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	sent := o.sent()
	if len(sent) < len(steps) {
		t.Fatalf("requests %v", o.requests())
	}
	for _, f := range sent {
		if cc := f.f.Control; cc.CON || cc.UNS || !cc.FIR || !cc.FIN {
			t.Errorf("%s: control %s", f.f.Function, cc)
		}
	}
}

// TestSpec4_3_Rule18_ConfirmEachFragment: clause 4.3 Rule 18 (p. 39): "A
// fragment containing a CONFIRM function code shall use the same SEQ
// number and UNS bit state as are in the fragment being confirmed": each
// fragment of a multi-fragment response is confirmed with its own SEQ
// (Rule 15: N, N+1, N+2).
func TestSpec4_3_Rule18_ConfirmEachFragment(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		n := req.f.Control.Seq
		return [][]byte{
			frag(ctl(true, false, true, n), app.FuncResponse, 0, event0),
			frag(ctl(false, false, true, n+1), app.FuncResponse, 0, event1),
			frag(ctl(false, true, true, n+2), app.FuncResponse, 0, event0),
		}
	})
	c := specDial(t, o, quiet...)
	for k := range 6 { // across a wrap of the sequence numbers
		res, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
		if err != nil || len(res.Fragments) != 3 {
			t.Fatalf("multi-fragment response: %v %v", res, err)
		}
		n := res.Fragments[0].Control.Seq
		got := o.waitConfirms(t, 3*(k+1))[3*k:]
		for i, cc := range got {
			if cc.Seq != (n+uint8(i))&0x0F || cc.UNS || !cc.FIR || !cc.FIN || cc.CON {
				t.Fatalf("confirmations %v of the fragments %d..%d", got, n, n+2)
			}
		}
	}
}

// TestSpec4_3_Rule13_ConfirmBeforeNextRequest: clause 4.3 Rule 13 (p. 39):
// "Masters that receive a properly formatted fragment with the CON bit set
// shall respond with an Application Layer confirm message before sending
// any other request message to that outstation".
func TestSpec4_3_Rule13_ConfirmBeforeNextRequest(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		return [][]byte{frag(ctl(true, true, true, req.f.Control.Seq), app.FuncResponse, 0, event0)}
	})
	c := specDial(t, o, quiet...)
	for range 5 {
		if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); err != nil {
			t.Fatal(err)
		}
	}
	sent := o.waitLog(t, "five confirmations", func(sent []specFrag) bool { return len(sent) == 10 })
	for i := 0; i+1 < len(sent); i += 2 {
		req, conf := sent[i].f, sent[i+1].f
		if req.Function != app.FuncRead || conf.Function != app.FuncConfirm || conf.Control.Seq != req.Control.Seq {
			t.Fatalf("fragment %d and %d: %s, %s", i, i+1, req, conf)
		}
	}
}

// TestSpec4_3_Rule4_RequestFragmentLimit: clause 4.3 Rule 4 (p. 39):
// "Master devices shall only send requests that fit within a single
// fragment. Any master that is capable of sending fragments larger than
// 249 octets shall be configurable to restrict the maximum fragment size
// of all requests to 249 octets." With WithMaxRequestFragment(249) a
// request of 249 octets goes, one of 250 fails with dnp3.ErrInvalidOption
// and nothing is sent (MASTER-7, APPSTRUCT-5); a limit below 249 is
// refused. Without the option there is no limit.
func TestSpec4_3_Rule4_RequestFragmentLimit(t *testing.T) {
	// headers returns READ headers that make a request of n octets:
	// 2 + 3 per AllObjects + 4 per CountOf.
	headers := func(all, counts int) []app.Header {
		var hs []app.Header
		for range all {
			hs = append(hs, app.AllObjects(app.G1V0))
		}
		for range counts {
			hs = append(hs, app.CountOf(app.G2V0, 5))
		}
		return hs
	}
	at249, at250 := headers(81, 1), headers(80, 2)
	for _, tc := range []struct {
		hs []app.Header
		n  int
	}{{at249, 249}, {at250, 250}} {
		b, err := (&app.Fragment{Function: app.FuncRead, Headers: tc.hs}).Encode()
		if err != nil || len(b) != tc.n {
			t.Fatalf("test request of %d octets: %d %v", tc.n, len(b), err)
		}
	}

	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
	c := specDial(t, o, append(quiet, WithMaxRequestFragment(249))...)
	if _, err := c.Read(testCtx(t), at249...); err != nil {
		t.Fatalf("request of 249 octets: %v", err)
	}
	if _, err := c.Read(testCtx(t), at250...); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("request of 250 octets: %v", err)
	}
	var many []Command
	for i := range 30 { // 2 + 4 + 30*12 octets
		many = append(many, CROB(uint32(i), app.OpLatchOn, 0, 0))
	}
	for _, mode := range []CommandMode{SelectBeforeOperate, DirectOperate, DirectOperateNoAck} {
		if _, err := c.Operate(testCtx(t), mode, many...); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Fatalf("control request over the limit, mode %d: %v", mode, err)
		}
	}
	if got := o.requests(); !slices.Equal(got, []app.FunctionCode{app.FuncRead}) {
		t.Fatalf("requests %v", got)
	}
	for _, n := range []int{-1, 0, 248} {
		if _, err := New("h", WithMaxRequestFragment(n)); !errors.Is(err, dnp3.ErrInvalidOption) {
			t.Fatalf("WithMaxRequestFragment(%d): %v", n, err)
		}
	}

	// No limit by default.
	p := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
	d := specDial(t, p, quiet...)
	if _, err := d.Read(testCtx(t), at250...); err != nil {
		t.Fatalf("request of 250 octets without a limit: %v", err)
	}
}

// TestSpecTable6_2_Row1_LateResponseDiscarded: clause 6.3, Table 6-2 row 1
// (printed page 165): in the Idle state a fragment is discarded and not
// confirmed. A response that arrives after the response timeout (row 7)
// is not confirmed and not taken for the next request's.
func TestSpecTable6_2_Row1_LateResponseDiscarded(t *testing.T) {
	timedOut := make(chan struct{})
	first := true
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		if first {
			// Answered once the master gave up, before the next request.
			first = false
			select {
			case <-timedOut:
			case <-time.After(5 * time.Second):
			}
			return [][]byte{frag(ctl(true, true, true, req.f.Control.Seq), app.FuncResponse, 0, event0)}
		}
		return [][]byte{frag(ctl(true, true, false, req.f.Control.Seq), app.FuncResponse, 0, event1)}
	})
	c := specDial(t, o, append(quiet, WithResponseTimeout(100*time.Millisecond))...)
	if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("unanswered read: %v", err)
	}
	close(timedOut)
	res, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
	if err != nil || len(res.Fragments) != 1 || res.Measurements()[0].Index != 1 {
		t.Fatalf("read after a late response: %v %v", res, err)
	}
	if cs := o.confirms(); len(cs) != 0 {
		t.Fatalf("late response confirmed: %v", cs)
	}
}

// TestSpecTable6_2_Rows3_5_AwaitFirstDiscards: Table 6-2 rows 3 and 5
// (p. 165): awaiting the first fragment, one without FIR (row 3) or with
// another SEQ than the request's (row 5) is discarded and not confirmed,
// and the master goes on waiting; the right one is then accepted (row 6).
func TestSpecTable6_2_Rows3_5_AwaitFirstDiscards(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		n := req.f.Control.Seq
		return [][]byte{
			frag(ctl(false, true, true, n), app.FuncResponse, 0, event1),   // row 3
			frag(ctl(true, true, true, n+3), app.FuncResponse, 0, event1),  // row 5
			frag(ctl(true, false, true, n-1), app.FuncResponse, 0, event1), // row 5
			frag(ctl(true, true, true, n), app.FuncResponse, 0, event0),    // row 6
		}
	})
	c := specDial(t, o, quiet...)
	res, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
	if err != nil || len(res.Fragments) != 1 || res.Measurements()[0].Index != 0 {
		t.Fatalf("response: %v %v", res, err)
	}
	// A confirmation of a discarded fragment would come first.
	if cs := o.waitConfirms(t, 1); len(cs) != 1 || cs[0].Seq != res.Fragments[0].Control.Seq {
		t.Fatalf("confirmations %v", cs)
	}
}

// TestSpecTable6_2_Rows8_14_RepeatConfirmedAgain: Table 6-2 rows 8 and 14
// (p. 165): during a multi-fragment response, a fragment whose octets match
// the previously accepted fragment is confirmed again if requested, and
// assembly goes on with the fragment timer restarted (MASTER-11).
func TestSpecTable6_2_Rows8_14_RepeatConfirmedAgain(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frags func(n uint8) [][]byte
		seqs  []uint8 // confirmed, relative to N
		count int
	}{
		{"row 14: the first fragment repeated", func(n uint8) [][]byte {
			first := frag(ctl(true, false, true, n), app.FuncResponse, 0, event0)
			return [][]byte{first, first, frag(ctl(false, true, true, n+1), app.FuncResponse, 0, event1)}
		}, []uint8{0, 0, 1}, 2},
		{"row 8: a middle fragment repeated", func(n uint8) [][]byte {
			middle := frag(ctl(false, false, true, n+1), app.FuncResponse, 0, event1)
			return [][]byte{frag(ctl(true, false, true, n), app.FuncResponse, 0, event0), middle, middle,
				frag(ctl(false, true, true, n+2), app.FuncResponse, 0, event0)}
		}, []uint8{0, 1, 1, 2}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newSpecOutstation(t, func(req specFrag) [][]byte { return tc.frags(req.f.Control.Seq) })
			c := specDial(t, o, quiet...)
			res, err := c.Read(testCtx(t), app.ClassHeaders(1)...)
			if err != nil || len(res.Fragments) != tc.count {
				t.Fatalf("response: %v %v", res, err)
			}
			n := res.Fragments[0].Control.Seq
			var got []uint8
			for _, cc := range o.waitConfirms(t, len(tc.seqs)) {
				got = append(got, (cc.Seq-n)&0x0F)
			}
			if !slices.Equal(got, tc.seqs) {
				t.Fatalf("confirmed N+%v, want N+%v", got, tc.seqs)
			}
		})
	}
}

// TestSpecTable6_2_AssemblyAbandoned: Table 6-2 rows 8, 9, 11, 13 and 14
// to 17 (pp. 165-166): during a multi-fragment response, a fragment that
// is neither the next one (SEQ N+1 without FIR) nor an exact repeat of the
// last one is discarded and not confirmed, and the master returns to Idle:
// the response is abandoned, with dnp3.ErrProtocol (MASTER-10). The table
// is introduced with "should" (clause 6.3, p. 163).
func TestSpecTable6_2_AssemblyAbandoned(t *testing.T) {
	for _, tc := range []struct {
		row  string
		bad  func(n uint8) [][]byte // after the first fragment N (FIR, CON)
		good int                    // fragments accepted before the bad one
	}{
		{"8: FIR=0 with the SEQ of the last fragment, other octets", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(false, false, true, n+1), app.FuncResponse, 0, event1),
				frag(ctl(false, false, true, n+1), app.FuncResponse, 0, event0)}
		}, 2},
		{"9: FIR=0 SEQ=N after the first fragment", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(false, false, true, n), app.FuncResponse, 0, event1)}
		}, 1},
		{"11: FIR=0 FIN=0 SEQ=N+3", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(false, false, true, n+3), app.FuncResponse, 0, event1)}
		}, 1},
		{"13: FIR=0 FIN=1 SEQ=N", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(false, true, true, n), app.FuncResponse, 0, event1)}
		}, 1},
		{"14: FIR=1 SEQ=N other octets", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(true, false, true, n), app.FuncResponse, 0, event1)}
		}, 1},
		{"15: FIR=1 SEQ=N after FIR=0", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(false, false, true, n+1), app.FuncResponse, 0, event1),
				frag(ctl(true, false, true, n+1), app.FuncResponse, 0, event0)}
		}, 2},
		{"16: FIR=1 FIN=0 SEQ=N+1", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(true, false, true, n+1), app.FuncResponse, 0, event1)}
		}, 1},
		{"17: FIR=1 FIN=1", func(n uint8) [][]byte {
			return [][]byte{frag(ctl(true, true, true, n+1), app.FuncResponse, 0, event1)}
		}, 1},
	} {
		t.Run("row "+tc.row, func(t *testing.T) {
			o := newSpecOutstation(t, func(req specFrag) [][]byte {
				n := req.f.Control.Seq
				out := [][]byte{frag(ctl(true, false, true, n), app.FuncResponse, 0, event0)}
				out = append(out, tc.bad(n)...)
				// The rest of the response, which the master no longer
				// waits for.
				return append(out, frag(ctl(false, true, true, n+uint8(tc.good)), app.FuncResponse, 0, event0))
			})
			c := specDial(t, o, quiet...)
			if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); !errors.Is(err, dnp3.ErrProtocol) {
				t.Fatalf("response with an unexpected fragment: %v", err)
			}
			// Only the fragments accepted before were confirmed; the
			// discarded one and the rest, received in Idle, were not. The
			// second read, answered alike, comes after the rest on the
			// stream.
			if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); !errors.Is(err, dnp3.ErrProtocol) {
				t.Fatalf("second read: %v", err)
			}
			// The confirmations of the second response's accepted
			// fragments follow its READ.
			o.waitLog(t, "the second response's confirmations", func(sent []specFrag) bool {
				reads, after := 0, 0
				for _, f := range sent {
					switch {
					case f.f.Function == app.FuncRead:
						reads++
					case reads == 2:
						after++
					}
				}
				return after >= tc.good
			})
			if cs := o.confirms(); len(cs) != 2*tc.good {
				t.Fatalf("confirmations %v, want %d", cs, 2*tc.good)
			}
		})
	}
}

// TestSpecTable6_2_Row18_FragmentTimeout: Table 6-2 row 18 (p. 166): when
// the response timer expires during a multi-fragment response, the master
// notes the lack of response and returns to Idle.
func TestSpecTable6_2_Row18_FragmentTimeout(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		return [][]byte{frag(ctl(true, false, true, req.f.Control.Seq), app.FuncResponse, 0, event0)}
	})
	c := specDial(t, o, append(quiet, WithResponseTimeout(100*time.Millisecond))...)
	if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("incomplete response: %v", err)
	}
}

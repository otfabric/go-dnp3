// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// writtenTime returns the time of the g50 object of a WRITE request.
func writtenTime(f *app.Fragment) (time.Time, app.GroupVariation, bool) {
	if f.Function != app.FuncWrite || len(f.Headers) != 1 || len(f.Headers[0].Objects) != 1 {
		return time.Time{}, 0, false
	}
	at, ok := f.Headers[0].Objects[0].Value.(app.AbsoluteTime)
	return at.Time.Time(), f.Headers[0].GV, ok
}

// delayResponse is the response to DELAY_MEASURE with a fine time delay
// object (g52v2) of d.
func delayResponse(seq uint8, iin app.IIN, d time.Duration) []byte {
	ms := uint16(d / time.Millisecond)
	return frag(app.SingleControl(seq), app.FuncResponse, iin, []byte{0x34, 0x02, 0x07, 0x01, byte(ms), byte(ms >> 8)})
}

// timeAnswer answers the time synchronization requests as an outstation
// that supports them, and every other request with no objects; iin is
// set in every response.
func timeAnswer(iin func() app.IIN) func(req specFrag) [][]byte {
	return func(req specFrag) [][]byte {
		if req.f.Function == app.FuncDelayMeasure {
			return [][]byte{delayResponse(req.f.Control.Seq, iin(), 0)}
		}
		return [][]byte{empty(req, iin())}
	}
}

// TestSpec10_3_4_1_UnconfirmedUserData: IEEE 1815-2012 clause 10.3.4.1
// (printed page 303): "Both master and outstations shall transport time
// synchronization messages using Data Link Layer function code
// UNCONFIRMED_USER_DATA", and shall not retry them at the Data Link Layer:
// DELAY_MEASURE, RECORD_CURRENT_TIME and a WRITE of g50v1 or g50v3, also
// with Link{Confirmed: true}, where the other requests go as
// CONFIRMED_USER_DATA (MASTER-9).
func TestSpec10_3_4_1_UnconfirmedUserData(t *testing.T) {
	o := newSpecOutstation(t, timeAnswer(func() app.IIN { return 0 }))
	m := &frameMetrics{}
	c := specDial(t, o, append(specQuiet, WithMetrics(m), WithLink(Link{Confirmed: true, Retries: 2}))...)
	ctx := testCtx(t)
	if err := c.SyncTime(ctx, TimeSyncLAN); err != nil {
		t.Fatal(err)
	}
	if err := c.SyncTime(ctx, TimeSyncNonLAN); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.DelayMeasure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteTime(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.IntegrityPoll(ctx); err != nil {
		t.Fatal(err)
	}
	ud := m.userData()
	for fc, n := range map[app.FunctionCode]int{app.FuncRecordCurrentTime: 1, app.FuncDelayMeasure: 2, app.FuncWrite: 3} {
		if got := ud[fc]; len(got) != n || slices.ContainsFunc(got, func(f link.Function) bool { return f != link.PrimaryUnconfirmedUserData }) {
			t.Errorf("%s sent as %v, want %d UNCONFIRMED_USER_DATA", fc, got, n)
		}
	}
	if got := ud[app.FuncRead]; !slices.Equal(got, []link.Function{link.PrimaryConfirmedUserData}) {
		t.Errorf("READ sent as %v, want CONFIRMED_USER_DATA", got)
	}
}

// TestSpec10_3_4_1_RetryIsNewRequest: clause 10.3.4.1 (pp. 303-304):
// "Masters and outstations shall not retry time synchronization messages
// at either the Application or Data Link Layers"; "If a master does not
// receive the expected response on the first try, it shall send a new
// request and not retry the message. New requests have a different
// sequence number". Under WithRetry a failed procedure starts again from
// its first request, with the next sequence numbers and a fresh time.
func TestSpec10_3_4_1_RetryIsNewRequest(t *testing.T) {
	for _, tc := range []struct {
		p    TimeSync
		drop app.FunctionCode // the request left unanswered the first time
		want []app.FunctionCode
	}{
		{TimeSyncLAN, app.FuncWrite, []app.FunctionCode{app.FuncRecordCurrentTime, app.FuncWrite, app.FuncRecordCurrentTime, app.FuncWrite}},
		{TimeSyncNonLAN, app.FuncDelayMeasure, []app.FunctionCode{app.FuncDelayMeasure, app.FuncDelayMeasure, app.FuncWrite}},
		{TimeSyncNonLAN, app.FuncWrite, []app.FunctionCode{app.FuncDelayMeasure, app.FuncWrite, app.FuncDelayMeasure, app.FuncWrite}},
	} {
		dropped := false
		answer := timeAnswer(func() app.IIN { return 0 })
		o := newSpecOutstation(t, func(req specFrag) [][]byte {
			if req.f.Function == tc.drop && !dropped {
				dropped = true
				return nil
			}
			return answer(req)
		})
		c := specDial(t, o, append(specQuiet, WithResponseTimeout(100*time.Millisecond),
			WithRetry(Retry{Attempts: 2, Backoff: 10 * time.Millisecond}))...)
		if err := c.SyncTime(testCtx(t), tc.p); err != nil {
			t.Fatalf("procedure %d: %v", tc.p, err)
		}
		sent := o.sent()
		if got := o.requests(); !slices.Equal(got, tc.want) {
			t.Fatalf("procedure %d: requests %v, want %v", tc.p, got, tc.want)
		}
		var times []time.Time
		for i, f := range sent {
			if i > 0 && f.f.Control.Seq != app.NextSeq(sent[i-1].f.Control.Seq) {
				t.Fatalf("procedure %d: sequence numbers of %v", tc.p, o.requests())
			}
			if at, _, ok := writtenTime(f.f); ok {
				times = append(times, at)
			}
		}
		if len(times) == 2 && !times[1].After(times[0]) {
			t.Fatalf("procedure %d: the repeated WRITE has the time of the first, %v", tc.p, times)
		}
	}
}

// TestSpec10_3_4_1_WriteTimeNotRetried: clause 10.3.4.1 (p. 303): a WRITE
// with a g50v1 object is not retried at the application layer; WriteTime,
// which carries a time the application chose, is sent once under
// WithRetry.
func TestSpec10_3_4_1_WriteTimeNotRetried(t *testing.T) {
	o := newSpecOutstation(t, func(specFrag) [][]byte { return nil })
	c := specDial(t, o, append(specQuiet, WithResponseTimeout(100*time.Millisecond),
		WithRetry(Retry{Attempts: 3, Backoff: 10 * time.Millisecond}))...)
	if err := c.WriteTime(testCtx(t), time.Now()); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("unanswered WRITE: %v", err)
	}
	if got := o.requests(); !slices.Equal(got, []app.FunctionCode{app.FuncWrite}) {
		t.Fatalf("requests %v", got)
	}
}

// TestSpec4_4_15_DelayMeasureRoundTrip: clause 4.4.15 (p. 64): the master
// measures the round trip of the DELAY_MEASURE that is answered, and
// clause 10.3.4.2 (p. 304) explains that a retry measured from the first
// try gives a wrong delay. Under WithRetry the second, answered request
// is a new one (clause 4.4.15.1 Rule 1, p. 65) and the round trip is its
// own (MASTER-8).
func TestSpec4_4_15_DelayMeasureRoundTrip(t *testing.T) {
	first := true
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		if first {
			first = false
			return nil
		}
		return [][]byte{delayResponse(req.f.Control.Seq, 0, 5*time.Millisecond)}
	})
	c := specDial(t, o, append(specQuiet, WithResponseTimeout(200*time.Millisecond),
		WithRetry(Retry{Attempts: 2, Backoff: 50 * time.Millisecond}))...)
	processing, rtt, err := c.DelayMeasure(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if processing != 5*time.Millisecond || rtt <= 0 || rtt >= 200*time.Millisecond {
		t.Fatalf("processing %v, round trip %v: the round trip includes the failed attempt", processing, rtt)
	}
	sent := o.sent()
	if len(sent) != 2 || sent[1].f.Control.Seq != app.NextSeq(sent[0].f.Control.Seq) {
		t.Fatalf("requests %v", o.requests())
	}
}

// TestSpec10_3_3_1_NonLANDelay: clause 10.3.3.1 e) and f) (pp. 300-301):
// the master computes the propagation delay as "(Time at [D] – Time at
// [A] – outstation processing delay) / 2" and writes g50v1 with the time
// it will be when the WRITE arrives: the current time plus that delay.
// An outstation that answers after 200 ms and reports 200 ms of
// processing gets about the time at which it receives the WRITE, not
// 100 ms ahead.
func TestSpec10_3_3_1_NonLANDelay(t *testing.T) {
	var mu sync.Mutex
	var received, written time.Time
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		switch req.f.Function {
		case app.FuncDelayMeasure:
			time.Sleep(200 * time.Millisecond) // the processing delay the outstation reports
			return [][]byte{delayResponse(req.f.Control.Seq, 0, 200*time.Millisecond)}
		case app.FuncWrite:
			mu.Lock()
			received = time.Now()
			written, _, _ = writtenTime(req.f)
			mu.Unlock()
		default:
			// Nothing to record.
		}
		return [][]byte{empty(req, 0)}
	})
	c := specDial(t, o, specQuiet...)
	if err := c.SyncTime(testCtx(t), TimeSyncNonLAN); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if d := written.Sub(received); d < -30*time.Millisecond || d > 30*time.Millisecond {
		t.Fatalf("written time %v off the time of receipt by %v", written, d)
	}
	if _, gv, _ := writtenTime(o.sent()[1].f); gv != app.G50V1 {
		t.Fatalf("WRITE of %s", gv)
	}
}

// TestSpec10_3_3_2_LANRecordedTime: clause 10.3.3.2 a) and d) (pp. 302-303):
// the master records the time when the last octet of RECORD_CURRENT_TIME
// leaves ([A]) and writes that time in a g50v3 object. The client takes it
// when the link layer has written the request, as close to the stack as
// it can (NOTE 3, p. 303): a time after the call, about when the
// outstation received the request, and before it received the WRITE.
func TestSpec10_3_3_2_LANRecordedTime(t *testing.T) {
	var mu sync.Mutex
	var recorded, written time.Time
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		switch req.f.Function {
		case app.FuncRecordCurrentTime:
			recorded = time.Now()
		case app.FuncWrite:
			written = time.Now()
		default:
			// Nothing to record.
		}
		return [][]byte{empty(req, 0)}
	})
	c := specDial(t, o, specQuiet...)
	before := time.Now().Truncate(time.Millisecond)
	if err := c.SyncTime(testCtx(t), TimeSyncLAN); err != nil {
		t.Fatal(err)
	}
	sent := o.sent()
	at, gv, ok := writtenTime(sent[1].f)
	mu.Lock()
	defer mu.Unlock()
	if !ok || gv != app.G50V3 || at.Before(before) || at.After(written) || at.Sub(recorded).Abs() > 20*time.Millisecond {
		t.Fatalf("g50v3 %v (%s): call at %v, RECORD_CURRENT_TIME received at %v, WRITE at %v", at, gv, before, recorded, written)
	}
}

// needTimeOutstation answers as an outstation that reports NEED_TIME
// (IIN1.4) until a time synchronization WRITE or a WRITE that clears the
// indication; rejected are the functions refused answers with IIN2.0.
func needTimeOutstation(t *testing.T, refused ...app.FunctionCode) *specOutstation {
	t.Helper()
	var mu sync.Mutex
	need := true
	iin := func() app.IIN {
		mu.Lock()
		defer mu.Unlock()
		if need {
			return app.IINNeedTime
		}
		return 0
	}
	answer := timeAnswer(iin)
	return newSpecOutstation(t, func(req specFrag) [][]byte {
		if slices.Contains(refused, req.f.Function) {
			return [][]byte{empty(req, iin()|app.IINNoFuncCodeSupport)}
		}
		if req.f.Function == app.FuncWrite {
			mu.Lock()
			need = false
			mu.Unlock()
		}
		return answer(req)
	})
}

// timeRequests returns the time synchronization requests among the
// fragments the master sent: their function code and, for a WRITE, the
// object written.
func timeRequests(sent []specFrag) []string {
	var out []string
	for _, f := range sent {
		switch f.f.Function {
		case app.FuncDelayMeasure, app.FuncRecordCurrentTime:
			out = append(out, f.f.Function.String())
		case app.FuncWrite:
			out = append(out, f.f.Function.String()+" "+f.f.Headers[0].GV.String())
		default:
			// Not a time synchronization message.
		}
	}
	return out
}

// plainStream hides that a stream is a net.Conn: a serial line, say.
type plainStream struct{ io.ReadWriteCloser }

// TestSpec4_5_5_NeedTimeAnswered: clause 4.5.5 (printed page 83): "If the
// outstation sets this bit, the master shall promptly perform a write time
// sequence", and clause 10.3.3 (p. 299): "The master shall send the time
// promptly after receiving a response with this bit set." By default the
// client does: with the LAN procedure (clause 10.3.3.2) over a network
// connection and with the non-LAN procedure (clause 10.3.3.1) over other
// streams (MASTER-5, APPSTRUCT-12).
func TestSpec4_5_5_NeedTimeAnswered(t *testing.T) {
	o := needTimeOutstation(t)
	specDial(t, o) // the default options
	want := []string{"RECORD_CURRENT_TIME", "WRITE g50v3"}
	o.waitLog(t, "a LAN time synchronization", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 2 })
	if got := timeRequests(o.sent()); !slices.Equal(got, want) {
		t.Fatalf("over TCP: %v, want %v", got, want)
	}

	s := needTimeOutstation(t)
	open := func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return nil, nil, err
		}
		return plainStream{conn}, conn.RemoteAddr(), nil
	}
	c, err := Dial(testCtx(t), "serial", WithStream(open), WithResponseTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	want = []string{"DELAY_MEASURE", "WRITE g50v1"}
	s.waitLog(t, "a non-LAN time synchronization", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 2 })
	if got := timeRequests(s.sent()); !slices.Equal(got, want) {
		t.Fatalf("over a stream: %v, want %v", got, want)
	}
}

// TestSpec4_5_5_NeedTimeFallback: clause 4.5.5 (p. 83): an outstation that
// sets IIN1.4 shall support time synchronization messages, but subset
// levels 1 to 3 do not include the LAN procedure's RECORD_CURRENT_TIME
// and g50v3 (IEEE 1815-2012 Tables 12-1 and 14-2 to 14-4). When the
// outstation refuses the LAN procedure as not supported (IIN2.0), the
// client's own default switches to the non-LAN procedure; when it refuses
// that too, automatic time synchronization stops for the connection.
func TestSpec4_5_5_NeedTimeFallback(t *testing.T) {
	o := needTimeOutstation(t, app.FuncRecordCurrentTime)
	specDial(t, o, WithAutoIntegrity(false))
	want := []string{"RECORD_CURRENT_TIME", "DELAY_MEASURE", "WRITE g50v1"}
	o.waitLog(t, "the non-LAN procedure", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 3 })
	if got := timeRequests(o.sent()); !slices.Equal(got, want) {
		t.Fatalf("time requests %v, want %v", got, want)
	}

	// Neither procedure: the client stops, though NEED_TIME stays set.
	p := needTimeOutstation(t, app.FuncRecordCurrentTime, app.FuncDelayMeasure)
	c := specDial(t, p, WithAutoIntegrity(false))
	want = []string{"RECORD_CURRENT_TIME", "DELAY_MEASURE"}
	p.waitLog(t, "both procedures", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 2 })
	for range 3 {
		if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); err != nil {
			t.Fatal(err)
		}
	}
	if got := timeRequests(p.sent()); !slices.Equal(got, want) {
		t.Fatalf("time requests %v, want %v", got, want)
	}

	// A procedure the application chose is not changed.
	q := needTimeOutstation(t, app.FuncRecordCurrentTime)
	d := specDial(t, q, WithAutoIntegrity(false), WithTimeSync(TimeSyncLAN))
	q.waitLog(t, "the LAN procedure", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 1 })
	if _, err := d.Read(testCtx(t), app.ClassHeaders(1)...); err != nil {
		t.Fatal(err)
	}
	q.waitLog(t, "the LAN procedure again", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 2 })
	if got := timeRequests(q.sent()); slices.Contains(got, "DELAY_MEASURE") {
		t.Fatalf("time requests %v with WithTimeSync(TimeSyncLAN)", got)
	}
}

// TestSpec4_5_5_NeedTimeOptions: clause 4.5.5 (p. 83): "If timekeeping is
// not required in the system, the master should simply issue a write
// request to clear IIN1.4": WithTimeSync(TimeSyncClearNeedTime) does
// that, with g80v1 index 4; ClearNeedTime sends the same request.
// WithTimeSync(TimeSyncNone) leaves NEED_TIME to the application.
func TestSpec4_5_5_NeedTimeOptions(t *testing.T) {
	clear4 := []byte{0x02, 0x50, 0x01, 0x00, 0x04, 0x04, 0x00}
	o := needTimeOutstation(t)
	c := specDial(t, o, WithAutoIntegrity(false), WithTimeSync(TimeSyncClearNeedTime))
	sent := o.waitLog(t, "the WRITE clearing IIN1.4", func(sent []specFrag) bool { return len(timeRequests(sent)) >= 1 })
	w := sent[len(sent)-1]
	if !bytes.Equal(w.raw[1:], clear4) || timeRequests(sent)[0] != "WRITE g80v1" {
		t.Fatalf("request % x, want C? % x", w.raw, clear4)
	}
	if err := c.ClearNeedTime(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if last := o.sent()[len(o.sent())-1]; !bytes.Equal(last.raw[1:], clear4) {
		t.Fatalf("ClearNeedTime: % x", last.raw)
	}
	if err := c.SyncTime(testCtx(t), TimeSyncClearNeedTime); err != nil {
		t.Fatal(err)
	}
	if last := o.sent()[len(o.sent())-1]; !bytes.Equal(last.raw[1:], clear4) {
		t.Fatalf("SyncTime(TimeSyncClearNeedTime): % x", last.raw)
	}

	p := needTimeOutstation(t)
	d := specDial(t, p, WithAutoIntegrity(false), WithTimeSync(TimeSyncNone))
	for range 3 {
		if _, err := d.Read(testCtx(t), app.ClassHeaders(1)...); err != nil {
			t.Fatal(err)
		}
	}
	p.none(t, 100*time.Millisecond)
	if got := timeRequests(p.sent()); len(got) != 0 {
		t.Fatalf("time requests %v with TimeSyncNone", got)
	}
	if err := d.SyncTime(testCtx(t), TimeSync(9)); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("SyncTime with an unknown procedure: %v", err)
	}
	if _, err := New("h", WithTimeSync(TimeSync(9))); !errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("WithTimeSync with an unknown procedure: %v", err)
	}
}

// TestSpec4_5_8_ClearRestartOctets: clauses 4.5.8 (p. 84) and 5.1.1.1.1
// Rule 1 (p. 101): the master clears IIN1.7 by writing 0 to g80v1 index 7,
// as in example EX 4-14: C? 02 50 01 00 07 07 00.
func TestSpec4_5_8_ClearRestartOctets(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{empty(req, 0)} })
	c := specDial(t, o, specQuiet...)
	if err := c.ClearRestart(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	sent := o.sent()
	if len(sent) != 1 || !bytes.Equal(sent[0].raw[1:], []byte{0x02, 0x50, 0x01, 0x00, 0x07, 0x07, 0x00}) {
		t.Fatalf("request % x", sent[0].raw)
	}
}

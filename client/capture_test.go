// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/capture"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// The client replay runs go-dnp3's master against recorded outstation
// replies (testdata/captures/README.md): for every recorded request with a
// recorded response, the client sends the same request with Request, a
// replay outstation checks the request against the recorded one and answers
// with the recorded response fragments, and the client's Result is compared
// with the recorded response as app.Decode reads it.
//
// Comparison rules:
//   - The application sequence number is dynamic: the replay outstation
//     answers with the recorded fragments' octets, the sequence number
//     replaced by the client's (the control octet's low four bits). Nothing
//     else is changed; the frames are segmented and encoded anew with the
//     recorded link addresses, the user data octets are the recorded ones.
//   - The client's request must equal the recorded request octet for octet
//     apart from the sequence number: a difference is an encoder difference.
//   - The client must accept the recorded response: the Result's fragments
//     must be the recorded ones and its error nil or an IINError carrying
//     the recorded IIN.

const capturesDir = "../testdata/captures"

// replayOutstation answers each request the client sends with the next
// queued recorded response.
type replayOutstation struct {
	t          *testing.T
	conn       net.Conn
	master     link.Address
	outstation link.Address
	reqs       chan []byte // reassembled request fragments
	seg        transport.Segmenter
}

func newReplayOutstation(t *testing.T, conn net.Conn, master, outstation link.Address) *replayOutstation {
	o := &replayOutstation{t: t, conn: conn, master: master, outstation: outstation, reqs: make(chan []byte, 64)}
	go o.read()
	return o
}

func (o *replayOutstation) read() {
	defer close(o.reqs)
	r := link.NewReader(o.conn)
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
		frag, err := ra.Add(f.Data)
		if err == nil && frag != nil {
			o.reqs <- frag
		}
	}
}

// send writes one fragment, segmented into frames from the outstation.
func (o *replayOutstation) send(frag []byte) error {
	for _, seg := range o.seg.Segment(frag) {
		f := link.Frame{Function: link.PrimaryUnconfirmedUserData, Dest: o.master, Src: o.outstation, Data: seg}
		b, err := f.Encode()
		if err != nil {
			return err
		}
		if _, err := o.conn.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// next returns the next request fragment that is (confirm true) or is
// not (confirm false) a CONFIRM, skipping the others.
func (o *replayOutstation) next(d time.Duration, confirm bool) ([]byte, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case b, ok := <-o.reqs:
			if !ok {
				return nil, false
			}
			if isConfirm := len(b) >= 2 && app.FunctionCode(b[1]) == app.FuncConfirm; isConfirm != confirm {
				continue
			}
			return b, true
		case <-timer.C:
			return nil, false
		}
	}
}

// withSeq returns a copy of a fragment with the sequence number seq.
func withSeq(b []byte, seq uint8) []byte {
	c := bytes.Clone(b)
	c[0] = c[0]&0xF0 | seq&0x0F
	return c
}

func TestCaptureClientReplay(t *testing.T) {
	recs, err := capture.Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var exchanges, responses, measurements, unsolicited int
	skipped := map[string]int{}
	for _, r := range recs {
		for si, s := range r.Conversations {
			master, outstation, ok := capture.Addresses(s)
			if !ok {
				continue
			}
			var cases []capture.Exchange
			uns := capture.Unsolicited(s)
			for _, ex := range capture.Exchanges(s) {
				reason := replaySkip(ex)
				if reason != "" {
					skipped[reason]++
					continue
				}
				cases = append(cases, ex)
			}
			if len(cases) == 0 && len(uns) == 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", r.File.ID, si), func(t *testing.T) {
				n, m := replayClient(t, master, outstation, cases)
				exchanges += len(cases)
				responses += n
				measurements += m
				if len(uns) > 0 {
					unsolicited += replayUnsolicited(t, master, outstation, uns)
				}
			})
		}
	}
	t.Logf("replayed %d exchanges (%d response fragments, %d measurements) and %d unsolicited responses; not replayed: %v",
		exchanges, responses, measurements, unsolicited, skipped)
}

// replaySkip returns why an exchange is not replayed through the client,
// or "".
func replaySkip(ex capture.Exchange) string {
	req := ex.Request.Frag
	switch {
	case ex.Request.Err != nil:
		return "request app.Decode refuses"
	case len(ex.Responses) == 0 && !req.Function.NoAck():
		return "no recorded response"
	case len(ex.Responses) > 0 && !ex.Complete:
		// conformance 8.9.2.2: the runner withholds or garbles the
		// confirmation of the first fragment, so the outstation sends no
		// more.
		return "multi-fragment response not completed"
	case req.Function == app.FuncAuthRequest || req.Function == app.FuncAuthRequestNoAck:
		return "secure authentication exchange (needs the session keys)"
	case req.Control.UNS:
		return "unsolicited confirm"
	}
	return ""
}

// dialReplay connects a client to a replay outstation over a pipe.
func dialReplay(t *testing.T, master, outstation link.Address, opts ...Option) (*Client, *replayOutstation, func()) {
	t.Helper()
	cs, os := net.Pipe()
	var once sync.Once
	opener := func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		var c net.Conn
		once.Do(func() { c = cs })
		if c == nil {
			return nil, nil, errors.New("replay: one connection only")
		}
		return c, c.RemoteAddr(), nil
	}
	opts = append([]Option{WithStream(opener), WithAddresses(master, outstation),
		WithStartup(Startup{}), WithAutoIntegrity(false), WithAutoClearRestart(false), WithAutoEventPoll(false),
		WithResponseTimeout(2 * time.Second), WithMaxFragment(1 << 16)}, opts...)
	c, err := New("replay", opts...)
	if err != nil {
		t.Fatal(err)
	}
	o := newReplayOutstation(t, os, master, outstation)
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return c, o, func() { _ = c.Close(); _ = os.Close() }
}

// replayClient runs one conversation's exchanges through one client.
func replayClient(t *testing.T, master, outstation link.Address, cases []capture.Exchange) (frags, meas int) {
	t.Helper()
	if len(cases) == 0 {
		return 0, 0
	}
	c, o, done := dialReplay(t, master, outstation)
	defer done()
	ctx := t.Context()
	for _, ex := range cases {
		req := ex.Request
		if req.Dest.Broadcast() {
			// A broadcast request has no response (IEEE 1815-2012
			// clause 4.4.6): the client sends it with Broadcast.
			if err := c.Broadcast(ctx, req.Dest, req.Frag.Function, req.Frag.Headers...); err != nil {
				t.Errorf("frame %d %s: %v", req.Frame, req.Frag, err)
				continue
			}
			got, ok := o.next(5*time.Second, false)
			if want := withSeq(req.Raw, got[0]); !ok || !bytes.Equal(got, want) {
				t.Errorf("frame %d %s: broadcast request:\n client   % x\n recorded % x", req.Frame, req.Frag, got, req.Raw)
			}
			continue
		}
		done := make(chan struct{})
		var got []byte
		go func() {
			defer close(done)
			b, ok := o.next(5*time.Second, false)
			if !ok {
				return
			}
			got = b
			seq := b[0] & 0x0F
			for _, resp := range ex.Responses {
				if err := o.send(withSeq(resp.Raw, seq)); err != nil {
					return
				}
				seq = app.NextSeq(seq)
			}
		}()
		res, err := c.Request(ctx, req.Frag.Function, req.Frag.Headers...)
		<-done
		name := fmt.Sprintf("frame %d %s", req.Frame, req.Frag)
		if got == nil {
			t.Errorf("%s: the client sent no request", name)
			continue
		}
		if want := withSeq(req.Raw, got[0]); !bytes.Equal(got, want) {
			t.Errorf("%s: request differs from the recorded one apart from the sequence number:\n client   % x\n recorded % x", name, got, want)
		}
		if len(ex.Responses) == 0 { // a no-ack request
			if err != nil || len(res.Fragments) != 0 {
				t.Errorf("%s: %v, %d fragments", name, err, len(res.Fragments))
			}
			continue
		}
		last := ex.Responses[len(ex.Responses)-1].Frag
		var iinErr *dnp3.IINError
		switch {
		case err == nil:
		case errors.As(err, &iinErr) && iinErr.IIN == last.IIN:
		default:
			t.Errorf("%s: %v", name, err)
			continue
		}
		if res == nil || len(res.Fragments) != len(ex.Responses) {
			t.Errorf("%s: %d response fragments, recorded %d", name, len(res.Fragments), len(ex.Responses))
			continue
		}
		for i, f := range res.Fragments {
			want := *ex.Responses[i].Frag
			want.Control.Seq = (got[0] + uint8(i)) & 0x0F
			if !reflect.DeepEqual(*f, want) {
				t.Errorf("%s: response fragment %d: client %s, recorded %s", name, i, f, &want)
			}
		}
		frags += len(res.Fragments)
		meas += len(res.Measurements())
	}
	return frags, meas
}

// replayUnsolicited sends a conversation's recorded unsolicited responses
// to a client: each must reach the Handler with the measurements app.Decode
// reads from it, and one that asks for confirmation must be confirmed with
// its sequence number and UNS set. A repeat (the same octets as the
// previous one, IEEE 1815-2012 clause 4.6.2) is confirmed again but not
// passed to the Handler twice.
func replayUnsolicited(t *testing.T, master, outstation link.Address, uns []capture.Fragment) int {
	t.Helper()
	var mu sync.Mutex
	var got []Measurement
	h := HandlerFunc(func(info ResponseInfo, ms []Measurement) {
		if info.Unsolicited {
			mu.Lock()
			got = append(got, ms...)
			mu.Unlock()
		}
	})
	_, o, done := dialReplay(t, master, outstation, WithHandler(h))
	defer done()
	var want []Measurement
	var prev []byte
	for _, f := range uns {
		if err := o.send(f.Raw); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.Raw, prev) {
			want = append(want, Measurements(f.Frag)...)
		}
		prev = f.Raw
		if !f.Frag.Control.CON {
			continue
		}
		b, ok := o.next(5*time.Second, true)
		if !ok {
			t.Errorf("frame %d %s: not confirmed", f.Frame, f.Frag)
			continue
		}
		c, err := app.Decode(b)
		if err != nil || !c.Control.UNS || c.Control.Seq != f.Frag.Control.Seq {
			t.Errorf("frame %d %s: confirmation %v (%v)", f.Frame, f.Frag, c, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= len(want) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unsolicited measurements: client %d, recorded %d", len(got), len(want))
	}
	return len(uns)
}

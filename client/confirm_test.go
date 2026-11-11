// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// rawOutstation answers each request with the octets its answer function
// returns (none for nil) and records the confirmations the master sends.
type rawOutstation struct {
	addr     string
	sess     chan *channel.Session
	confirms chan app.Control
}

func newRawOutstation(t *testing.T, answer func(req *app.Fragment) []byte) *rawOutstation {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	o := &rawOutstation{addr: l.Addr().String(), sess: make(chan *channel.Session, 1), confirms: make(chan app.Control, 16)}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		reqs := make(chan *app.Fragment, 16)
		sess := ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1,
			OnFragment: func(b []byte, _ link.Address) {
				f, err := app.Decode(b)
				switch {
				case err != nil:
				case f.Function == app.FuncConfirm:
					o.confirms <- f.Control
				default:
					reqs <- f
				}
			}})
		ch.Start()
		o.sess <- sess
		defer func() { ch.Close(nil); <-ch.Done() }()
		for {
			select {
			case r := <-reqs:
				if b := answer(r); b != nil {
					_ = sess.Send(context.Background(), b)
				}
			case <-ch.Done():
				return
			}
		}
	}()
	return o
}

// noConfirm fails when the master confirms within d.
func (o *rawOutstation) noConfirm(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case c := <-o.confirms:
		t.Fatalf("unexpected confirmation %s", c)
	case <-time.After(d):
	}
}

func (o *rawOutstation) confirmed(t *testing.T) app.Control {
	t.Helper()
	select {
	case c := <-o.confirms:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("no confirmation")
		return app.Control{}
	}
}

// One binary input event (g2v1, index 0, ONLINE and on), whole and with
// the header announcing a second object that is not there.
var (
	oneEvent       = []byte{0x02, 0x01, 0x17, 0x01, 0x00, 0x81}
	truncatedEvent = []byte{0x02, 0x01, 0x17, 0x02, 0x00, 0x81}
	// An object of a group the codec cannot size: parsing stops at it.
	unknownObject = []byte{0xFE, 0x01, 0x00, 0x00, 0x00, 0x00}
)

func response(seq uint8, con bool, objects ...[]byte) []byte {
	c := app.Control{FIR: true, FIN: true, CON: con, Seq: seq}
	b := []byte{c.Byte(), byte(app.FuncResponse), 0x00, 0x00}
	for _, o := range objects {
		b = append(b, o...)
	}
	return b
}

func unsolicited(seq uint8, con bool, objects ...[]byte) []byte {
	c := app.Control{FIR: true, FIN: true, CON: con, UNS: true, Seq: seq}
	b := []byte{c.Byte(), byte(app.FuncUnsolicitedResponse), 0x00, 0x00}
	for _, o := range objects {
		b = append(b, o...)
	}
	return b
}

// TestConfirmOnlyWhatWasParsed: the master confirms a response that asks
// for it (CON, IEEE 1815-2012 clause 4.2.2.4.3) only once the whole fragment
// has been parsed. A confirmation tells the outstation that the events were
// received and processed, after which it discards them, so a fragment whose
// parse stopped early is not confirmed and the outstation reports its events
// again.
func TestConfirmOnlyWhatWasParsed(t *testing.T) {
	bodies := make(chan [][]byte, 4)
	o := newRawOutstation(t, func(r *app.Fragment) []byte {
		return response(r.Control.Seq, true, <-bodies...)
	})
	// No startup integrity poll: each request takes the next body.
	c, err := Dial(testCtx(t), o.addr, WithAutoIntegrity(false), WithStartup(Startup{}), WithResponseTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	for _, bad := range [][][]byte{{truncatedEvent}, {oneEvent, unknownObject}} {
		bodies <- bad
		if _, err := c.Read(testCtx(t), app.AllObjects(app.G2V0)); !errors.Is(err, dnp3.ErrTimeout) {
			t.Fatalf("read of an unparsable response: %v", err)
		}
		o.noConfirm(t, 100*time.Millisecond)
	}

	bodies <- [][]byte{oneEvent}
	res, err := c.Read(testCtx(t), app.AllObjects(app.G2V0))
	if err != nil || len(res.Measurements()) != 1 {
		t.Fatalf("read: %v %v", res, err)
	}
	if cc := o.confirmed(t); cc.UNS || cc.Seq != res.Fragments[0].Control.Seq {
		t.Fatalf("confirmation %s for seq %d", cc, res.Fragments[0].Control.Seq)
	}

	// Without CON, nothing is confirmed.
	o2 := newRawOutstation(t, func(r *app.Fragment) []byte { return response(r.Control.Seq, false, oneEvent) })
	c2, err := Dial(testCtx(t), o2.addr, WithAutoIntegrity(false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	if _, err := c2.Read(testCtx(t), app.AllObjects(app.G2V0)); err != nil {
		t.Fatal(err)
	}
	o2.noConfirm(t, 100*time.Millisecond)
}

// TestUnsolicitedConfirmOnlyWhatWasParsed: an unsolicited response is
// confirmed when it asks for it and was parsed whole (IEEE 1815-2012 clause
// 4.2.2.4.3), with its UNS bit and sequence number; one without CON, or one
// whose parse stopped early, is not.
func TestUnsolicitedConfirmOnlyWhatWasParsed(t *testing.T) {
	o := newRawOutstation(t, func(r *app.Fragment) []byte { return response(r.Control.Seq, false) })
	got := make(chan []Measurement, 4)
	c, err := Dial(testCtx(t), o.addr, WithAutoIntegrity(false),
		WithHandler(HandlerFunc(func(info ResponseInfo, ms []Measurement) {
			if info.Unsolicited {
				got <- ms
			}
		})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	sess := <-o.sess
	send := func(b []byte) {
		t.Helper()
		if err := sess.Send(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}

	send(unsolicited(1, true, truncatedEvent))
	o.noConfirm(t, 150*time.Millisecond)
	send(unsolicited(2, true, oneEvent, unknownObject))
	o.noConfirm(t, 150*time.Millisecond)
	send(unsolicited(3, false, oneEvent))
	o.noConfirm(t, 150*time.Millisecond)
	if ms := <-got; len(ms) != 1 {
		t.Fatalf("unsolicited events without CON: %v", ms)
	}

	send(unsolicited(4, true, oneEvent))
	if cc := o.confirmed(t); !cc.UNS || cc.Seq != 4 {
		t.Fatalf("confirmation %s", cc)
	}
	if ms := <-got; len(ms) != 1 {
		t.Fatalf("unsolicited events: %v", ms)
	}
	select {
	case ms := <-got:
		t.Fatalf("events of an unparsable response delivered: %v", ms)
	default:
	}
}

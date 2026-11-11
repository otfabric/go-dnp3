// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/link"
)

// The spec tests check the master against IEEE 1815-2012, one requirement
// per test: the name gives the clause, the doc comment the printed page and
// the requirement. They run the client against a specOutstation, which
// shows them every octet the master sends.

// specFrag is a fragment the master sent: its encoding, decoded.
type specFrag struct {
	raw []byte
	f   *app.Fragment
}

// specOutstation answers each request with the fragments its answer
// function returns, in order, and records every fragment the master sends,
// confirmations included, in the order they arrived.
type specOutstation struct {
	addr  string
	ready chan struct{}
	sess  *channel.Session

	mu      sync.Mutex
	log     []specFrag
	changed chan struct{} // signalled when log grows
}

func newSpecOutstation(t *testing.T, answer func(req specFrag) [][]byte) *specOutstation {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	o := &specOutstation{addr: l.Addr().String(), ready: make(chan struct{}), changed: make(chan struct{}, 1)}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		ch := channel.New(conn, channel.Config{})
		reqs := make(chan specFrag, 64)
		o.sess = ch.AddSession(channel.SessionConfig{Local: 10, Remote: 1,
			OnFragment: func(b []byte, _ link.Address) {
				f, err := app.Decode(b)
				if err != nil {
					return
				}
				sf := specFrag{raw: append([]byte(nil), b...), f: f}
				o.mu.Lock()
				o.log = append(o.log, sf)
				o.mu.Unlock()
				select {
				case o.changed <- struct{}{}:
				default:
				}
				if f.Function != app.FuncConfirm {
					reqs <- sf
				}
			}})
		ch.Start()
		close(o.ready)
		defer func() { ch.Close(nil); <-ch.Done() }()
		for {
			select {
			case r := <-reqs:
				for _, b := range answer(r) {
					_ = o.sess.Send(context.Background(), b)
				}
			case <-ch.Done():
				return
			}
		}
	}()
	return o
}

// push sends a fragment to the master at once, for example an unsolicited
// response.
func (o *specOutstation) push(t *testing.T, b []byte) {
	t.Helper()
	select {
	case <-o.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("the master did not connect")
	}
	if err := o.sess.Send(t.Context(), b); err != nil {
		t.Fatal(err)
	}
}

// none fails when the master sends another fragment within d.
func (o *specOutstation) none(t *testing.T, d time.Duration) {
	t.Helper()
	n := len(o.sent())
	timeout := time.After(d)
	for {
		select {
		case <-o.changed:
			if sent := o.sent(); len(sent) > n {
				t.Fatalf("unexpected fragment from the master: %s", sent[n].f)
			}
		case <-timeout:
			return
		}
	}
}

// sent returns the fragments the master sent so far.
func (o *specOutstation) sent() []specFrag {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]specFrag(nil), o.log...)
}

// waitLog waits until pred holds for the fragments the master sent, and
// returns them.
func (o *specOutstation) waitLog(t *testing.T, what string, pred func(sent []specFrag) bool) []specFrag {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if sent := o.sent(); pred(sent) {
			return sent
		}
		select {
		case <-o.changed:
		case <-deadline:
			t.Fatalf("timed out waiting for %s; the master sent %v", what, o.requests())
		}
	}
}

// waitConfirms waits until the master sent n confirmations, and returns
// them.
func (o *specOutstation) waitConfirms(t *testing.T, n int) []app.Control {
	t.Helper()
	o.waitLog(t, "confirmations", func([]specFrag) bool { return len(o.confirms()) >= n })
	return o.confirms()
}

// requests returns the function codes of the requests the master sent so
// far, confirmations left out.
func (o *specOutstation) requests() []app.FunctionCode {
	var out []app.FunctionCode
	for _, f := range o.sent() {
		if f.f.Function != app.FuncConfirm {
			out = append(out, f.f.Function)
		}
	}
	return out
}

// quiet turns off everything the client does on its own, for the tests
// that look at one request.
var quiet = []Option{WithStartup(Startup{}), WithAutoIntegrity(false), WithAutoClearRestart(false),
	WithAutoEventPoll(false), WithTimeSync(TimeSyncNone)}

// specDial connects a client to o with a short response timeout; opts
// come after the defaults.
func specDial(t *testing.T, o *specOutstation, opts ...Option) *Client {
	t.Helper()
	c, err := Dial(testCtx(t), o.addr, append([]Option{WithResponseTimeout(500 * time.Millisecond)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// frag encodes a response fragment with the given control, function, IIN
// and the octets of its objects.
func frag(c app.Control, fc app.FunctionCode, iin app.IIN, objects ...[]byte) []byte {
	b := []byte{c.Byte(), byte(fc), byte(iin), byte(iin >> 8)}
	for _, o := range objects {
		b = append(b, o...)
	}
	return b
}

// echo answers a request with the octets after its function code.
func echo(req specFrag, iin app.IIN) []byte {
	return frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, iin, req.raw[2:])
}

// empty answers a request with no objects.
func empty(req specFrag, iin app.IIN) []byte {
	return frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, iin)
}

// frameMetrics records the link frames the client writes.
type frameMetrics struct {
	dnp3.NopMetrics
	mu     sync.Mutex
	frames []link.Frame
}

func (m *frameMetrics) OnFrameSent(_ net.Addr, f *link.Frame, _ int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := *f
	g.Data = append([]byte(nil), f.Data...)
	m.frames = append(m.frames, g)
}

// userData returns the link function of each frame that carried the first
// segment of an application fragment, with the fragment's function code.
func (m *frameMetrics) userData() map[app.FunctionCode][]link.Function {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[app.FunctionCode][]link.Function{}
	for _, f := range m.frames {
		// The transport header (FIR in bit 6), the application control
		// and the function code.
		if len(f.Data) >= 3 && f.Data[0]&0x40 != 0 {
			fc := app.FunctionCode(f.Data[2])
			out[fc] = append(out[fc], f.Function)
		}
	}
	return out
}

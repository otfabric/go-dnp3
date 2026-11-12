// SPDX-License-Identifier: MIT

package channel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// Spec tests: IEEE 1815-2012 clause 9 (data link layer, Tables 9-6 and
// 9-7), clause 10.4 (multiple messages) and the link layer parts of clause
// 13 (keep-alive, UDP datagrams), run against a session with a raw peer
// that writes and reads single frames. Page numbers are printed pages.

// station is the raw peer of a session: the master of an outstation
// session, or the outstation of a master session.
type station struct {
	*rawPeer
	self, peer link.Address // the raw station's address, the session's
	dir        bool         // the DIR bit the raw station sets
	in         *inbox       // what the session delivers
}

// frame returns a frame from the station to the session.
func (s *station) frame(fn link.Function, fcb, fcv bool, data []byte) link.Frame {
	return link.Frame{Dir: s.dir, Function: fn, FCB: fcb, FCV: fcv, Dest: s.peer, Src: s.self, Data: data}
}

// pri returns a primary frame with the FCV bit its function requires.
func (s *station) pri(fn link.Function, fcb bool, data []byte) link.Frame {
	return s.frame(fn, fcb, fn.UsesFCB(), data)
}

// sec returns a secondary frame from the station.
func (s *station) sec(fn link.Function, dfc bool) link.Frame {
	return link.Frame{Dir: s.dir, Function: fn, DFC: dfc, Dest: s.peer, Src: s.self}
}

// expect reads the next frame and checks its function and addresses.
func (s *station) expect(fn link.Function) link.Frame {
	s.t.Helper()
	f := s.read()
	if f.Function != fn || f.Dest != s.self || f.Src != s.peer {
		s.t.Fatalf("got %s, want %s %d->%d", f.String(), fn, s.peer, s.self)
	}
	return f
}

// noReply checks that what was written before drew no link reply: a
// REQUEST_LINK_STATUS sent after it is answered first. The session handles
// frames, and writes its replies, in the order they arrive.
func (s *station) noReply() {
	s.t.Helper()
	s.write(s.pri(link.PrimaryRequestLinkStatus, false, nil))
	if f := s.read(); f.Function != link.SecondaryLinkStatus {
		s.t.Fatalf("unexpected reply %s", f.String())
	}
}

// marker is the fragment notDelivered sends.
var marker = []byte{0xEE, 0xE0}

// notDelivered checks that nothing written before was passed up: a
// fragment sent after it is the next one delivered.
func (s *station) notDelivered() {
	s.t.Helper()
	s.write(s.pri(link.PrimaryUnconfirmedUserData, false, segmentOf(marker)))
	if d := s.in.next(s.t); !bytes.Equal(d.frag, marker) {
		s.t.Fatalf("delivered %v", d.frag)
	}
}

// delivered checks the next fragment the session passes up.
func (s *station) delivered(want []byte) {
	s.t.Helper()
	if d := s.in.next(s.t); !bytes.Equal(d.frag, want) {
		s.t.Fatalf("delivered %v, want %v", d.frag, want)
	}
}

// outstationStation returns an outstation session (10) on a TCP
// connection and the raw master (1) at its other end.
func outstationStation(t *testing.T, cfg SessionConfig, ccfg Config) (*Session, *station) {
	t.Helper()
	a, b := tcpPair(t)
	in := newInbox()
	ccfg.Remote = b.RemoteAddr()
	ch := New(b, ccfg)
	cfg.Local, cfg.Remote = outstationAddr, masterAddr
	if cfg.OnFragment == nil {
		cfg.OnFragment = in.fn
	}
	s := ch.AddSession(cfg)
	ch.Start()
	t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	return s, &station{rawPeer: newRaw(t, a), self: masterAddr, peer: outstationAddr, dir: true, in: in}
}

// masterStation returns a master session (1) on a TCP connection and the
// raw outstation (10) at its other end.
func masterStation(t *testing.T, cfg SessionConfig, ccfg Config) (*Session, *station) {
	t.Helper()
	a, b := tcpPair(t)
	in := newInbox()
	ccfg.Remote = a.RemoteAddr()
	ch := New(a, ccfg)
	cfg.Local, cfg.Remote, cfg.Master, cfg.OnFragment = masterAddr, outstationAddr, true, in.fn
	s := ch.AddSession(cfg)
	ch.Start()
	t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	return s, &station{rawPeer: newRaw(t, b), self: outstationAddr, peer: masterAddr, dir: false, in: in}
}

// sendAsync starts s.Send and returns its result channel.
func sendAsync(s *Session, frag []byte) chan error {
	errc := make(chan error, 1)
	go func() { errc <- s.Send(context.Background(), frag) }()
	return errc
}

// probeAsync starts s.Probe and returns its result channel.
func probeAsync(s *Session) chan error {
	errc := make(chan error, 1)
	go func() { errc <- s.Probe() }()
	return errc
}

func result(t *testing.T, errc chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("the session did not finish")
		return nil
	}
}

// linkMetrics counts the errors the channel reports.
type linkMetrics struct {
	dnp3.NopMetrics
	framing, decode atomic.Int64
}

func (m *linkMetrics) OnFramingError(net.Addr, error) { m.framing.Add(1) }
func (m *linkMetrics) OnDecodeError(net.Addr, error)  { m.decode.Add(1) }

// warnLog records warnings.
type warnLog struct {
	mu    sync.Mutex
	warns []string
}

func (l *warnLog) Debugf(string, ...any) {}
func (l *warnLog) Infof(string, ...any)  {}
func (l *warnLog) Errorf(string, ...any) {}
func (l *warnLog) Warnf(format string, args ...any) {
	l.mu.Lock()
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *warnLog) has(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.warns {
		if strings.Contains(w, s) {
			return true
		}
	}
	return false
}

// rawHeader returns a frame header with any control octet, also one whose
// function code is not defined, with a valid CRC.
func rawHeader(ctrl byte, dest, src link.Address) []byte {
	h := binary.LittleEndian.AppendUint16([]byte{link.Start0, link.Start1, 5, ctrl}, uint16(dest))
	h = binary.LittleEndian.AppendUint16(h, uint16(src))
	c := link.CRC(h)
	return binary.LittleEndian.AppendUint16(h, c)
}

// TestSpecTable9_7 drives the Secondary Station state table (clause
// 9.3.2.2, Table 9-7, p. 292-293) row by row, on an outstation session:
// the state before (UnReset, or Idle with an expected FCB), the frame
// received, the reply (none where the table allows "may optionally not
// transmit anything"), whether the user data is passed up, and the state
// after. Replies come from the outstation: DIR 0 (clause 9.2.3), DFC 0
// (9.2.4.1.3.5).
func TestSpecTable9_7(t *testing.T) {
	const none = link.Function(0xFF)
	type state int
	const (
		unreset state = iota
		idle1         // Idle, EFCB 1
		idle0         // Idle, EFCB 0
	)
	cases := []struct {
		row    uint8
		before state
		fn     link.Function
		fcb    bool
		fcv    bool
		raw    []byte // a frame Encode refuses: an undefined function code
		reply  link.Function
		passed bool
		after  state
	}{
		{row: 1, before: unreset, fn: link.PrimaryResetLinkStates, reply: link.SecondaryAck, after: idle1},
		{row: 2, before: unreset, fn: link.PrimaryResetLinkStates, fcv: true, reply: none, after: unreset},
		{row: 3, before: unreset, raw: rawHeader(0xC1, outstationAddr, masterAddr), reply: none, after: unreset},
		{row: 3, before: unreset, raw: rawHeader(0xC5, outstationAddr, masterAddr), reply: none, after: unreset},
		{row: 3, before: unreset, raw: rawHeader(0xCF, outstationAddr, masterAddr), reply: none, after: unreset},
		{row: 4, before: unreset, fn: link.PrimaryTestLinkStates, fcb: true, reply: none, after: unreset},
		{row: 5, before: unreset, fn: link.PrimaryTestLinkStates, fcb: true, fcv: true, reply: none, after: unreset},
		{row: 6, before: unreset, fn: link.PrimaryConfirmedUserData, fcb: true, reply: none, after: unreset},
		{row: 7, before: unreset, fn: link.PrimaryConfirmedUserData, fcb: true, fcv: true, reply: none, after: unreset},
		{row: 8, before: unreset, fn: link.PrimaryUnconfirmedUserData, reply: none, passed: true, after: unreset},
		{row: 9, before: unreset, fn: link.PrimaryUnconfirmedUserData, fcv: true, reply: none, after: unreset},
		{row: 10, before: unreset, fn: link.PrimaryRequestLinkStatus, reply: link.SecondaryLinkStatus, after: unreset},
		{row: 11, before: unreset, fn: link.PrimaryRequestLinkStatus, fcv: true, reply: none, after: unreset},
		{row: 12, before: idle0, fn: link.PrimaryResetLinkStates, reply: link.SecondaryAck, after: idle1},
		{row: 13, before: idle0, fn: link.PrimaryResetLinkStates, fcv: true, reply: none, after: idle0},
		{row: 14, before: idle1, raw: rawHeader(0xC1, outstationAddr, masterAddr), reply: none, after: idle1},
		{row: 14, before: idle1, raw: rawHeader(0xD8, outstationAddr, masterAddr), reply: none, after: idle1},
		{row: 15, before: idle1, fn: link.PrimaryTestLinkStates, fcb: true, reply: none, after: idle1},
		{row: 16, before: idle1, fn: link.PrimaryTestLinkStates, fcb: true, fcv: true, reply: link.SecondaryAck, after: idle0},
		{row: 16, before: idle0, fn: link.PrimaryTestLinkStates, fcv: true, reply: link.SecondaryAck, after: idle1},
		{row: 17, before: idle1, fn: link.PrimaryTestLinkStates, fcv: true, reply: link.SecondaryAck, after: idle1},
		{row: 18, before: idle1, fn: link.PrimaryConfirmedUserData, fcb: true, reply: none, after: idle1},
		{row: 19, before: idle1, fn: link.PrimaryConfirmedUserData, fcb: true, fcv: true, reply: link.SecondaryAck, passed: true, after: idle0},
		{row: 19, before: idle0, fn: link.PrimaryConfirmedUserData, fcv: true, reply: link.SecondaryAck, passed: true, after: idle1},
		{row: 20, before: idle1, fn: link.PrimaryConfirmedUserData, fcv: true, reply: link.SecondaryAck, after: idle1},
		{row: 21, before: idle1, fn: link.PrimaryUnconfirmedUserData, reply: none, passed: true, after: idle1},
		{row: 22, before: idle1, fn: link.PrimaryUnconfirmedUserData, fcv: true, reply: none, after: idle1},
		{row: 23, before: idle1, fn: link.PrimaryRequestLinkStatus, reply: link.SecondaryLinkStatus, after: idle1},
		{row: 24, before: idle1, fn: link.PrimaryRequestLinkStatus, fcv: true, reply: none, after: idle1},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("row %d/%d", c.row, i), func(t *testing.T) {
			_, m := outstationStation(t, SessionConfig{}, Config{})
			// Bring the session to the state before.
			if c.before != unreset {
				m.write(m.pri(link.PrimaryResetLinkStates, false, nil))
				m.expect(link.SecondaryAck)
			}
			if c.before == idle0 {
				m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{0xF0})))
				m.expect(link.SecondaryAck)
				m.delivered([]byte{0xF0})
			}

			data := []byte{c.row}
			if c.raw != nil {
				if _, err := m.conn.Write(c.raw); err != nil {
					t.Fatal(err)
				}
			} else {
				var seg []byte
				if c.fn.HasData() {
					seg = segmentOf(data)
				}
				m.write(m.frame(c.fn, c.fcb, c.fcv, seg))
			}
			if c.reply == none {
				m.noReply()
			} else if f := m.expect(c.reply); f.Dir || f.DFC {
				t.Fatalf("reply %s: DIR or DFC set", f.String())
			}
			if c.passed {
				m.delivered(data)
			} else {
				m.notDelivered()
			}

			// The state after: only an unreset secondary leaves confirmed
			// user data unanswered (rows 7 and 19/20); a reset one passes up
			// the frame whose FCB it expects.
			switch c.after {
			case unreset:
				m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{0xC1})))
				m.noReply()
				m.notDelivered()
			default:
				fcb := c.after == idle1
				m.write(m.pri(link.PrimaryConfirmedUserData, fcb, segmentOf([]byte{0xC2})))
				m.expect(link.SecondaryAck)
				m.delivered([]byte{0xC2})
			}
		})
	}
}

// TestSpec9_2_6_2_TestLinkStatesRepeatsNack checks clause 9.2.6.2 (p. 283)
// and Table 9-7 row 17 (p. 292): a TEST_LINK_STATES whose FCB is not the
// expected one is answered with a repeat of the most recent ACK or NACK,
// here a NACK sent because the receive queue was full.
func TestSpec9_2_6_2_TestLinkStatesRepeatsNack(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	in := newInbox()
	_, m := outstationStation(t, SessionConfig{QueueSize: 1, OnFragment: func(frag []byte, dest link.Address) {
		in.fn(frag, dest)
		once.Do(func() { close(entered); <-release })
	}}, Config{})
	m.in = in
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	m.write(m.pri(link.PrimaryResetLinkStates, false, nil))
	m.expect(link.SecondaryAck)
	m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1})))
	m.expect(link.SecondaryAck)
	<-entered // the first fragment is being handled: the queue is empty
	m.write(m.pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{2})))
	m.expect(link.SecondaryAck) // queued: the queue is full now
	m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{3})))
	if f := m.expect(link.SecondaryNack); !f.DFC {
		t.Fatalf("NACK without DFC: %s", f.String())
	}
	// EFCB is still 1: a TEST_LINK_STATES with FCB 0 is a repeat.
	m.write(m.pri(link.PrimaryTestLinkStates, false, nil))
	if f := m.expect(link.SecondaryNack); !f.DFC {
		t.Fatalf("repeat of the NACK: %s", f.String())
	}
	close(release)
	m.delivered([]byte{1})
	m.delivered([]byte{2})
	// With the queue free the repeat of the refused frame is taken.
	m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{3})))
	if f := m.expect(link.SecondaryAck); f.DFC {
		t.Fatalf("ACK after the queue drained: %s", f.String())
	}
	m.delivered([]byte{3})
	// The most recent answer is an ACK again.
	m.write(m.pri(link.PrimaryTestLinkStates, true, nil))
	m.expect(link.SecondaryAck)
}

// TestSpec9_2_4_1_3_5_DFC checks the DFC bit of clauses 9.2.4.1.3.5 (p.
// 278) and 9.2.7.2 (p. 284-285): it is in every secondary answer, set
// while the receive buffers are full; CONFIRMED_USER_DATA that the full
// queue cannot take is answered NACK with DFC set and the expected FCB is
// not toggled, so the primary's repeat is taken, once, after the queue
// drained.
func TestSpec9_2_4_1_3_5_DFC(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	in := newInbox()
	_, m := outstationStation(t, SessionConfig{QueueSize: 1, OnFragment: func(frag []byte, dest link.Address) {
		in.fn(frag, dest)
		once.Do(func() { close(entered); <-release })
	}}, Config{})
	m.in = in
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	m.write(m.pri(link.PrimaryRequestLinkStatus, false, nil))
	if f := m.expect(link.SecondaryLinkStatus); f.DFC {
		t.Fatal("DFC set with an empty queue")
	}
	m.write(m.pri(link.PrimaryResetLinkStates, false, nil))
	m.expect(link.SecondaryAck)
	m.write(m.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{1})))
	<-entered
	m.write(m.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{2})))
	// The queue holds a fragment and is full: every answer has DFC.
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.write(m.pri(link.PrimaryRequestLinkStatus, false, nil))
		if m.expect(link.SecondaryLinkStatus).DFC {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DFC never set with a full queue")
		}
	}
	m.write(m.pri(link.PrimaryTestLinkStates, true, nil))
	if f := m.expect(link.SecondaryAck); !f.DFC {
		t.Fatalf("ACK with a full queue: %s", f.String())
	}
	// EFCB is 0 now. A confirmed fragment is refused with NACK and DFC.
	m.write(m.pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{3})))
	if f := m.expect(link.SecondaryNack); !f.DFC {
		t.Fatalf("NACK without DFC: %s", f.String())
	}
	close(release)
	m.delivered([]byte{1})
	m.delivered([]byte{2})
	for {
		m.write(m.pri(link.PrimaryRequestLinkStatus, false, nil))
		if !m.expect(link.SecondaryLinkStatus).DFC {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DFC still set after the queue drained")
		}
	}
	// The repeat, same FCB: EFCB was not toggled by the NACK.
	m.write(m.pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{3})))
	m.expect(link.SecondaryAck)
	m.delivered([]byte{3})
	// Its own repeat is a duplicate: ACKed, not passed up again (row 20).
	m.write(m.pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{3})))
	m.expect(link.SecondaryAck)
	m.notDelivered()
}

// TestSpecTable9_6_ConfirmedData checks the confirmed user data path of
// the Primary Station state table (Table 9-6, p. 288-289): row 2, a reset
// before the first confirmed frame (clause 9.2.6.1, p. 283); row 14, the
// first frame after the ACK carries FCB 1; row 26, the FCB toggles on
// ACK; row 7, a reset secondary gets confirmed data without a new reset.
// The master's frames carry DIR 1 (9.2.3) and FCV 1 (Table 9-1).
func TestSpecTable9_6_ConfirmedData(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	errc := sendAsync(s, []byte{1})
	if r := o.expect(link.PrimaryResetLinkStates); !r.Dir || r.FCV || r.FCB {
		t.Fatalf("row 2: %s", r.String())
	}
	o.write(o.sec(link.SecondaryAck, false))
	d := o.expect(link.PrimaryConfirmedUserData)
	if !d.Dir || !d.FCV || !d.FCB || !bytes.Equal(d.Data[1:], []byte{1}) {
		t.Fatalf("row 14: %s", d.String())
	}
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
	for i, fcb := range []bool{false, true, false} {
		errc = sendAsync(s, []byte{byte(2 + i)})
		if d := o.expect(link.PrimaryConfirmedUserData); d.FCB != fcb || !d.FCV {
			t.Fatalf("rows 7 and 26, frame %d: %s", i, d.String())
		}
		o.write(o.sec(link.SecondaryAck, false))
		if err := result(t, errc); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSpecTable9_6_Row15_ResetRefused checks Table 9-6 row 15 (p. 288): a
// RESET_LINK_STATES answered with anything but ACK fails the request and
// leaves the secondary unreset, so the next request starts with a reset.
func TestSpecTable9_6_Row15_ResetRefused(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	for _, answer := range []link.Function{link.SecondaryNack, link.SecondaryNotSupported, link.SecondaryLinkStatus} {
		errc := sendAsync(s, []byte{1})
		o.expect(link.PrimaryResetLinkStates)
		o.write(o.sec(answer, false))
		if err := result(t, errc); !errors.Is(err, dnp3.ErrProtocol) {
			t.Fatalf("RESET answered with %s: %v", answer, err)
		}
	}
	errc := sendAsync(s, []byte{2})
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// TestSpecTable9_6_Rows16And17_ResetUnanswered checks Table 9-6 rows 17
// and 16 (p. 288): an unanswered RESET_LINK_STATES is repeated while
// retries remain, then the request fails and the secondary stays unreset.
func TestSpecTable9_6_Rows16And17_ResetUnanswered(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: 60 * time.Millisecond, Retries: 2}, Config{})
	errc := sendAsync(s, []byte{1})
	for range 3 {
		o.expect(link.PrimaryResetLinkStates)
	}
	if err := result(t, errc); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("row 16: %v", err)
	}
	errc = sendAsync(s, []byte{2})
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	if d := o.expect(link.PrimaryConfirmedUserData); !d.FCB {
		t.Fatal("FCB after the reset")
	}
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// resetLink makes the secondary of s reset, Table 9-6 rows 2 and 14.
func resetLink(t *testing.T, s *Session, o *station) {
	t.Helper()
	errc := sendAsync(s, []byte{0})
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// TestSpecTable9_6_Row27_NackResets checks Table 9-6 row 27 (p. 289): a
// NACK with DFC 0 to CONFIRMED_USER_DATA leads to a RESET_LINK_STATES,
// then the frame is sent again with FCB 1 (row 14). A second NACK for the
// same frame fails it rather than looping: the defensive programming the
// NOTE under the table encourages.
func TestSpecTable9_6_Row27_NackResets(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	resetLink(t, s, o)
	errc := sendAsync(s, []byte{7})
	first := o.expect(link.PrimaryConfirmedUserData)
	if first.FCB {
		t.Fatal("FCB not toggled")
	}
	o.write(o.sec(link.SecondaryNack, false))
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	again := o.expect(link.PrimaryConfirmedUserData)
	if !again.FCB || !bytes.Equal(again.Data, first.Data) {
		t.Fatalf("frame after the reset: %s", again.String())
	}
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}

	errc = sendAsync(s, []byte{8})
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryNack, false))
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryNack, false))
	if err := result(t, errc); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("second NACK: %v", err)
	}
}

// TestSpecTable9_6_Row28_NackWithDFC checks Table 9-6 row 28 (p. 289) and
// clause 9.3.1.1 (p. 287): a NACK with DFC 1 means the secondary's
// buffers are full. The frame is not sent again, the request fails and the
// secondary is taken as unreset: the next request starts with a reset.
func TestSpecTable9_6_Row28_NackWithDFC(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	resetLink(t, s, o)
	errc := sendAsync(s, []byte{7})
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryNack, true))
	if err := result(t, errc); !errors.Is(err, dnp3.ErrProtocol) {
		t.Fatalf("NACK with DFC: %v", err)
	}
	errc = sendAsync(s, []byte{8})
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// TestSpecTable9_6_Row29_OtherAnswer checks Table 9-6 row 29 (p. 289):
// CONFIRMED_USER_DATA answered with neither ACK nor NACK fails and leaves
// the secondary unreset.
func TestSpecTable9_6_Row29_OtherAnswer(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	for _, answer := range []link.Function{link.SecondaryNotSupported, link.SecondaryLinkStatus} {
		resetLink(t, s, o)
		errc := sendAsync(s, []byte{7})
		o.expect(link.PrimaryConfirmedUserData)
		o.write(o.sec(answer, false))
		if err := result(t, errc); !errors.Is(err, dnp3.ErrProtocol) {
			t.Fatalf("answer %s: %v", answer, err)
		}
	}
}

// TestSpecTable9_6_Rows30And31_DataUnanswered checks Table 9-6 rows 31
// and 30 (p. 289): unanswered CONFIRMED_USER_DATA is repeated with the
// same FCB and data while retries remain, then the request fails and the
// secondary is taken as unreset.
func TestSpecTable9_6_Rows30And31_DataUnanswered(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: 60 * time.Millisecond, Retries: 2}, Config{})
	resetLink(t, s, o)
	errc := sendAsync(s, []byte{7})
	first := o.expect(link.PrimaryConfirmedUserData)
	for range 2 {
		if r := o.expect(link.PrimaryConfirmedUserData); r.FCB != first.FCB || !bytes.Equal(r.Data, first.Data) {
			t.Fatalf("row 31: %s", r.String())
		}
	}
	if err := result(t, errc); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("row 30: %v", err)
	}
	errc = sendAsync(s, []byte{8})
	o.expect(link.PrimaryResetLinkStates)
	o.write(o.sec(link.SecondaryAck, false))
	o.expect(link.PrimaryConfirmedUserData)
	o.write(o.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// TestSpecTable9_6_Rows3And8_Unconfirmed checks Table 9-6 rows 3 and 8
// (p. 288) with clauses 9.2.4.1.3.3 and 9.2.4.1.3.4 (p. 277-278):
// unconfirmed user data goes as
// UNCONFIRMED_USER_DATA with FCB and FCV clear, with no reset before it,
// whether or not the secondary is reset. Clause 9.2.5.2.1 (p. 282): a
// frame to a broadcast address never uses CONFIRMED_USER_DATA, also on a
// confirmed session, and it leaves the confirmed state as it was.
func TestSpecTable9_6_Rows3And8_Unconfirmed(t *testing.T) {
	s, o := masterStation(t, SessionConfig{ResponseTimeout: time.Second}, Config{})
	if err := s.Send(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if f := o.expect(link.PrimaryUnconfirmedUserData); f.Control() != 0xC4 || f.FCB || f.FCV {
		t.Fatalf("row 3: %s", f.String())
	}

	c, co := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	resetLink(t, c, co)
	for _, dest := range []link.Address{link.BroadcastNoConfirm, link.BroadcastConfirm, link.BroadcastOptionalConfirm} {
		if err := c.SendBroadcast(context.Background(), []byte{2}, dest); err != nil {
			t.Fatal(err)
		}
		f := co.read()
		if f.Function != link.PrimaryUnconfirmedUserData || f.Dest != dest || f.FCB || f.FCV || !f.Dir {
			t.Fatalf("row 8, broadcast to %#04x: %s", uint16(dest), f.String())
		}
	}
	errc := sendAsync(c, []byte{3})
	if f := co.expect(link.PrimaryConfirmedUserData); f.FCB {
		t.Fatalf("the broadcasts changed the FCB: %s", f.String())
	}
	co.write(co.sec(link.SecondaryAck, false))
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// TestSpecTable9_6_LinkStatusRows checks the REQUEST_LINK_STATUS rows of
// Table 9-6 (p. 288-289) through Probe, the keep-alive of clause
// 13.2.3.3.1 (p. 382): rows 4 and 9 send it with FCV 0; rows 18 and 32,
// LINK_STATUS, keep the reset state; rows 19 and 33, another answer, are
// noted as an error and keep it as well; rows 21 and 35 repeat it while
// retries remain; rows 20 and 34 fail and leave the secondary unreset.
func TestSpecTable9_6_LinkStatusRows(t *testing.T) {
	t.Run("rows 4, 18 and 19: unreset", func(t *testing.T) {
		var m linkMetrics
		s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{Metrics: &m})
		for _, answer := range []link.Function{link.SecondaryLinkStatus, link.SecondaryNotSupported} {
			errc := probeAsync(s)
			if r := o.expect(link.PrimaryRequestLinkStatus); r.FCV || r.FCB || !r.Dir {
				t.Fatalf("row 4: %s", r.String())
			}
			o.write(o.sec(answer, false))
			if err := result(t, errc); err != nil {
				t.Fatalf("answered with %s: %v", answer, err)
			}
		}
		if m.decode.Load() != 1 {
			t.Fatalf("row 19: %d errors noted, want 1", m.decode.Load())
		}
		resetLink(t, s, o) // still unreset: the first request resets
	})
	t.Run("rows 9, 32 and 33: reset", func(t *testing.T) {
		var m linkMetrics
		s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{Metrics: &m})
		resetLink(t, s, o)
		for _, answer := range []link.Function{link.SecondaryLinkStatus, link.SecondaryAck, link.SecondaryNack} {
			errc := probeAsync(s)
			o.expect(link.PrimaryRequestLinkStatus)
			o.write(o.sec(answer, false))
			if err := result(t, errc); err != nil {
				t.Fatalf("answered with %s: %v", answer, err)
			}
		}
		if m.decode.Load() != 2 {
			t.Fatalf("row 33: %d errors noted, want 2", m.decode.Load())
		}
		// Still reset: confirmed data goes without a reset, FCB 0 next.
		errc := sendAsync(s, []byte{1})
		if f := o.expect(link.PrimaryConfirmedUserData); f.FCB {
			t.Fatalf("rows 32/33 changed the link state: %s", f.String())
		}
		o.write(o.sec(link.SecondaryAck, false))
		if err := result(t, errc); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rows 34 and 35: unanswered while reset", func(t *testing.T) {
		s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: 60 * time.Millisecond, Retries: 1}, Config{})
		resetLink(t, s, o)
		errc := probeAsync(s)
		o.expect(link.PrimaryRequestLinkStatus)
		o.expect(link.PrimaryRequestLinkStatus) // row 35
		if err := result(t, errc); !errors.Is(err, dnp3.ErrTimeout) {
			t.Fatalf("row 34: %v", err)
		}
		resetLink(t, s, o) // row 34: SecUnResetIdle
	})
	t.Run("rows 20 and 21: unanswered while unreset", func(t *testing.T) {
		s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: 60 * time.Millisecond, Retries: 1}, Config{})
		errc := probeAsync(s)
		o.expect(link.PrimaryRequestLinkStatus)
		o.expect(link.PrimaryRequestLinkStatus) // row 21
		if err := result(t, errc); !errors.Is(err, dnp3.ErrTimeout) {
			t.Fatalf("row 20: %v", err)
		}
		resetLink(t, s, o)
	})
}

// TestSpec13_2_3_3_1_KeepAliveAnyAnswer checks clause 13.2.3.3.1 (p. 382)
// with Table 9-6 row 33 (p. 289): only a keep-alive that draws no answer
// deems the connection broken. An answer other than LINK_STATUS is
// counted as an error and the connection stays; silence closes a stream
// channel with ErrTimeout.
func TestSpec13_2_3_3_1_KeepAliveAnyAnswer(t *testing.T) {
	var m linkMetrics
	log := &warnLog{}
	a, b := tcpPair(t)
	ch := New(a, Config{Remote: a.RemoteAddr(), Metrics: &m, Log: logx.New(log, "test")})
	ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true,
		KeepAlive: 80 * time.Millisecond, ResponseTimeout: 80 * time.Millisecond})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	o := &station{rawPeer: newRaw(t, b), self: outstationAddr, peer: masterAddr}
	for _, answer := range []link.Function{link.SecondaryNotSupported, link.SecondaryAck, link.SecondaryNack, link.SecondaryLinkStatus} {
		o.expect(link.PrimaryRequestLinkStatus)
		o.write(o.sec(answer, false))
	}
	o.expect(link.PrimaryRequestLinkStatus) // the channel is still open
	select {
	case <-ch.Closing():
		t.Fatalf("closed after answered keep-alives: %v", ch.Err())
	default:
	}
	if n := m.decode.Load(); n != 3 {
		t.Fatalf("%d answers counted as errors, want 3", n)
	}
	if !log.has("keep-alive answered with another function") {
		t.Fatal("the other answers were not logged")
	}
	// This one goes unanswered.
	select {
	case <-ch.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("an unanswered keep-alive did not close the channel")
	}
	if !errors.Is(ch.Err(), dnp3.ErrTimeout) {
		t.Fatalf("Err = %v", ch.Err())
	}
}

// TestSpec13_2_3_3_1_KeepAliveRestartsOnReceive checks clause 13.2.3.3.1
// (p. 382): the keep-alive timer restarts whenever a message is received
// from the other end, so a peer that keeps sending is never probed; when
// it falls silent, REQUEST_LINK_STATUS goes out.
func TestSpec13_2_3_3_1_KeepAliveRestartsOnReceive(t *testing.T) {
	a, b := tcpPair(t)
	ch := New(a, Config{Remote: a.RemoteAddr()})
	ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true,
		KeepAlive: 300 * time.Millisecond, ResponseTimeout: time.Second})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	o := newRaw(t, b)
	frames := make(chan link.Frame, 16)
	go func() {
		for {
			f, err := o.r.ReadFrame()
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	data := link.Frame{Function: link.PrimaryUnconfirmedUserData, Dest: masterAddr, Src: outstationAddr, Data: segmentOf([]byte{1})}
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	until := time.After(700 * time.Millisecond)
loop:
	for {
		select {
		case <-tick.C:
			o.write(data)
		case f := <-frames:
			t.Fatalf("probed while the peer was sending: %s", f.String())
		case <-until:
			break loop
		}
	}
	tick.Stop()
	select {
	case f := <-frames:
		if f.Function != link.PrimaryRequestLinkStatus {
			t.Fatalf("after the peer fell silent: %s", f.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no keep-alive after the peer fell silent")
	}
}

// datagrams is an in-memory datagram socket: each send arrives as one
// whole datagram, each write leaves as one. Its peer is known from the
// first datagram received, as a UDP socket's is.
type datagrams struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	peer   net.Addr
}

func newDatagrams() *datagrams {
	return &datagrams{in: make(chan []byte, 16), out: make(chan []byte, 64), closed: make(chan struct{})}
}

func (d *datagrams) ReadDatagram() ([]byte, error) {
	select {
	case b := <-d.in:
		d.mu.Lock()
		d.peer = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
		d.mu.Unlock()
		return b, nil
	case <-d.closed:
		return nil, net.ErrClosed
	}
}

func (d *datagrams) Read([]byte) (int, error) {
	return 0, errors.New("a datagram socket is read with ReadDatagram")
}

func (d *datagrams) Write(b []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, net.ErrClosed
	case d.out <- bytes.Clone(b):
		return len(b), nil
	default:
		return len(b), nil // lost, as a datagram may be
	}
}

func (d *datagrams) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *datagrams) Peer() net.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peer
}

// send delivers one datagram holding octets.
func (d *datagrams) send(octets ...[]byte) { d.in <- bytes.Join(octets, nil) }

// next returns the next datagram written.
func (d *datagrams) next(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-d.out:
		return b
	case <-time.After(3 * time.Second):
		t.Fatal("no datagram sent")
		return nil
	}
}

// nextFrame returns the frame of the next datagram written, which must
// hold exactly one whole frame (clause 13.2.3.2.3).
func (d *datagrams) nextFrame(t *testing.T) link.Frame {
	t.Helper()
	b := d.next(t)
	f, n, err := link.Decode(b)
	if err != nil || n != len(b) {
		t.Fatalf("datagram of %d octets: %d decoded, %v", len(b), n, err)
	}
	return f
}

func encode(t *testing.T, f link.Frame) []byte {
	t.Helper()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// datagramOutstation returns an outstation session on a datagram socket.
func datagramOutstation(t *testing.T, cfg SessionConfig, ccfg Config) (*Channel, *datagrams, *inbox) {
	t.Helper()
	d := newDatagrams()
	in := newInbox()
	ch := New(d, ccfg)
	cfg.Local, cfg.Remote, cfg.OnFragment = outstationAddr, masterAddr, in.fn
	ch.AddSession(cfg)
	ch.Start()
	t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
	return ch, d, in
}

var (
	rls   = link.Frame{Dir: true, Function: link.PrimaryRequestLinkStatus, Dest: outstationAddr, Src: masterAddr}
	udata = func(b ...byte) link.Frame {
		return link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: masterAddr, Data: segmentOf(b)}
	}
)

// TestSpec13_2_3_3_1_DatagramKeepAlive checks the keep-alive on a
// datagram socket. Clause 13.2.3.3.1 (p. 382-383) monitors a TCP
// connection, and Table 13-2 closes connections; a UDP socket has none.
// Before any master sent a datagram nobody is probed; an unanswered probe
// is logged, and the socket keeps serving and probing.
func TestSpec13_2_3_3_1_DatagramKeepAlive(t *testing.T) {
	ch, d, in := datagramOutstation(t, SessionConfig{KeepAlive: 40 * time.Millisecond, ResponseTimeout: 30 * time.Millisecond}, Config{})
	select {
	case b := <-d.out:
		t.Fatalf("a datagram before any peer: % x", b)
	case <-time.After(200 * time.Millisecond):
	}
	d.send(encode(t, udata(1)))
	if got := in.next(t); !bytes.Equal(got.frag, []byte{1}) {
		t.Fatal("first datagram")
	}
	for range 3 {
		if f := d.nextFrame(t); f.Function != link.PrimaryRequestLinkStatus || f.Dest != masterAddr {
			t.Fatalf("probe %s", f.String())
		}
	}
	select {
	case <-ch.Closing():
		t.Fatalf("unanswered keep-alives closed the socket: %v", ch.Err())
	default:
	}
	d.send(encode(t, udata(2)))
	if got := in.next(t); !bytes.Equal(got.frag, []byte{2}) {
		t.Fatal("a datagram after the failed keep-alives")
	}
}

// TestSpec13_2_3_2_3_SeveralFramesPerDatagram checks clause 13.2.3.2.3
// (p. 382): every link frame of one datagram is taken, and each frame
// sent goes in a datagram of its own.
func TestSpec13_2_3_2_3_SeveralFramesPerDatagram(t *testing.T) {
	_, d, in := datagramOutstation(t, SessionConfig{}, Config{})
	var sg transport.Segmenter
	var octets [][]byte
	octets = append(octets, encode(t, rls))
	for _, s := range sg.Segment(payload(700)) {
		octets = append(octets, encode(t, link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: masterAddr, Data: s}))
	}
	octets = append(octets, encode(t, rls))
	d.send(octets...)
	for range 2 {
		if f := d.nextFrame(t); f.Function != link.SecondaryLinkStatus {
			t.Fatalf("reply %s", f.String())
		}
	}
	if got := in.next(t); !bytes.Equal(got.frag, payload(700)) {
		t.Fatal("the fragment of the datagram's frames")
	}
}

// TestSpec13_2_3_2_3_FrameCutAtDatagramEnd checks clause 13.2.3.2.3 (p.
// 382) with 9.2.9 (p. 285): a frame does not span datagrams, so one cut
// at the end of a datagram is discarded as a framing error, and the
// octets of the next datagram are not taken as its rest.
func TestSpec13_2_3_2_3_FrameCutAtDatagramEnd(t *testing.T) {
	var m linkMetrics
	_, d, _ := datagramOutstation(t, SessionConfig{}, Config{Metrics: &m})
	long := encode(t, link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: outstationAddr, Src: masterAddr, Data: payload(link.MaxUserData)})
	// A frame and the first 60 octets of a 292-octet one.
	d.send(encode(t, rls), long[:60])
	if f := d.nextFrame(t); f.Function != link.SecondaryLinkStatus {
		t.Fatalf("reply %s", f.String())
	}
	// The next datagram is read on its own.
	d.send(encode(t, rls))
	if f := d.nextFrame(t); f.Function != link.SecondaryLinkStatus {
		t.Fatalf("reply after the cut frame %s", f.String())
	}
	if m.framing.Load() != 1 {
		t.Fatalf("%d framing errors, want 1", m.framing.Load())
	}
	// A datagram that is only a cut header.
	d.send(long[:5])
	d.send(encode(t, rls))
	if f := d.nextFrame(t); f.Function != link.SecondaryLinkStatus {
		t.Fatalf("reply after a cut header %s", f.String())
	}
}

// TestSpec13_2_3_2_3_OneFramePerWrite checks clause 9.2.4.4 (p. 281) and
// 13.2.3.2.3 (p. 382): a frame is written whole, without gaps, in one
// write, so on a datagram socket each datagram is exactly one frame.
func TestSpec13_2_3_2_3_OneFramePerWrite(t *testing.T) {
	d := newDatagrams()
	ch := New(d, Config{})
	s := ch.AddSession(SessionConfig{Local: outstationAddr, Remote: masterAddr})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	frag := payload(2048)
	if err := s.Send(context.Background(), frag); err != nil {
		t.Fatal(err)
	}
	r := transport.NewReassembler(0)
	var got []byte
	for i := range 9 {
		f := d.nextFrame(t)
		if f.Function != link.PrimaryUnconfirmedUserData || f.Dir || len(f.Data) != min(link.MaxUserData, 2048-i*249+1) {
			t.Fatalf("frame %d: %s", i, f.String())
		}
		var err error
		if got, err = r.Add(f.Data); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, frag) {
		t.Fatal("the frames did not carry the fragment")
	}
}

// TestSpec10_4_1_Rule1_BackToBackFrames checks clause 10.4.1 rule 1 and
// 10.4.3 (p. 305): a master takes every frame of a 2048-octet fragment,
// nine frames, and one more, sent back to back in one write as
// UNCONFIRMED_USER_DATA.
func TestSpec10_4_1_Rule1_BackToBackFrames(t *testing.T) {
	_, o := masterStation(t, SessionConfig{}, Config{})
	var sg transport.Segmenter
	var b []byte
	frames := 0
	for _, frag := range [][]byte{payload(2048), {0xC0, 0x81}} {
		for _, s := range sg.Segment(frag) {
			b = append(b, encode(t, link.Frame{Function: link.PrimaryUnconfirmedUserData, Dest: masterAddr, Src: outstationAddr, Data: s})...)
			frames++
		}
	}
	if frames != 10 {
		t.Fatalf("%d frames", frames)
	}
	if _, err := o.conn.Write(b); err != nil {
		t.Fatal(err)
	}
	o.delivered(payload(2048))
	o.delivered([]byte{0xC0, 0x81})
}

// TestSpec10_4_2_AckBeforeResponse checks clause 10.4.2 (p. 305): for a
// request in CONFIRMED_USER_DATA the outstation sends the link ACK first,
// then the frame of its response, back to back.
func TestSpec10_4_2_AckBeforeResponse(t *testing.T) {
	a, b := tcpPair(t)
	ch := New(b, Config{})
	var s *Session
	s = ch.AddSession(SessionConfig{Local: outstationAddr, Remote: masterAddr, OnFragment: func(frag []byte, _ link.Address) {
		_ = s.Send(context.Background(), append([]byte{0xAB}, frag...))
	}})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	m := &station{rawPeer: newRaw(t, a), self: masterAddr, peer: outstationAddr, dir: true}
	m.write(m.pri(link.PrimaryResetLinkStates, false, nil))
	m.expect(link.SecondaryAck)
	m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1, 2})))
	m.expect(link.SecondaryAck)
	if f := m.expect(link.PrimaryUnconfirmedUserData); !bytes.Equal(f.Data[1:], []byte{0xAB, 1, 2}) {
		t.Fatalf("response %s", f.String())
	}
}

// TestSpec10_4_4_FramesForOthers checks clause 10.4.4 (p. 305): an
// outstation takes the frames addressed to itself from a stream that also
// carries, back to back, frames to and from other stations, and answers
// only its own.
func TestSpec10_4_4_FramesForOthers(t *testing.T) {
	_, m := outstationStation(t, SessionConfig{}, Config{})
	other := func(fn link.Function, dest, src link.Address, data []byte) link.Frame {
		return link.Frame{Dir: true, Function: fn, Dest: dest, Src: src, Data: data}
	}
	var b []byte
	for _, f := range []link.Frame{
		other(link.PrimaryRequestLinkStatus, 99, masterAddr, nil),
		m.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{1})),
		other(link.PrimaryUnconfirmedUserData, 98, 2, segmentOf([]byte{9})),
		{Function: link.SecondaryLinkStatus, Dest: masterAddr, Src: 97}, // another outstation's answer
		m.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{2})),
		m.pri(link.PrimaryRequestLinkStatus, false, nil),
	} {
		b = append(b, encode(t, f)...)
	}
	if _, err := m.conn.Write(b); err != nil {
		t.Fatal(err)
	}
	m.expect(link.SecondaryLinkStatus)
	m.delivered([]byte{1})
	m.delivered([]byte{2})
	m.noReply()
}

// TestSpec9_2_4_1_3_1_DIRIgnored checks clause 9.2.4.1.3.1 (p. 277):
// receivers should ignore the DIR bit. Frames whose DIR is that of the
// receiving station's own role are taken, in both roles.
func TestSpec9_2_4_1_3_1_DIRIgnored(t *testing.T) {
	_, m := outstationStation(t, SessionConfig{}, Config{})
	m.dir = false // a master that clears DIR
	m.write(m.pri(link.PrimaryRequestLinkStatus, false, nil))
	m.expect(link.SecondaryLinkStatus)
	m.write(m.pri(link.PrimaryResetLinkStates, false, nil))
	m.expect(link.SecondaryAck)
	m.write(m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1})))
	m.expect(link.SecondaryAck)
	m.delivered([]byte{1})
	m.write(m.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{2})))
	m.delivered([]byte{2})

	_, o := masterStation(t, SessionConfig{}, Config{})
	o.dir = true // an outstation that sets DIR
	o.write(o.pri(link.PrimaryRequestLinkStatus, false, nil))
	o.expect(link.SecondaryLinkStatus)
	o.write(o.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{3})))
	o.delivered([]byte{3})
}

// TestSpec9_2_3_DIRByRole checks clause 9.2.3 (p. 276) and 9.2.4.1.3.1
// (p. 277): a master sets DIR in every frame it sends, primary or
// secondary; an outstation clears it. The outstation's unconfirmed data
// frame is control octet 0x44 (FCB and FCV clear, 9.2.4.1.3.3 and
// 9.2.4.1.3.4).
func TestSpec9_2_3_DIRByRole(t *testing.T) {
	s, o := masterStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	errc := sendAsync(s, []byte{1})
	for _, fn := range []link.Function{link.PrimaryResetLinkStates, link.PrimaryConfirmedUserData} {
		if f := o.expect(fn); !f.Dir {
			t.Fatalf("master %s without DIR", fn)
		}
		o.write(o.sec(link.SecondaryAck, false))
	}
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
	if err := s.SendBroadcast(context.Background(), []byte{2}, link.BroadcastNoConfirm); err != nil {
		t.Fatal(err)
	}
	if f := o.read(); f.Function != link.PrimaryUnconfirmedUserData || f.Control() != 0xC4 {
		t.Fatalf("master unconfirmed data %s", f.String())
	}
	o.write(o.pri(link.PrimaryRequestLinkStatus, false, nil))
	if f := o.expect(link.SecondaryLinkStatus); !f.Dir {
		t.Fatal("master LINK_STATUS without DIR")
	}
	o.write(o.pri(link.PrimaryResetLinkStates, false, nil))
	if f := o.expect(link.SecondaryAck); !f.Dir {
		t.Fatal("master ACK without DIR")
	}
	o.write(o.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{3})))
	if f := o.expect(link.SecondaryAck); !f.Dir {
		t.Fatal("master ACK of confirmed data without DIR")
	}
	o.delivered([]byte{3})

	os, m := outstationStation(t, SessionConfig{Confirmed: true, ResponseTimeout: time.Second}, Config{})
	errc = sendAsync(os, []byte{4})
	for _, fn := range []link.Function{link.PrimaryResetLinkStates, link.PrimaryConfirmedUserData} {
		if f := m.expect(fn); f.Dir {
			t.Fatalf("outstation %s with DIR", fn)
		}
		m.write(m.sec(link.SecondaryAck, false))
	}
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
	u, m2 := outstationStation(t, SessionConfig{}, Config{})
	if err := u.Send(context.Background(), []byte{5}); err != nil {
		t.Fatal(err)
	}
	if f := m2.expect(link.PrimaryUnconfirmedUserData); f.Control() != 0x44 {
		t.Fatalf("outstation unconfirmed data: control %#02x", f.Control())
	}
}

// TestSpec9_2_4_1_3_6_MasterAsSecondary checks clause 9.2.4.1.3.6 (p. 280)
// and the 9.2.6.5 NOTE (p. 284): every device, the master too, processes
// the primary function codes 0, 2, 3, 4 and 9, and never answers them with
// NOT_SUPPORTED. The master answers an outstation's keep-alive.
func TestSpec9_2_4_1_3_6_MasterAsSecondary(t *testing.T) {
	_, o := masterStation(t, SessionConfig{}, Config{})
	o.write(o.pri(link.PrimaryRequestLinkStatus, false, nil))
	o.expect(link.SecondaryLinkStatus)
	o.write(o.pri(link.PrimaryResetLinkStates, false, nil))
	o.expect(link.SecondaryAck)
	o.write(o.pri(link.PrimaryTestLinkStates, true, nil))
	o.expect(link.SecondaryAck)
	o.write(o.pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{1})))
	o.expect(link.SecondaryAck)
	o.delivered([]byte{1})
	o.write(o.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{2})))
	o.delivered([]byte{2})
	o.noReply()
}

// TestSpec9_2_5_2_2_SelfAddress checks clause 9.2.5.2.2 (p. 282): a
// station processes frames to the self address 0xFFFC only with the
// feature enabled (it is disabled by default, and a master never has it),
// and then answers with its individual address as source; with two
// stations on one channel only the enabled one answers.
func TestSpec9_2_5_2_2_SelfAddress(t *testing.T) {
	self := func(s *station, fn link.Function, fcb bool, data []byte) link.Frame {
		f := s.pri(fn, fcb, data)
		f.Dest = link.SelfAddress
		return f
	}
	t.Run("disabled", func(t *testing.T) {
		_, m := outstationStation(t, SessionConfig{}, Config{})
		m.write(self(m, link.PrimaryRequestLinkStatus, false, nil))
		m.write(self(m, link.PrimaryResetLinkStates, false, nil))
		m.write(self(m, link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{1})))
		m.noReply()
		m.notDelivered()
	})
	t.Run("enabled", func(t *testing.T) {
		_, m := outstationStation(t, SessionConfig{SelfAddress: true}, Config{})
		m.write(self(m, link.PrimaryRequestLinkStatus, false, nil))
		if f := m.expect(link.SecondaryLinkStatus); f.Src != outstationAddr {
			t.Fatalf("source %d", f.Src)
		}
		m.write(self(m, link.PrimaryResetLinkStates, false, nil))
		m.expect(link.SecondaryAck)
		m.write(self(m, link.PrimaryConfirmedUserData, true, segmentOf([]byte{2})))
		m.expect(link.SecondaryAck)
		if d := m.in.next(t); !bytes.Equal(d.frag, []byte{2}) || d.dest != link.SelfAddress {
			t.Fatalf("delivered %v to %#04x", d.frag, uint16(d.dest))
		}
	})
	t.Run("master", func(t *testing.T) {
		_, o := masterStation(t, SessionConfig{}, Config{})
		o.write(self(o, link.PrimaryRequestLinkStatus, false, nil))
		o.write(self(o, link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{3})))
		o.noReply()
		o.notDelivered()
	})
	t.Run("one of two", func(t *testing.T) {
		a, b := tcpPair(t)
		ch := New(b, Config{})
		ch.AddSession(SessionConfig{Local: 10, Remote: masterAddr, SelfAddress: true})
		ch.AddSession(SessionConfig{Local: 11, Remote: masterAddr})
		ch.Start()
		defer func() { ch.Close(nil); <-ch.Done() }()
		m := &station{rawPeer: newRaw(t, a), self: masterAddr, peer: 10, dir: true}
		m.write(self(m, link.PrimaryRequestLinkStatus, false, nil))
		if f := m.expect(link.SecondaryLinkStatus); f.Src != 10 {
			t.Fatalf("answered by %d", f.Src)
		}
		m.noReply() // no second answer before it
	})
}

// TestSpec9_2_5_2_1_Broadcast checks clauses 9.2.4.1.3.6 (p. 280) and
// 9.2.5.2.1 (p. 282): a station accepts frames to the three broadcast
// addresses, never replies to them whatever the function code, and passes
// the destination up with the user data.
func TestSpec9_2_5_2_1_Broadcast(t *testing.T) {
	_, m := outstationStation(t, SessionConfig{}, Config{})
	m.write(m.pri(link.PrimaryResetLinkStates, false, nil))
	m.expect(link.SecondaryAck)
	for _, dest := range []link.Address{link.BroadcastNoConfirm, link.BroadcastConfirm, link.BroadcastOptionalConfirm} {
		for _, f := range []link.Frame{
			m.pri(link.PrimaryResetLinkStates, false, nil),
			m.pri(link.PrimaryTestLinkStates, true, nil),
			m.pri(link.PrimaryRequestLinkStatus, false, nil),
			m.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{0xBB})),
		} {
			f.Dest = dest
			m.write(f)
			m.noReply()
		}
		for range 2 { // the confirmed data may be passed up, or not
			m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: dest, Src: masterAddr, Data: segmentOf([]byte{byte(dest & 0xFF)})})
			for {
				d := m.in.next(t)
				if bytes.Equal(d.frag, []byte{0xBB}) {
					continue
				}
				if !bytes.Equal(d.frag, []byte{byte(dest & 0xFF)}) || d.dest != dest {
					t.Fatalf("broadcast to %#04x delivered %v to %#04x", uint16(dest), d.frag, uint16(d.dest))
				}
				break
			}
		}
	}
	// A master ignores broadcasts (clauses 4 to 6 define them for
	// outstations only).
	_, o := masterStation(t, SessionConfig{}, Config{})
	o.write(link.Frame{Function: link.PrimaryUnconfirmedUserData, Dest: link.BroadcastOptionalConfirm, Src: outstationAddr, Data: segmentOf([]byte{1})})
	o.notDelivered()
}

// TestSpec9_2_6_1_IndependentPairs checks clauses 9.2.6.1 (p. 283) and
// 9.2.8 (p. 285): the link states of each station pair are kept apart, so
// a reset of one pair, and its frame count bits, do not touch another on
// the same stream.
func TestSpec9_2_6_1_IndependentPairs(t *testing.T) {
	a, b := tcpPair(t)
	in10, in11 := newInbox(), newInbox()
	ch := New(b, Config{})
	ch.AddSession(SessionConfig{Local: 10, Remote: masterAddr, OnFragment: in10.fn})
	ch.AddSession(SessionConfig{Local: 11, Remote: masterAddr, OnFragment: in11.fn})
	ch.Start()
	defer func() { ch.Close(nil); <-ch.Done() }()
	raw := newRaw(t, a)
	m10 := &station{rawPeer: raw, self: masterAddr, peer: 10, dir: true, in: in10}
	m11 := &station{rawPeer: raw, self: masterAddr, peer: 11, dir: true, in: in11}
	m10.write(m10.pri(link.PrimaryResetLinkStates, false, nil))
	m10.expect(link.SecondaryAck)
	m11.write(m11.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{1})))
	m11.noReply() // 11 is still unreset
	m10.write(m10.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{2})))
	m10.expect(link.SecondaryAck)
	m10.delivered([]byte{2})
	m11.write(m11.pri(link.PrimaryResetLinkStates, false, nil))
	m11.expect(link.SecondaryAck)
	// 10 expects FCB 0 now, 11 expects 1.
	m11.write(m11.pri(link.PrimaryConfirmedUserData, true, segmentOf([]byte{3})))
	m11.expect(link.SecondaryAck)
	m11.delivered([]byte{3})
	m10.write(m10.pri(link.PrimaryConfirmedUserData, false, segmentOf([]byte{4})))
	m10.expect(link.SecondaryAck)
	m10.delivered([]byte{4})
}

// TestSpec8_2_1_4_Rule5_3_RepeatedFrame checks rule 5.3 of clause 8.2.1.4
// (p. 269) on a channel: an UNCONFIRMED_USER_DATA frame repeated in the
// middle of a fragment is discarded, the fragment is delivered once, and
// the repeat is not counted as an error.
func TestSpec8_2_1_4_Rule5_3_RepeatedFrame(t *testing.T) {
	var met linkMetrics
	_, m := outstationStation(t, SessionConfig{}, Config{Metrics: &met})
	var sg transport.Segmenter
	segs := sg.Segment(payload(600))
	for _, s := range [][]byte{segs[0], segs[1], segs[1], segs[2]} {
		m.write(m.pri(link.PrimaryUnconfirmedUserData, false, s))
	}
	m.delivered(payload(600))
	m.notDelivered()
	if met.decode.Load() != 0 {
		t.Fatalf("%d decode errors for a repeated segment", met.decode.Load())
	}
}

// TestSpec13_2_1_1_ConfirmedOnNetworkWarns checks the warning for clause
// 13.2.1.1 (p. 377): devices shall not send CONFIRMED_USER_DATA over IP.
// A confirmed session on a TCP connection or a datagram socket logs it; a
// serial-like stream or an unconfirmed session does not.
func TestSpec13_2_1_1_ConfirmedOnNetworkWarns(t *testing.T) {
	const warning = "13.2.1.1"
	tcp, _ := tcpPair(t)
	pipe, other := net.Pipe()
	defer func() { _ = pipe.Close(); _ = other.Close() }()
	for _, c := range []struct {
		name      string
		s         Stream
		confirmed bool
		warns     bool
	}{
		{"TCP confirmed", tcp, true, true},
		{"datagram confirmed", newDatagrams(), true, true},
		{"pipe confirmed", pipe, true, false},
		{"TCP unconfirmed", tcp, false, false},
	} {
		log := &warnLog{}
		ch := New(c.s, Config{Log: logx.New(log, "test")})
		ch.AddSession(SessionConfig{Local: 1, Remote: 2, Master: true, Confirmed: c.confirmed})
		if log.has(warning) != c.warns {
			t.Errorf("%s: warning %v, want %v", c.name, log.has(warning), c.warns)
		}
		for _, s := range ch.Sessions() {
			s.Remove()
		}
	}
}

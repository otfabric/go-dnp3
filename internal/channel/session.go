// SPDX-License-Identifier: MIT

package channel

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// SessionConfig configures one association on a channel.
type SessionConfig struct {
	// Local and Remote are the link addresses of this station and of the
	// peer.
	Local, Remote link.Address

	// Master is set for the master end: it sets the DIR bit of every
	// frame, and frames from the peer must have it clear. A master ignores
	// broadcast frames.
	Master bool

	// Confirmed selects CONFIRMED_USER_DATA, preceded by a reset of the
	// link states, instead of UNCONFIRMED_USER_DATA. IEEE 1815-2012
	// recommends unconfirmed user data on TCP.
	Confirmed bool

	// ResponseTimeout is how long a primary frame waits for its secondary
	// answer (ACK, LINK_STATUS). Zero means 2 seconds.
	ResponseTimeout time.Duration

	// Retries is the number of times a primary frame is repeated after a
	// timeout.
	Retries int

	// KeepAlive is the idle time after which REQUEST_LINK_STATUS is sent.
	// A peer that does not answer closes the channel. Zero disables it.
	KeepAlive time.Duration

	// MaxFragment is the largest fragment reassembled; zero means
	// transport.DefaultMaxFragment.
	MaxFragment int

	// QueueSize is the number of reassembled fragments that may wait for
	// OnFragment. Fragments beyond it are dropped. Zero means 64.
	QueueSize int

	// OnFragment receives every reassembled fragment, in order, on the
	// session's goroutine. dest is the destination address of the frames
	// that carried it: Local, a broadcast address or the self address.
	OnFragment func(frag []byte, dest link.Address)
}

// Session is one association on a channel.
type Session struct {
	ch  *Channel
	cfg SessionConfig

	// Primary side: one transaction (and one fragment) at a time.
	pmu       sync.Mutex
	seg       transport.Segmenter
	fcb       bool
	linkReset bool
	secCh     chan link.Frame
	waiting   atomic.Bool

	// Secondary side and reassembly: reader goroutine only.
	secReset  bool
	expectFCB bool
	reasm     *transport.Reassembler

	lastRx  atomic.Int64
	queue   chan delivery
	removed chan struct{}
	rmOnce  sync.Once
}

type delivery struct {
	frag []byte
	dest link.Address
}

func newSession(c *Channel, cfg SessionConfig) *Session {
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = 2 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 64
	}
	s := &Session{
		ch:      c,
		cfg:     cfg,
		secCh:   make(chan link.Frame, 1),
		reasm:   transport.NewReassembler(cfg.MaxFragment),
		queue:   make(chan delivery, cfg.QueueSize),
		removed: make(chan struct{}),
	}
	s.lastRx.Store(time.Now().UnixNano())
	return s
}

// Local returns the link address of this station.
func (s *Session) Local() link.Address { return s.cfg.Local }

// Remote returns the link address of the peer.
func (s *Session) Remote() link.Address { return s.cfg.Remote }

// Channel returns the channel of the session.
func (s *Session) Channel() *Channel { return s.ch }

// Remove stops the session's goroutines; frames for its address pair are
// then handed to Accept again.
func (s *Session) Remove() {
	s.rmOnce.Do(func() {
		s.ch.mu.Lock()
		if s.ch.sessions[key{s.cfg.Local, s.cfg.Remote}] == s {
			delete(s.ch.sessions, key{s.cfg.Local, s.cfg.Remote})
		}
		s.ch.mu.Unlock()
		close(s.removed)
	})
}

func (s *Session) run() {
	defer s.ch.wg.Done()
	var keepAlive <-chan time.Time
	var timer *time.Timer
	if s.cfg.KeepAlive > 0 {
		timer = time.NewTimer(s.cfg.KeepAlive)
		defer timer.Stop()
		keepAlive = timer.C
	}
	probe := make(chan error, 1)
	probing := false
	for {
		select {
		case <-s.ch.closing:
			// Fragments that arrived before the stream ended are delivered:
			// a peer may confirm a response and hang up at once, and that
			// confirmation counts.
			s.drain()
			return
		case <-s.removed:
			return
		case d := <-s.queue:
			if s.cfg.OnFragment != nil {
				s.cfg.OnFragment(d.frag, d.dest)
			}
		case <-keepAlive:
			idle := time.Since(time.Unix(0, s.lastRx.Load()))
			if idle < s.cfg.KeepAlive || probing {
				timer.Reset(max(s.cfg.KeepAlive-idle, time.Millisecond))
				continue
			}
			// Probe on another goroutine so that delivery goes on.
			probing = true
			go func() { probe <- s.requestLinkStatus() }()
			timer.Reset(s.cfg.KeepAlive)
		case err := <-probe:
			probing = false
			if err != nil {
				s.ch.cfg.Log.Warn("keep-alive failed", "remote_addr", s.cfg.Remote, "error", err)
				s.ch.Close(fmt.Errorf("%w: no answer to REQUEST_LINK_STATUS: %w", dnp3.ErrTimeout, err))
				return
			}
		}
	}
}

// drain delivers the fragments still queued. The reader has stopped by
// the time the stream is closed by the peer, so nothing is added while it
// runs.
func (s *Session) drain() {
	for {
		select {
		case d := <-s.queue:
			if s.cfg.OnFragment != nil {
				s.cfg.OnFragment(d.frag, d.dest)
			}
		default:
			return
		}
	}
}

// Send splits frag into segments and sends them, one frame each. It
// returns when the last frame was written (unconfirmed) or acknowledged
// (confirmed). Fragments of one session are sent one at a time.
func (s *Session) Send(ctx context.Context, frag []byte) error {
	return s.send(ctx, frag, s.cfg.Remote)
}

// SendBroadcast sends frag to a broadcast address, always as unconfirmed
// user data.
func (s *Session) SendBroadcast(ctx context.Context, frag []byte, dest link.Address) error {
	if !dest.Broadcast() {
		return fmt.Errorf("%w: %d is not a broadcast address", dnp3.ErrInvalidOption, dest)
	}
	return s.send(ctx, frag, dest)
}

func (s *Session) send(ctx context.Context, frag []byte, dest link.Address) error {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if err := s.alive(ctx); err != nil {
		return err
	}
	confirmed := s.cfg.Confirmed && !dest.Broadcast()
	for _, seg := range s.seg.Segment(frag) {
		f := link.Frame{Dir: s.cfg.Master, Dest: dest, Src: s.cfg.Local, Data: seg}
		if !confirmed {
			f.Function = link.PrimaryUnconfirmedUserData
			if err := s.ch.writeFrame(&f); err != nil {
				return err
			}
			continue
		}
		if err := s.sendConfirmed(ctx, &f); err != nil {
			return err
		}
	}
	return nil
}

// sendConfirmed sends one segment as CONFIRMED_USER_DATA, resetting the
// link first when needed. A NACK means the secondary lost its link state:
// the link is reset and the frame repeated once.
func (s *Session) sendConfirmed(ctx context.Context, f *link.Frame) error {
	for attempt := 0; ; attempt++ {
		if !s.linkReset {
			reset := link.Frame{Dir: s.cfg.Master, Function: link.PrimaryResetLinkStates, Dest: f.Dest, Src: s.cfg.Local}
			r, err := s.transact(ctx, &reset)
			if err != nil {
				return err
			}
			if r.Function != link.SecondaryAck {
				return fmt.Errorf("%w: reset of link states answered with %s", dnp3.ErrProtocol, r.Function)
			}
			s.linkReset, s.fcb = true, true
		}
		f.Function, f.FCV, f.FCB = link.PrimaryConfirmedUserData, true, s.fcb
		r, err := s.transact(ctx, f)
		if err != nil {
			s.linkReset = false
			return err
		}
		switch {
		case r.Function == link.SecondaryAck:
			s.fcb = !s.fcb
			return nil
		case r.Function == link.SecondaryNack && attempt == 0:
			s.linkReset = false
		default:
			s.linkReset = false
			return fmt.Errorf("%w: confirmed user data answered with %s", dnp3.ErrProtocol, r.Function)
		}
	}
}

// requestLinkStatus sends REQUEST_LINK_STATUS and waits for LINK_STATUS.
func (s *Session) requestLinkStatus() error {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	f := link.Frame{Dir: s.cfg.Master, Function: link.PrimaryRequestLinkStatus, Dest: s.cfg.Remote, Src: s.cfg.Local}
	r, err := s.transact(context.Background(), &f)
	if err != nil {
		return err
	}
	if r.Function != link.SecondaryLinkStatus {
		return fmt.Errorf("%w: request link status answered with %s", dnp3.ErrProtocol, r.Function)
	}
	return nil
}

// transact writes a primary frame and waits for the secondary answer,
// repeating the frame up to Retries times on timeout. The caller holds pmu.
func (s *Session) transact(ctx context.Context, f *link.Frame) (link.Frame, error) {
	timer := time.NewTimer(s.cfg.ResponseTimeout)
	defer timer.Stop()
	s.waiting.Store(true)
	defer s.waiting.Store(false)
	for attempt := 0; ; attempt++ {
		select {
		case <-s.secCh: // a stale answer
		default:
		}
		if err := s.ch.writeFrame(f); err != nil {
			return link.Frame{}, err
		}
		timer.Reset(s.cfg.ResponseTimeout)
		select {
		case r := <-s.secCh:
			return r, nil
		case <-timer.C:
			if attempt >= s.cfg.Retries {
				return link.Frame{}, fmt.Errorf("%w: no link layer answer to %s after %d attempts", dnp3.ErrTimeout, f.Function, attempt+1)
			}
		case <-ctx.Done():
			return link.Frame{}, ctx.Err()
		case <-s.ch.closing:
			return link.Frame{}, s.ch.closedErr()
		case <-s.removed:
			return link.Frame{}, dnp3.ErrClosed
		}
	}
}

func (s *Session) alive(ctx context.Context) error {
	select {
	case <-s.ch.closing:
		return s.ch.closedErr()
	case <-s.removed:
		return dnp3.ErrClosed
	default:
		return ctx.Err()
	}
}

// handleFrame processes a frame on the reader goroutine.
func (s *Session) handleFrame(f link.Frame) {
	s.lastRx.Store(time.Now().UnixNano())
	log := s.ch.cfg.Log
	if f.Dir == s.cfg.Master {
		log.Debug("frame with the DIR bit of this station's role ignored", "frame", f.String())
		return
	}
	broadcast := f.Dest.Broadcast()
	if broadcast && s.cfg.Master {
		log.Debug("broadcast frame to a master ignored", "frame", f.String())
		return
	}
	if broadcast && !f.Function.HasData() {
		log.Debug("broadcast frame without user data ignored", "frame", f.String())
		return
	}
	if !f.Function.Primary() {
		if s.waiting.Load() {
			select {
			case s.secCh <- f:
			default:
			}
		} else {
			log.Debug("unsolicited secondary frame ignored", "frame", f.String())
		}
		return
	}
	if f.FCV != f.Function.UsesFCB() {
		log.Warn("frame with invalid FCV bit ignored", "frame", f.String())
		return
	}

	switch f.Function {
	case link.PrimaryUnconfirmedUserData:
		s.receive(f.Data, f.Dest)
	case link.PrimaryResetLinkStates:
		s.secReset, s.expectFCB = true, true
		s.reply(link.SecondaryAck)
	case link.PrimaryTestLinkStates:
		if !s.secReset {
			log.Debug("test link states while not reset ignored")
			return
		}
		if f.FCB == s.expectFCB {
			s.expectFCB = !s.expectFCB
		}
		s.reply(link.SecondaryAck)
	case link.PrimaryConfirmedUserData:
		if !s.secReset {
			log.Info("confirmed user data while the link is not reset ignored")
			return
		}
		if !broadcast {
			s.reply(link.SecondaryAck)
		}
		if f.FCB != s.expectFCB {
			log.Debug("repeated confirmed user data discarded", "frame", f.String())
			return
		}
		s.expectFCB = !s.expectFCB
		s.receive(f.Data, f.Dest)
	case link.PrimaryRequestLinkStatus:
		s.reply(link.SecondaryLinkStatus)
	default:
		s.reply(link.SecondaryNotSupported)
	}
}

func (s *Session) reply(fn link.Function) {
	f := link.Frame{Dir: s.cfg.Master, Function: fn, Dest: s.cfg.Remote, Src: s.cfg.Local}
	if err := s.ch.writeFrame(&f); err != nil {
		s.ch.cfg.Log.Debug("link reply not sent", "error", err)
	}
}

// receive feeds a segment to the reassembler and queues a completed
// fragment.
func (s *Session) receive(seg []byte, dest link.Address) {
	frag, err := s.reasm.Add(seg)
	if err != nil {
		s.ch.cfg.Log.Debug("segment discarded", "error", err)
		if s.ch.cfg.Metrics != nil {
			s.ch.cfg.Metrics.OnDecodeError(s.ch.cfg.Remote, err)
		}
		return
	}
	if frag == nil {
		return
	}
	select {
	case s.queue <- delivery{frag: frag, dest: dest}:
	default:
		err := fmt.Errorf("%w: receive queue full, fragment of %d octets dropped", dnp3.ErrProtocol, len(frag))
		s.ch.cfg.Log.Warn("fragment dropped", "error", err)
		if s.ch.cfg.Metrics != nil {
			s.ch.cfg.Metrics.OnDecodeError(s.ch.cfg.Remote, err)
		}
	}
}

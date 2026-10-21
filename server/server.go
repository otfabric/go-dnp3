// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
)

// DefaultPort is the registered DNP3 port.
const DefaultPort = 20000

// Server is a DNP3 outstation: a point database served to masters over
// any number of channels.
type Server struct {
	opts  options
	db    *Database
	clock *clock
	log   *logx.Logger
	sm    dnp3.ServerMetrics

	mu         sync.Mutex
	assocs     map[link.Address]*association
	channels   map[*channel.Channel]struct{}
	listeners  map[net.Listener]struct{}
	indication app.IIN
	freezes    map[*time.Timer]struct{} // scheduled FREEZE_AT_TIME
	closed     bool
	closeCh    chan struct{}
	wg         sync.WaitGroup
}

// New returns an outstation configured by opts. Add points to its
// Database, then serve it with ListenAndServe, Serve or ServeConn.
func New(opts ...Option) (*Server, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	s := &Server{
		opts:      o,
		clock:     newClock(),
		log:       logx.New(o.logger, "server", "outstation", o.address),
		freezes:   make(map[*time.Timer]struct{}),
		assocs:    make(map[link.Address]*association),
		channels:  make(map[*channel.Channel]struct{}),
		listeners: make(map[net.Listener]struct{}),
		closeCh:   make(chan struct{}),
	}
	s.sm, _ = o.metrics.(dnp3.ServerMetrics)
	s.db = newDatabase(s)
	for _, m := range o.masters {
		s.association(m)
	}
	return s, nil
}

// Database returns the point database.
func (s *Server) Database() *Database { return s.db }

// Address returns the link address of the outstation.
func (s *Server) Address() link.Address { return s.opts.address }

// Now returns the time of the outstation's clock, which time
// synchronization sets.
func (s *Server) Now() time.Time { return s.clock.time() }

// SetIndications sets or clears the application controlled internal
// indications of every association: app.IINLocalControl,
// app.IINDeviceTrouble and app.IINConfigCorrupt. Other bits are ignored.
func (s *Server) SetIndications(bits app.IIN, on bool) {
	bits &= app.IINLocalControl | app.IINDeviceTrouble | app.IINConfigCorrupt
	s.mu.Lock()
	if on {
		s.indication |= bits
	} else {
		s.indication &^= bits
	}
	s.mu.Unlock()
}

func (s *Server) indications() app.IIN {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.indication
}

// Restart behaves as after a restart of the outstation: every association
// reports IIN1.7 (DEVICE_RESTART) again, its event buffer is cleared,
// unsolicited responses start over with a null unsolicited response, and,
// with WithTimeSync, its time counts as unsynchronized until the next time
// synchronization (IIN1.4).
func (s *Server) Restart() {
	for _, a := range s.associations() {
		a.post(func() { a.restart() })
	}
}

func (s *Server) associations() []*association {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*association, 0, len(s.assocs))
	for _, a := range s.assocs {
		out = append(out, a)
	}
	return out
}

// association returns the association of master m, creating it. It
// returns nil once the server is closed.
func (s *Server) association(m link.Address) *association {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if a, ok := s.assocs[m]; ok {
		return a
	}
	a := newAssociation(s, m)
	s.assocs[m] = a
	s.wg.Add(1)
	go a.run()
	return a
}

func (s *Server) masterAllowed(m link.Address) bool {
	if len(s.opts.masters) == 0 {
		return m <= link.MaxStationAddress
	}
	for _, x := range s.opts.masters {
		if x == m {
			return true
		}
	}
	return false
}

// publish hands new events to every association.
func (s *Server) publish(evs []event) {
	for _, a := range s.associations() {
		discarded := a.events.add(evs)
		for c := 1; c <= 3; c++ {
			if discarded[c] > 0 {
				s.log.Warn("event buffer overflow", "master", a.master, "class", c, "discarded", discarded[c])
				if s.sm != nil {
					s.sm.OnEventsDiscarded(c, discarded[c])
				}
			}
		}
		a.wake()
	}
}

// ListenAndServe listens on the TCP address addr (":20000" when empty),
// with TLS when WithTLS was given, and serves until Close.
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if s.opts.tls != nil {
		l = tls.NewListener(l, s.opts.tls)
	}
	return s.Serve(l)
}

// Serve accepts connections on l and serves each until Close. It returns
// nil after Close, otherwise the error that stopped the listener.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = l.Close()
		return dnp3.ErrClosed
	}
	s.listeners[l] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, l)
		s.mu.Unlock()
	}()
	s.log.Info("listening", "address", l.Addr().String())
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		if s.connections() >= s.opts.maxConns {
			s.log.Warn("connection refused: limit reached", "remote", c.RemoteAddr().String(), "limit", s.opts.maxConns)
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.ServeConn(c, c.RemoteAddr())
		}()
	}
}

func (s *Server) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.channels)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ServeConn serves one stream, for example a serial port or a connection
// accepted elsewhere, until it ends or the server is closed. remote names
// the peer in logs and metrics and may be nil. It returns the reason the
// stream ended: nil after Close.
func (s *Server) ServeConn(rw io.ReadWriteCloser, remote net.Addr) error {
	return serveConn(rw, remote, []*Server{s})
}

// takes reports whether a frame to local is for the server: its own
// address, a broadcast address, or the self address when enabled.
func (s *Server) takes(local link.Address) bool {
	return local == s.opts.address || local.Broadcast() || (s.opts.selfAddress && local == link.SelfAddress)
}

// serveConn serves one stream for the outstations of servers, which have
// distinct addresses: each takes the frames to its address, all of them
// the broadcasts. The channel's metrics and log are the first server's.
func serveConn(rw io.ReadWriteCloser, remote net.Addr, servers []*Server) error {
	lead := servers[0]
	var ch *channel.Channel
	ch = channel.New(rw, channel.Config{
		Remote:  remote,
		Metrics: lead.opts.metrics,
		Log:     lead.log.With("remote", addrString(remote)),
		Accept: func(local, master link.Address) *channel.Session {
			var first *channel.Session
			for _, s := range servers {
				if !s.takes(local) {
					continue
				}
				if !s.masterAllowed(master) {
					s.log.Debug("frame from unknown master ignored", "master", master)
					continue
				}
				sess := ch.Session(s.opts.address, master)
				if sess == nil {
					sess = s.bind(ch, master)
				}
				if sess != nil && first == nil {
					first = sess
				}
			}
			return first
		},
	})
	for i, s := range servers {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			for _, o := range servers[:i] {
				o.mu.Lock()
				delete(o.channels, ch)
				o.mu.Unlock()
			}
			_ = rw.Close()
			return dnp3.ErrClosed
		}
		s.channels[ch] = struct{}{}
		s.mu.Unlock()
	}
	for _, s := range servers {
		s.log.Info("connection opened", "remote", addrString(remote))
		// With a single configured master the association is known before
		// the master speaks, so that the null unsolicited response can go
		// out.
		if len(s.opts.masters) == 1 {
			s.bind(ch, s.opts.masters[0])
		}
	}
	ch.Start()
	<-ch.Done()

	err := ch.Err()
	for _, s := range servers {
		s.mu.Lock()
		delete(s.channels, ch)
		s.mu.Unlock()
		s.log.Info("connection closed", "remote", addrString(remote), "error", err)
	}
	return err
}

// bind adds the session of master on ch and attaches it to the master's
// association.
func (s *Server) bind(ch *channel.Channel, master link.Address) *channel.Session {
	a := s.association(master)
	if a == nil {
		return nil
	}
	ka := s.opts.link.KeepAlive
	if ka == 0 {
		ka = 60 * time.Second
	}
	var sess *channel.Session
	sess = ch.AddSession(channel.SessionConfig{
		Local:           s.opts.address,
		Remote:          master,
		Confirmed:       s.opts.link.Confirmed,
		ResponseTimeout: s.opts.link.Timeout,
		Retries:         s.opts.link.Retries,
		KeepAlive:       max(ka, 0),
		MaxFragment:     s.opts.maxRxFragment,
		OnFragment: func(frag []byte, dest link.Address) {
			a.receive(sess, frag, dest)
		},
	})
	a.attach(sess)
	return sess
}

// CloseConnections closes every current client connection without
// stopping the listeners: masters may reconnect. Associations and their
// event buffers are kept.
func (s *Server) CloseConnections() {
	s.mu.Lock()
	chans := make([]*channel.Channel, 0, len(s.channels))
	for ch := range s.channels {
		chans = append(chans, ch)
	}
	s.mu.Unlock()
	for _, ch := range chans {
		ch.Close(nil)
	}
}

// Close stops the listeners, closes every connection and stops the
// associations. It waits for their goroutines to end.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	for t := range s.freezes {
		t.Stop()
	}
	clear(s.freezes)
	for l := range s.listeners {
		_ = l.Close()
	}
	chans := make([]*channel.Channel, 0, len(s.channels))
	for ch := range s.channels {
		chans = append(chans, ch)
	}
	assocs := make([]*association, 0, len(s.assocs))
	for _, a := range s.assocs {
		assocs = append(assocs, a)
	}
	s.mu.Unlock()
	for _, ch := range chans {
		ch.Close(nil)
	}
	for _, a := range assocs {
		a.close()
	}
	s.wg.Wait()
	return nil
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// clock is the outstation's time: the system clock plus the offset that
// time synchronization established.
type clock struct {
	mu     sync.Mutex
	offset time.Duration
}

func newClock() *clock { return &clock{} }

func (c *clock) time() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *clock) now() app.Timestamp { return app.TimestampOf(c.time()) }

// set makes the clock read t at the system time at.
func (c *clock) set(t, at time.Time) {
	c.mu.Lock()
	c.offset = t.Sub(at)
	c.mu.Unlock()
}

// handlerContext returns the context handler calls run with: canceled
// when the server closes.
func (s *Server) handlerContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-s.closeCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

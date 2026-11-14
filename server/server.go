// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
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

// DefaultTLSPort is the port of DNP3 over TLS: IEEE 1815-2012 clause
// 7.8.8 makes 19999 the default, and clause 13.2.2.2 requires devices that
// use TLS to support it.
const DefaultTLSPort = 19999

// Server is a DNP3 outstation: a point database served to masters over
// any number of channels.
type Server struct {
	opts  options
	db    *Database
	clock *clock
	log   *logx.Logger
	sm    dnp3.ServerMetrics
	// maxAssocs is the limit of WithMaxAssociations.
	maxAssocs int
	// timeSync is the synchronization state of clock.
	timeSync syncState
	// handles assigns file handles, unique to the outstation.
	handles fileHandles

	mu         sync.Mutex
	assocs     map[link.Address]*association
	channels   map[*channel.Channel]struct{}
	listeners  map[net.Listener]struct{}
	indication app.IIN
	freezes    map[string]*scheduledFreeze // FREEZE_AT_TIME schedules, by the points they name
	// pending counts the connections Serve and ServeByMasterIP accepted
	// that are not among channels yet, in their TLS handshake: they count
	// against WithMaxConnections from the moment they are accepted.
	pending int
	closed  bool
	closeCh chan struct{}
	// closeCtx is canceled by Close: it ends the TLS handshakes of accepted
	// connections.
	closeCtx    context.Context
	cancelClose context.CancelFunc
	wg          sync.WaitGroup
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
	maxAssocs, err := o.maxAssociations()
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:      o,
		clock:     newClock(),
		log:       logx.New(o.logger, "server", "outstation", o.address),
		freezes:   make(map[string]*scheduledFreeze),
		assocs:    make(map[link.Address]*association),
		channels:  make(map[*channel.Channel]struct{}),
		listeners: make(map[net.Listener]struct{}),
		closeCh:   make(chan struct{}),
		maxAssocs: maxAssocs,
	}
	s.closeCtx, s.cancelClose = context.WithCancel(context.Background())
	// The application's metrics are called guarded: a callback that does
	// not return normally is logged, and the outstation goes on.
	sm, _ := o.metrics.(dnp3.ServerMetrics)
	s.sm = logx.ServerMetrics(sm, s.log)
	s.opts.metrics = logx.Metrics(o.metrics, s.log)
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
// synchronization (IIN1.4). Points get the classes they were added with
// again, undoing ASSIGN_CLASS (IEEE 1815-2012 4.4.14, p. 63); deadbands
// written by a master are kept.
func (s *Server) Restart() {
	s.db.revertClasses()
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
// returns nil once the server is closed, and when m is new and the server
// holds WithMaxAssociations associations.
func (s *Server) association(m link.Address) *association {
	a, _ := s.associate(m)
	return a
}

// errTooManyAssociations is the error a frame of a new master gets while
// the server holds WithMaxAssociations associations.
var errTooManyAssociations = errors.New("server: frame of a new master dropped: the outstation holds as many associations as WithMaxAssociations allows")

// associate is association, which reports errTooManyAssociations for a new
// master beyond the limit: the frame is dropped before an association, or
// anything else, is made for it.
func (s *Server) associate(m link.Address) (*association, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil
	}
	if a, ok := s.assocs[m]; ok {
		return a, nil
	}
	if len(s.assocs) >= s.maxAssocs {
		return nil, errTooManyAssociations
	}
	a := newAssociation(s, m)
	s.assocs[m] = a
	s.wg.Add(1)
	go a.run()
	return a, nil
}

// forget frees the place of an association that ended.
func (s *Server) forget(a *association) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assocs[a.master] == a {
		delete(s.assocs, a.master)
	}
}

func (s *Server) masterAllowed(m link.Address) bool {
	if len(s.opts.masters) == 0 {
		return m <= link.MaxStationAddress
	}
	return slices.Contains(s.opts.masters, m)
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

// ListenAndServe listens on the TCP address addr, with TLS when WithTLS
// was given, and serves until Close. An empty addr is ":20000", or
// ":19999" ([DefaultTLSPort]) with TLS.
func (s *Server) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", listenAddr(addr, s.opts.tls != nil))
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
		c, remote, err := acceptConn(s.log, l)
		if err != nil {
			if s.isClosed() {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Anything else, such as running out of file descriptors, may
			// pass: keep accepting after a pause.
			s.log.Warn("accept failed", "error", err)
			delay = acceptDelay(delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		if !s.opts.masterIPAllowed(remote) {
			s.log.Warn("connection refused: address not among WithMasterIPs", "remote", addrString(remote))
			_ = c.Close()
			continue
		}
		if !s.reserve() {
			s.log.Warn("connection refused: limit reached", "remote", addrString(remote), "limit", s.opts.maxConns)
			_ = c.Close()
			continue
		}
		if !s.spawn(func() { s.serveAccepted(c, remote) }) {
			// Accepted as Close closed the listener.
			s.unreserve()
			_ = c.Close()
			return nil
		}
	}
}

// reserve counts an accepted connection against WithMaxConnections before
// its TLS handshake, and reports false when the server already holds that
// many: the connections it serves and those still in their handshake.
func (s *Server) reserve() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.channels)+s.pending >= s.opts.maxConns {
		return false
	}
	s.pending++
	return true
}

// unreserve gives back the place of a connection reserve counted that will
// not be served.
func (s *Server) unreserve() {
	s.mu.Lock()
	s.pending--
	s.mu.Unlock()
}

// serveAccepted runs in the goroutine of a connection that reserve
// counted: the TLS handshake, then the connection is served, counted among
// the channels instead of pending from then on.
func (s *Server) serveAccepted(c net.Conn, remote net.Addr) {
	if err := handshake(s.closeCtx, s.log, c); err != nil {
		s.unreserve()
		s.log.Warn("TLS handshake failed", "remote", addrString(remote), "error", err)
		return
	}
	_ = serveConn(c, remote, []*Server{s}, true)
}

// errNoAccept is an Accept that returned neither a connection nor an error.
var errNoAccept = errors.New("net.Listener.Accept returned neither a connection nor an error")

// acceptConn accepts the next connection of l, with its remote address
// read once. The listener and its connections may be the application's:
// an Accept that does not return normally, or returns neither a
// connection nor an error, is an Accept error, and so is a connection
// whose RemoteAddr does not return normally, which is closed.
func acceptConn(log *logx.Logger, l net.Listener) (net.Conn, net.Addr, error) {
	c, err := logx.Call(log, "net.Listener.Accept", l.Accept)
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, errNoAccept
	}
	remote, err := logx.Call(log, "net.Conn.RemoteAddr", func() (net.Addr, error) { return c.RemoteAddr(), nil })
	if err != nil {
		_ = logx.Do(log, "net.Conn.Close", c.Close)
		return nil, nil, err
	}
	return c, remote, nil
}

// spawn runs f in a goroutine that Close waits for, and reports false,
// without running it, once the server is closed. The check and the Add
// are under s.mu, which Close holds as it marks the server closed: every
// Add from zero happens before Close's Wait, as sync.WaitGroup requires,
// and no goroutine starts after Close returned.
func (s *Server) spawn(f func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Go(f)
	return true
}

// acceptDelay is the pause after an Accept error: doubling from 5 ms up to
// a second.
func acceptDelay(d time.Duration) time.Duration {
	return min(max(2*d, 5*time.Millisecond), time.Second)
}

// handshakeTimeout bounds the TLS handshake of an accepted connection, so
// that a peer that stalls it cannot hold a connection slot.
var handshakeTimeout = 10 * time.Second

// handshake completes the TLS handshake of an accepted connection within
// handshakeTimeout, or until ctx ends (Close cancels it), closing it on
// failure. Other connections pass. A handshake that does not return
// normally, in a callback of the application's tls.Config, fails; log
// reports it.
func handshake(ctx context.Context, log *logx.Logger, c net.Conn) error {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := logx.Do(log, "TLS handshake", func() error { return tc.HandshakeContext(ctx) }); err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

// defaultPort returns DefaultTLSPort with TLS, DefaultPort without.
func defaultPort(tls bool) int {
	if tls {
		return DefaultTLSPort
	}
	return DefaultPort
}

// listenAddr is the address ListenAndServe listens on: addr, or every
// interface at defaultPort when addr is empty.
func listenAddr(addr string, tls bool) string {
	if addr == "" {
		return fmt.Sprintf(":%d", defaultPort(tls))
	}
	return addr
}

// streamConnected reports whether a master is connected over a stream
// (TCP, TLS or serial) that is open: DialAndServe does not connect while
// one is.
func (s *Server) streamConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.channels {
		if !ch.Datagram() && !closing(ch) {
			return true
		}
	}
	return false
}

// connections returns the number of connections served, and of accepted
// ones in their TLS handshake.
func (s *Server) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.channels) + s.pending
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
	return serveConn(rw, remote, []*Server{s}, false)
}

// takes reports whether a frame to local is for the server: its own
// address, a broadcast address, or the self address when enabled.
func (s *Server) takes(local link.Address) bool {
	return local == s.opts.address || local.Broadcast() || (s.opts.selfAddress && local == link.SelfAddress)
}

// serveConn serves one stream for the outstations of servers, which have
// distinct addresses: each takes the frames to its address, all of them
// the broadcasts. The channel's metrics and log are the first server's.
// With reserved, the stream is a connection that the single server's
// reserve counted: it moves from pending to the channels in one step, so
// that the server's count never misses it.
func serveConn(rw io.ReadWriteCloser, remote net.Addr, servers []*Server, reserved bool) error {
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
		if reserved {
			s.pending--
		}
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
	if wait, ok := silentLimit(remote, servers); ok && len(ch.Sessions()) == 0 {
		// The keep-alive of IEEE 1815-2012 clause 13.2.3.3.1 runs per
		// master, and no master has spoken yet: a TCP connection that
		// stays silent for a keep-alive interval and a link timeout is
		// deemed broken, as an unanswered keep-alive would be.
		t := time.AfterFunc(wait, func() {
			if len(ch.Sessions()) == 0 {
				ch.Close(fmt.Errorf("%w: no master spoke on the connection within the keep-alive interval", dnp3.ErrTimeout))
			}
		})
		defer t.Stop()
	}
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

// silentLimit returns how long a TCP connection may stay without a
// master: the longest keep-alive interval plus link timeout of servers.
// It is false for other streams, such as serial lines and datagram
// sockets, and when a server has disabled its keep-alive.
func silentLimit(remote net.Addr, servers []*Server) (time.Duration, bool) {
	if _, ok := remote.(*net.TCPAddr); !ok {
		return 0, false
	}
	var wait time.Duration
	for _, s := range servers {
		ka, to := s.opts.link.KeepAlive, s.opts.link.Timeout
		if ka < 0 {
			return 0, false
		}
		if ka == 0 {
			ka = 60 * time.Second
		}
		if to <= 0 {
			to = 2 * time.Second
		}
		wait = max(wait, ka+to)
	}
	return wait, true
}

// bind adds the session of master on ch and attaches it to the master's
// association.
func (s *Server) bind(ch *channel.Channel, master link.Address) *channel.Session {
	a, err := s.associate(master)
	if err != nil {
		if s.log.DebugEnabled() {
			s.log.Debug("frame of a new master dropped: association limit reached", "master", master, "limit", s.maxAssocs)
		}
		if m := s.opts.metrics; m != nil {
			m.OnDecodeError(ch.Remote(), err)
		}
		return nil
	}
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
		SelfAddress:     s.opts.selfAddress,
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

// Close stops the listeners, closes every connection, ends the TLS
// handshakes in progress and stops the associations. It waits for their
// goroutines to end, so it must not be called from a [Handler] method,
// which runs on an association goroutine: call go srv.Close() there.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	s.cancelClose()
	for _, f := range s.freezes {
		f.timer.Stop()
	}
	clear(s.freezes)
	// Under s.mu: a Close of the application's listener that does not
	// return normally is logged after the unlock, and Close goes on.
	var failed []*logx.Failure
	for l := range s.listeners {
		if fail, _ := logx.Try("net.Listener.Close", l.Close); fail != nil {
			failed = append(failed, fail)
		}
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
	for _, fail := range failed {
		s.log.Report(fail)
	}
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

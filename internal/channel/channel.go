// SPDX-License-Identifier: MIT

// Package channel runs the DNP3 data link layer procedures and the
// transport function over one byte stream: a TCP connection, a serial port
// or a UDP socket.
//
// A Channel owns the stream and one reader goroutine. Frames are routed by
// their address pair to a Session, which keeps the link state of one
// association (frame count bits, reset state, keep-alive) and the
// transport sequence numbers, and delivers reassembled fragments in order
// on a goroutine of its own. Several sessions share a channel on a
// multi-drop serial line.
package channel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/logx"
	"github.com/otfabric/go-dnp3/link"
)

// Stream is the transport a channel runs over. A net.Conn satisfies it.
type Stream interface {
	io.ReadWriteCloser
}

// writeDeadliner is implemented by streams whose writes can be bounded.
type writeDeadliner interface {
	SetWriteDeadline(t time.Time) error
}

// DatagramStream is implemented by a Stream whose reads are datagrams,
// such as a UDP socket. A link frame never spans datagrams (IEEE
// 1815-2012 clause 13.2.3.2.3), so the channel decodes each datagram on
// its own: it takes every frame in it, and a damaged or cut frame costs
// the rest of that datagram only.
type DatagramStream interface {
	// ReadDatagram returns the next datagram. An error ends the channel.
	ReadDatagram() ([]byte, error)
}

// frameReader is a link.Reader, or the per-datagram reader.
type frameReader interface {
	ReadFrame() (link.Frame, error)
}

// datagramReader reads the frames of a DatagramStream, one datagram at a
// time.
type datagramReader struct {
	s   DatagramStream
	cur *link.Reader // over the current datagram; nil between datagrams
}

func (d *datagramReader) ReadFrame() (link.Frame, error) {
	for {
		if d.cur == nil {
			dg, err := d.s.ReadDatagram()
			if err != nil {
				return link.Frame{}, err
			}
			d.cur = link.NewReader(bytes.NewReader(dg))
		}
		f, err := d.cur.ReadFrame()
		switch {
		case errors.Is(err, io.EOF):
			d.cur = nil // the datagram is done
		case errors.Is(err, io.ErrUnexpectedEOF):
			d.cur = nil
			return link.Frame{}, fmt.Errorf("%w: frame cut at the end of a datagram", link.ErrFraming)
		default:
			return f, err
		}
	}
}

// netStream reports whether s is a network stream (TCP, TLS or UDP), as
// opposed to a serial line or a pipe.
func netStream(s Stream) bool {
	if _, ok := s.(DatagramStream); ok {
		return true
	}
	c, ok := s.(net.Conn)
	if !ok {
		return false
	}
	switch c.LocalAddr().(type) {
	case *net.TCPAddr, *net.UDPAddr:
		return true
	}
	return false
}

// Config configures a channel.
type Config struct {
	// Remote is the address of the peer, for logs and metrics.
	Remote net.Addr
	// Metrics, when not nil, observes frames and fragments.
	Metrics dnp3.Metrics
	// Log is the component logger; nil discards.
	Log *logx.Logger
	// Accept is called for frames whose address pair has no session. It
	// may add a session for them and return it, or return nil to drop the
	// frame. A nil Accept drops them.
	Accept func(local, remote link.Address) *Session
	// WriteTimeout bounds each write on streams that support deadlines.
	// Zero means 10 seconds.
	WriteTimeout time.Duration
}

type key struct{ local, remote link.Address }

// Channel is one byte stream and the sessions on it.
type Channel struct {
	cfg      Config
	stream   Stream
	reader   frameReader
	datagram bool

	wmu sync.Mutex // serializes writes

	mu       sync.Mutex
	sessions map[key]*Session
	err      error

	closing chan struct{} // closed by Close
	done    chan struct{} // closed when the reader and every session ended
	once    sync.Once
	wg      sync.WaitGroup
}

// New returns a channel over s. Add sessions, then call Start.
func New(s Stream, cfg Config) *Channel {
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	c := &Channel{
		cfg:      cfg,
		stream:   s,
		sessions: make(map[key]*Session),
		closing:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	if d, ok := s.(DatagramStream); ok {
		c.reader, c.datagram = &datagramReader{s: d}, true
	} else {
		c.reader = link.NewReader(s)
	}
	return c
}

// Datagram reports whether the channel runs over a datagram socket.
func (c *Channel) Datagram() bool { return c.datagram }

// Start starts reading. The channel runs until Close is called or the
// stream fails.
func (c *Channel) Start() {
	if c.cfg.Metrics != nil {
		c.cfg.Metrics.OnConnect(c.cfg.Remote)
	}
	c.wg.Add(1)
	go c.readLoop()
	go func() {
		c.wg.Wait()
		close(c.done)
	}()
}

// Remote returns the address of the peer.
func (c *Channel) Remote() net.Addr { return c.cfg.Remote }

// Peer returns the address what is written goes to: the stream's own
// (Peer() net.Addr), which for a UDP socket is the master that sent the
// last datagram and nil before the first, or else Remote.
func (c *Channel) Peer() net.Addr {
	if p, ok := c.stream.(interface{ Peer() net.Addr }); ok {
		return p.Peer()
	}
	return c.cfg.Remote
}

// Done is closed when the channel has stopped: the reader and every
// session goroutine have returned.
func (c *Channel) Done() <-chan struct{} { return c.done }

// Closing is closed as soon as Close was called or the stream failed.
func (c *Channel) Closing() <-chan struct{} { return c.closing }

// Err returns the reason the channel stopped: nil when it was closed with
// a nil error, an error wrapping dnp3.ErrConnectionLost when the stream
// failed.
func (c *Channel) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close stops the channel with reason err (nil for an orderly close by the
// application) and closes the stream. It does not wait; use Done.
func (c *Channel) Close(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.closing)
		_ = c.stream.Close()
		if c.cfg.Metrics != nil {
			c.cfg.Metrics.OnDisconnect(c.cfg.Remote, err)
		}
	})
}

// AddSession adds a session for the address pair of cfg and starts its
// goroutine. It replaces nothing: adding a pair twice returns the
// existing session.
func (c *Channel) AddSession(cfg SessionConfig) *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key{cfg.Local, cfg.Remote}
	if s, ok := c.sessions[k]; ok {
		return s
	}
	s := newSession(c, cfg)
	if cfg.Confirmed && netStream(c.stream) {
		c.cfg.Log.Warn("confirmed user data on a network stream: IEEE 1815-2012 clause 13.2.1.1 forbids it over TCP and UDP",
			"local_addr", cfg.Local, "remote_addr", cfg.Remote)
	}
	c.sessions[k] = s
	c.wg.Add(1)
	go s.run()
	return s
}

// Sessions returns the sessions of the channel.
func (c *Channel) Sessions() []*Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		out = append(out, s)
	}
	return out
}

func (c *Channel) lookup(local, remote link.Address) *Session {
	c.mu.Lock()
	s := c.sessions[key{local, remote}]
	c.mu.Unlock()
	if s == nil && c.cfg.Accept != nil {
		s = c.cfg.Accept(local, remote)
	}
	return s
}

// Session returns the session of the address pair, or nil.
func (c *Channel) Session(local, remote link.Address) *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[key{local, remote}]
}

// broadcastTargets returns the sessions that take a frame from remote to
// dest, a broadcast address or the self address: every session of the
// remote for a broadcast, those with SelfAddress for the self address.
func (c *Channel) broadcastTargets(dest, remote link.Address) []*Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*Session
	for k, s := range c.sessions {
		if k.remote == remote && (dest != link.SelfAddress || s.cfg.SelfAddress) {
			out = append(out, s)
		}
	}
	return out
}

func (c *Channel) readLoop() {
	defer c.wg.Done()
	for {
		f, err := c.reader.ReadFrame()
		if err != nil {
			if errors.Is(err, link.ErrFraming) {
				c.cfg.Log.Debug("framing error", "error", err)
				if c.cfg.Metrics != nil {
					c.cfg.Metrics.OnFramingError(c.cfg.Remote, err)
				}
				continue
			}
			select {
			case <-c.closing:
			default:
				if err == io.EOF {
					err = fmt.Errorf("%w: closed by peer", dnp3.ErrConnectionLost)
				} else {
					err = fmt.Errorf("%w: %w", dnp3.ErrConnectionLost, err)
				}
				c.Close(err)
			}
			return
		}
		if c.cfg.Metrics != nil {
			c.cfg.Metrics.OnFrameReceived(c.cfg.Remote, &f, link.EncodedLen(len(f.Data)))
		}
		if c.cfg.Log.DebugEnabled() {
			c.cfg.Log.Debug("frame received", "frame", f.String())
		}
		switch {
		case f.Dest.Broadcast() || f.Dest == link.SelfAddress:
			if c.cfg.Accept != nil {
				// Every station that takes the broadcast gets a session,
				// also when it is the master's first frame to it.
				c.cfg.Accept(f.Dest, f.Src)
			}
			targets := c.broadcastTargets(f.Dest, f.Src)
			for _, s := range targets {
				s.handleFrame(f)
			}
		default:
			if s := c.lookup(f.Dest, f.Src); s != nil {
				s.handleFrame(f)
			} else {
				c.cfg.Log.Debug("frame for unknown address pair dropped", "dest", f.Dest, "src", f.Src)
			}
		}
	}
}

// writeFrame encodes and writes f.
func (c *Channel) writeFrame(f *link.Frame) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	c.wmu.Lock()
	select {
	case <-c.closing:
		c.wmu.Unlock()
		return c.closedErr()
	default:
	}
	if d, ok := c.stream.(writeDeadliner); ok {
		_ = d.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
	}
	_, err = c.stream.Write(b)
	c.wmu.Unlock()
	if err != nil {
		err = fmt.Errorf("%w: write: %w", dnp3.ErrConnectionLost, err)
		c.Close(err)
		return err
	}
	if c.cfg.Metrics != nil {
		c.cfg.Metrics.OnFrameSent(c.cfg.Remote, f, len(b))
	}
	if c.cfg.Log.DebugEnabled() {
		c.cfg.Log.Debug("frame sent", "frame", f.String())
	}
	return nil
}

// closedErr returns the error for an operation on a stopped channel.
func (c *Channel) closedErr() error {
	if err := c.Err(); err != nil {
		return err
	}
	return dnp3.ErrClosed
}

// DatagramErrorPasses reports whether a read or write error of a datagram
// socket concerns one datagram only, such as the ICMP port unreachable a
// connected UDP socket reports as ECONNREFUSED, or a send to a route that
// went away: the socket keeps working, so the error must not end the
// channel. A closed socket or an expired deadline does end it.
func DatagramErrorPasses(err error) bool {
	return !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded)
}

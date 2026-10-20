// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/link"
)

// Group serves several outstations on the same connections: a multi-drop
// channel (IEEE 1815-2012 clause 9), where every station takes the frames
// to its own link address and all of them the broadcasts. Each outstation
// is a [Server] with its own address, database, handler and options; the
// group only shares the listeners and connections, so that a master
// reaches each by its address over one port or one serial line.
type Group struct {
	servers []*Server

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     int
	closed    bool
	wg        sync.WaitGroup
}

// NewGroup returns a group of servers, which must have distinct
// addresses. The servers are served through the group: do not serve them
// on their own as well.
func NewGroup(servers ...*Server) (*Group, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("%w: a group without servers", dnp3.ErrInvalidOption)
	}
	seen := map[link.Address]bool{}
	for _, s := range servers {
		if s == nil {
			return nil, fmt.Errorf("%w: a nil server in a group", dnp3.ErrInvalidOption)
		}
		if seen[s.opts.address] {
			return nil, fmt.Errorf("%w: two servers with the address %d", dnp3.ErrInvalidOption, s.opts.address)
		}
		seen[s.opts.address] = true
	}
	return &Group{servers: append([]*Server(nil), servers...), listeners: map[net.Listener]struct{}{}}, nil
}

// Servers returns the servers of the group, in the order given.
func (g *Group) Servers() []*Server { return append([]*Server(nil), g.servers...) }

// ListenAndServe listens on the TCP address addr (":20000" when empty),
// with the TLS configuration of the first server's WithTLS when it has
// one, and serves until Close.
func (g *Group) ListenAndServe(addr string) error {
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if cfg := g.servers[0].opts.tls; cfg != nil {
		l = tls.NewListener(l, cfg)
	}
	return g.Serve(l)
}

// Serve accepts connections on l and serves each until Close. A
// connection is refused while the group holds as many as the smallest
// WithMaxConnections of its servers. It returns nil after Close,
// otherwise the error that stopped the listener.
func (g *Group) Serve(l net.Listener) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = l.Close()
		return dnp3.ErrClosed
	}
	g.listeners[l] = struct{}{}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.listeners, l)
		g.mu.Unlock()
	}()
	limit := g.servers[0].opts.maxConns
	for _, s := range g.servers[1:] {
		limit = min(limit, s.opts.maxConns)
	}
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if g.isClosed() {
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
		g.mu.Lock()
		full := g.conns >= limit
		if !full {
			g.conns++
		}
		g.mu.Unlock()
		if full {
			g.servers[0].log.Warn("connection refused: limit reached", "remote", c.RemoteAddr().String(), "limit", limit)
			_ = c.Close()
			continue
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			_ = g.ServeConn(c, c.RemoteAddr())
			g.mu.Lock()
			g.conns--
			g.mu.Unlock()
		}()
	}
}

// ServeConn serves one stream, for example a serial port, for every
// outstation of the group until it ends or the group is closed.
func (g *Group) ServeConn(rw io.ReadWriteCloser, remote net.Addr) error {
	if g.isClosed() {
		_ = rw.Close()
		return dnp3.ErrClosed
	}
	return serveConn(rw, remote, g.servers)
}

// ServeUDP serves the outstations of the group over UDP on pc, as
// [Server.ServeUDP] does for one.
func (g *Group) ServeUDP(pc net.PacketConn) error {
	return g.ServeConn(&udpStream{pc: pc}, pc.LocalAddr())
}

func (g *Group) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// Close stops the listeners and closes every server of the group, and
// with them the connections.
func (g *Group) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	for l := range g.listeners {
		_ = l.Close()
	}
	g.mu.Unlock()
	for _, s := range g.servers {
		_ = s.Close()
	}
	g.wg.Wait()
	return nil
}

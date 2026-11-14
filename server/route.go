// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
)

// A Route assigns the connections of the masters whose IP address lies in
// Masters to one outstation, Server, or to the outstations of one Group.
// Exactly one of Server and Group is set.
type Route struct {
	Masters netip.Prefix
	Server  *Server
	Group   *Group
}

// ServeByMasterIP accepts connections on l and gives each to the route of
// the master's IP address: method 1 of IEEE 1815-2012 clause 13.2.3.5.1,
// which clause 13.2.3.5.4 requires of an outstation that supports multiple
// masters. The first route whose prefix holds the address takes the
// connection; one that no route takes is closed. Method 2, a port for each
// master, is a listener for each Server or Group.
//
// The targets serve the connections as their own Serve does, with their
// TLS handshake, WithMaxConnections and WithMasterIPs; give l a listener
// of tls.NewListener for TLS. Closing a target closes its connections;
// closing l stops the accepting. ServeByMasterIP returns the error that
// stopped l, wrapping net.ErrClosed after l.Close.
//
//	l, _ := net.Listen("tcp", ":20000")
//	go server.ServeByMasterIP(l,
//		server.Route{Masters: netip.MustParsePrefix("192.0.2.1/32"), Server: scada},
//		server.Route{Masters: netip.MustParsePrefix("198.51.100.0/24"), Group: engineering})
func ServeByMasterIP(l net.Listener, routes ...Route) error {
	if err := checkRoutes(routes); err != nil {
		return err
	}
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			delay = acceptDelay(delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		r, ok := routeOf(routes, c.RemoteAddr())
		if !ok {
			_ = c.Close()
			continue
		}
		r.serve(c)
	}
}

// checkRoutes validates the routes of ServeByMasterIP.
func checkRoutes(routes []Route) error {
	if len(routes) == 0 {
		return fmt.Errorf("%w: ServeByMasterIP without routes", dnp3.ErrInvalidOption)
	}
	for i, r := range routes {
		switch {
		case !r.Masters.IsValid():
			return fmt.Errorf("%w: route %d: invalid prefix", dnp3.ErrInvalidOption, i)
		case (r.Server == nil) == (r.Group == nil):
			return fmt.Errorf("%w: route %d: set exactly one of Server and Group", dnp3.ErrInvalidOption, i)
		}
	}
	return nil
}

// routeOf returns the first route whose prefix holds the IP address of a.
func routeOf(routes []Route, a net.Addr) (Route, bool) {
	for _, r := range routes {
		if inPrefixes([]netip.Prefix{r.Masters}, a) {
			return r, true
		}
	}
	return Route{}, false
}

// serve gives an accepted connection to the route's target, as its Serve
// would.
func (r Route) serve(c net.Conn) {
	if r.Server != nil {
		s := r.Server
		switch {
		case s.isClosed():
			_ = c.Close()
			return
		case !s.opts.masterIPAllowed(c.RemoteAddr()):
			s.log.Warn("connection refused: address not among WithMasterIPs", "remote", c.RemoteAddr().String())
			_ = c.Close()
			return
		case !s.reserve():
			s.log.Warn("connection refused: limit reached", "remote", c.RemoteAddr().String(), "limit", s.opts.maxConns)
			_ = c.Close()
			return
		}
		// The goroutine is one Close waits for, as Serve's are.
		if !s.spawn(func() { s.serveAccepted(c) }) {
			s.unreserve()
			_ = c.Close()
		}
		return
	}
	g := r.Group
	switch {
	case g.isClosed():
		_ = c.Close()
		return
	case !g.masterIPAllowed(c.RemoteAddr()):
		g.servers[0].log.Warn("connection refused: address not among WithMasterIPs", "remote", c.RemoteAddr().String())
		_ = c.Close()
		return
	case !g.acquire():
		g.servers[0].log.Warn("connection refused: limit reached", "remote", c.RemoteAddr().String(), "limit", g.limit())
		_ = c.Close()
		return
	}
	if !g.spawn(func() { g.serveAccepted(c, g.handshake) }) {
		g.release()
		_ = c.Close()
	}
}

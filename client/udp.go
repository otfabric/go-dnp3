// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/internal/channel"
)

// UDP returns a StreamOpener for DNP3 over UDP (port 20000 by convention):
// every link frame travels in a datagram to addr
// ("host:port"). Use it with WithStream:
//
//	c, err := client.New(addr, client.WithStream(client.UDP(addr)))
//
// It dials with a net.Dialer, not the dialer of WithDialer, which a
// stream opener does not see; use UDPWithDialer to supply one.
func UDP(addr string) StreamOpener {
	return UDPWithDialer(nil, addr)
}

// UDPWithDialer is UDP with the connected UDP socket opened by d: d is
// called with network "udp" and addr, and with the context of the
// Connect or reconnect attempt, which it must honour. d is held to the
// contract of WithDialer: a connection exactly when the error is nil.
// With d nil it is UDP. A net.Dialer with LocalAddr set is UDPFrom.
//
//	d := &net.Dialer{Control: allowlist}
//	c, err := client.New(addr, client.WithStream(client.UDPWithDialer(d, addr)))
func UDPWithDialer(d Dialer, addr string) StreamOpener {
	if d == nil {
		d = &net.Dialer{}
	}
	return func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		conn, err := dialConn(ctx, d, "udp", addr)
		if err != nil {
			return nil, nil, err
		}
		return udpConn{conn}, conn.RemoteAddr(), nil
	}
}

// UDPFrom is UDP with the local address the datagrams are sent from, for
// an outstation that sends its responses to a fixed port of the master
// (IEEE 1815-2012 Table 13-1, case 1) or takes requests from known ports
// only. local is "host:port"; an empty host is any address.
//
//	c, err := client.New(addr, client.WithStream(client.UDPFrom(":20000", addr)))
//
// Like UDP, it does not use the dialer of WithDialer; UDPWithDialer with
// a dialer that binds local is its counterpart with a dialer.
func UDPFrom(local, remote string) StreamOpener {
	return func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		la, err := net.ResolveUDPAddr("udp", local)
		if err != nil {
			return nil, nil, err
		}
		return UDPWithDialer(&net.Dialer{LocalAddr: la}, remote)(ctx)
	}
}

// udpConn is a connected UDP socket whose errors for one datagram do not
// end the channel: an ICMP port unreachable, while the outstation is not
// listening yet or restarts, makes the next read fail with ECONNREFUSED,
// and the request is repeated by the response timeout instead.
//
// The channel reads it a datagram at a time (channel.DatagramStream), so
// that a datagram that carries several frames is read whole (IEEE
// 1815-2012 clause 13.2.3.2.3).
type udpConn struct{ net.Conn }

func (u udpConn) Read(b []byte) (int, error) {
	for {
		n, err := u.Conn.Read(b)
		if err == nil || !channel.DatagramErrorPasses(err) {
			return n, err
		}
		time.Sleep(time.Millisecond) // a socket that keeps failing does not spin
	}
}

// ReadDatagram returns the next datagram, whole.
func (u udpConn) ReadDatagram() ([]byte, error) {
	dg := make([]byte, 65535)
	n, err := u.Read(dg)
	if err != nil {
		return nil, err
	}
	return dg[:n], nil
}

func (u udpConn) Write(b []byte) (int, error) {
	n, err := u.Conn.Write(b)
	if err != nil && channel.DatagramErrorPasses(err) {
		return len(b), nil
	}
	return n, err
}

// Accept returns a StreamOpener for an outstation that establishes the
// connection (the dual end point of IEEE 1815-2012): it waits
// for the outstation to connect on l. Use it with WithStream; with
// WithReconnect the client waits for the next connection when one ends.
// The client does not close l. For TLS, give a listener of
// tls.NewListener: the master is the TLS server of such a connection.
//
// The opener has at most one Accept on l in progress. An attempt that ends
// before a connection came, by its context, leaves that Accept to the next
// attempt, which takes the connection it returns; only after the client is
// closed is a connection it returns closed. The pending Accept ends when l
// is closed.
//
//	l, _ := net.Listen("tcp", ":20000")
//	c, err := client.New("outstation", client.WithStream(client.Accept(l)))
func Accept(l net.Listener) StreamOpener {
	a := &acceptor{l: l}
	return a.open
}

// acceptor is the state of an Accept opener.
type acceptor struct {
	l  net.Listener
	mu sync.Mutex
	// pending receives the outcome of the Accept in progress; nil when
	// none is.
	pending chan accepted
}

type accepted struct {
	conn net.Conn
	err  error
}

func (a *acceptor) open(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
	a.mu.Lock()
	ch := a.pending
	if ch == nil {
		ch = make(chan accepted, 1)
		a.pending = ch
		go func() {
			conn, err := a.l.Accept()
			ch <- accepted{conn, err}
		}()
	}
	a.mu.Unlock()
	select {
	case r := <-ch:
		a.done(ch)
		if r.err != nil {
			return nil, nil, r.err
		}
		return r.conn, r.conn.RemoteAddr(), nil
	case <-ctx.Done():
		if errors.Is(context.Cause(ctx), dnp3.ErrClosed) {
			// The client is closed: no attempt follows, and the connection
			// the pending Accept takes is closed rather than kept.
			a.done(ch)
			go func() {
				if r := <-ch; r.conn != nil {
					_ = r.conn.Close()
				}
			}()
		}
		return nil, nil, ctx.Err()
	}
}

// done forgets the Accept whose outcome ch receives, so that the next
// attempt starts another.
func (a *acceptor) done(ch chan accepted) {
	a.mu.Lock()
	if a.pending == ch {
		a.pending = nil
	}
	a.mu.Unlock()
}

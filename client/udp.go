// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/otfabric/go-dnp3/internal/channel"
)

// UDP returns a StreamOpener for DNP3 over UDP (port 20000 by convention):
// every link frame travels in a datagram to addr
// ("host:port"). Use it with WithStream:
//
//	c, err := client.New(addr, client.WithStream(client.UDP(addr)))
func UDP(addr string) StreamOpener {
	return func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, err
		}
		return udpConn{conn}, conn.RemoteAddr(), nil
	}
}

// udpConn is a connected UDP socket whose errors for one datagram do not
// end the channel: an ICMP port unreachable, while the outstation is not
// listening yet or restarts, makes the next read fail with ECONNREFUSED,
// and the request is repeated by the response timeout instead.
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
//	l, _ := net.Listen("tcp", ":20000")
//	c, err := client.New("outstation", client.WithStream(client.Accept(l)))
func Accept(l net.Listener) StreamOpener {
	return func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		type accepted struct {
			conn net.Conn
			err  error
		}
		done := make(chan accepted, 1)
		go func() {
			conn, err := l.Accept()
			done <- accepted{conn, err}
		}()
		select {
		case a := <-done:
			if a.err != nil {
				return nil, nil, a.err
			}
			return a.conn, a.conn.RemoteAddr(), nil
		case <-ctx.Done():
			// The pending Accept takes the next connection; it is closed
			// rather than leaked.
			go func() {
				if a := <-done; a.conn != nil {
					_ = a.conn.Close()
				}
			}()
			return nil, nil, ctx.Err()
		}
	}
}

// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"io"
	"net"
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
		return conn, conn.RemoteAddr(), nil
	}
}

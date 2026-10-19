// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"net"
	"sync"
)

// ServeUDP serves DNP3 over UDP on pc until Close. Each datagram carries
// link frames; responses go to the address the last datagram came from, so
// one socket serves one master at a time (a master behind another address
// takes over the socket when it sends).
func (s *Server) ServeUDP(pc net.PacketConn) error {
	return s.ServeConn(&udpStream{pc: pc}, pc.LocalAddr())
}

// udpStream adapts a packet socket to the stream a channel runs over.
type udpStream struct {
	pc   net.PacketConn
	mu   sync.Mutex
	peer net.Addr
	buf  []byte
}

func (u *udpStream) Read(b []byte) (int, error) {
	if len(u.buf) == 0 {
		dg := make([]byte, 65535)
		n, addr, err := u.pc.ReadFrom(dg)
		if err != nil {
			return 0, err
		}
		u.mu.Lock()
		u.peer = addr
		u.mu.Unlock()
		u.buf = dg[:n]
	}
	n := copy(b, u.buf)
	u.buf = u.buf[n:]
	return n, nil
}

func (u *udpStream) Write(b []byte) (int, error) {
	u.mu.Lock()
	peer := u.peer
	u.mu.Unlock()
	if peer == nil {
		return 0, errors.New("dnp3: no UDP peer yet")
	}
	return u.pc.WriteTo(b, peer)
}

func (u *udpStream) Close() error { return u.pc.Close() }

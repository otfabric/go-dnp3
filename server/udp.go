// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"sync"
	"time"

	"github.com/otfabric/go-dnp3/internal/channel"
)

// ServeUDP serves DNP3 over UDP on pc until Close. Each datagram carries
// link frames; responses go to the address the last datagram came from, so
// one socket serves one master at a time (a master behind another address
// takes over the socket when it sends).
//
// Until a master has sent a datagram there is nowhere to send to: what the
// outstation sends before (the null unsolicited response, for one) is
// dropped, as an unreachable datagram would be, and repeated by the
// unsolicited retries. Use ServeUDPTo to name the master's address up front.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	return s.ServeConn(&udpStream{pc: pc}, pc.LocalAddr())
}

// ServeUDPTo is ServeUDP with the master's address known from the start:
// unsolicited responses reach it before it sent anything. A datagram from
// another address takes over the socket, as with ServeUDP.
func (s *Server) ServeUDPTo(pc net.PacketConn, peer net.Addr) error {
	return s.ServeConn(&udpStream{pc: pc, peer: peer}, pc.LocalAddr())
}

// udpStream adapts a packet socket to the stream a channel runs over.
type udpStream struct {
	pc   net.PacketConn
	mu   sync.Mutex
	peer net.Addr
	buf  []byte
}

// Read returns the octets of the datagrams received. An error that
// concerns one datagram only (see channel.DatagramErrorPasses) is skipped:
// it does not end the socket.
func (u *udpStream) Read(b []byte) (int, error) {
	for len(u.buf) == 0 {
		dg := make([]byte, 65535)
		n, addr, err := u.pc.ReadFrom(dg)
		if err != nil {
			if !channel.DatagramErrorPasses(err) {
				return 0, err
			}
			time.Sleep(time.Millisecond) // a socket that keeps failing does not spin
			continue
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

// Write sends to the current peer. Without one, or when the send fails for
// this datagram only, the octets are dropped: a datagram nobody can receive
// is lost, it does not end the socket.
func (u *udpStream) Write(b []byte) (int, error) {
	u.mu.Lock()
	peer := u.peer
	u.mu.Unlock()
	if peer == nil {
		return len(b), nil
	}
	n, err := u.pc.WriteTo(b, peer)
	if err != nil && channel.DatagramErrorPasses(err) {
		return len(b), nil
	}
	return n, err
}

// Peer returns the address datagrams are sent to, nil before there is one.
func (u *udpStream) Peer() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peer
}

func (u *udpStream) Close() error { return u.pc.Close() }

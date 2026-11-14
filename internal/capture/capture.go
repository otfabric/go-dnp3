// SPDX-License-Identifier: MIT

// Package capture reads recorded DNP3 traffic for tests: classic pcap and
// pcapng files with Ethernet frames (optionally 802.1Q tagged) or BSD
// loopback frames, IPv4, TCP and UDP.
//
// It reassembles each direction of a TCP connection in sequence order
// (retransmitted and overlapping bytes are dropped, credited to the frame
// that first carried them) into runs of contiguous bytes; a sequence gap
// starts a new run. Each UDP datagram is a run of its own. The DNP3 layers
// (link frames, transport reassembly, application fragments) are in
// dnp3.go: they run go-dnp3's own codecs over these runs.
//
// It is test infrastructure for testdata/captures and not part of the
// public API. It reads files from this repository, not untrusted input, but
// it still checks every length it reads.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Transport of a conversation.
type Transport string

// Transports.
const (
	TCP Transport = "tcp"
	UDP Transport = "udp"
)

// Run is a stretch of contiguous bytes of one direction: a reassembled
// part of a TCP stream between gaps, or one UDP datagram.
type Run struct {
	// FromClient is true for bytes sent by the client: the side that
	// opened the TCP connection (SYN) or, without a SYN, the side that is
	// not on the server port (see Conversation).
	FromClient bool
	Data       []byte
	// Frames and Times are, per byte of Data, the 1-based number of the
	// capture frame that delivered it and that frame's capture time.
	Frames []int
	Times  []time.Time
	// Cut is true when the run follows a gap or starts without the
	// connection's SYN: its first byte need not be a frame boundary.
	Cut bool
}

// Conversation is one TCP connection or one UDP address pair.
type Conversation struct {
	Transport      Transport
	Client, Server string // "ip:port"
	// SYN reports whether the connection's opening was captured, which
	// decides Client and Server; otherwise the server is the side on a
	// DNP3 port (20000, 20001), or the lower port.
	SYN bool
	// Gaps is the number of sequence gaps in both directions.
	Gaps int
	// Runs of both directions, ordered by the frame that delivered their
	// first byte.
	Runs []Run
}

// ErrFormat reports a file that is neither pcap nor pcapng, or is cut short.
var ErrFormat = errors.New("capture: unsupported or malformed capture file")

const (
	linkNull     = 0
	linkEthernet = 1
	linkLoop     = 108
	etherIPv4    = 0x0800
	etherVLAN    = 0x8100
	protoTCP     = 6
	protoUDP     = 17
)

// ReadFile reads a capture file and returns its TCP and UDP conversations,
// ordered by the frame that opened them, and the number of frames in the
// file.
func ReadFile(path string) ([]Conversation, int, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return nil, 0, err
	}
	return Read(b)
}

// Read parses a capture held in memory.
func Read(b []byte) ([]Conversation, int, error) {
	frames, err := packets(b)
	if err != nil {
		return nil, 0, err
	}
	a := newAssembler()
	for i, f := range frames {
		if err := a.frame(i+1, f); err != nil {
			return nil, 0, fmt.Errorf("frame %d: %w", i+1, err)
		}
	}
	return a.conversations(), len(frames), nil
}

// packet is one link-layer frame.
type packet struct {
	link uint32
	time time.Time
	data []byte
}

// packets returns the frames of a pcap or pcapng file.
func packets(b []byte) ([]packet, error) {
	if len(b) < 4 {
		return nil, ErrFormat
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		return pcapPackets(b, binary.LittleEndian, time.Microsecond)
	case 0xa1b23c4d:
		return pcapPackets(b, binary.LittleEndian, time.Nanosecond)
	case 0xd4c3b2a1:
		return pcapPackets(b, binary.BigEndian, time.Microsecond)
	case 0x4d3cb2a1:
		return pcapPackets(b, binary.BigEndian, time.Nanosecond)
	case 0x0a0d0d0a:
		return pcapngPackets(b)
	}
	return nil, ErrFormat
}

func pcapPackets(b []byte, bo binary.ByteOrder, unit time.Duration) ([]packet, error) {
	if len(b) < 24 {
		return nil, ErrFormat
	}
	link := bo.Uint32(b[20:24]) & 0x0fffffff
	var out []packet
	for off := 24; off < len(b); {
		if len(b)-off < 16 {
			return nil, ErrFormat
		}
		sec := int64(bo.Uint32(b[off:]))
		frac := int64(bo.Uint32(b[off+4:]))
		n, ok := length(bo.Uint32(b[off+8 : off+12]))
		off += 16
		if !ok || n > len(b)-off {
			return nil, ErrFormat
		}
		t := time.Unix(sec, frac*int64(unit)).UTC()
		out = append(out, packet{link: link, time: t, data: b[off : off+n]})
		off += n
	}
	return out, nil
}

// length converts a 32-bit length or index field to int. A value of 2^31
// or more is refused: it would turn negative in a 32-bit int, and no
// capture record is that long.
func length(v uint32) (int, bool) {
	if v > math.MaxInt32 {
		return 0, false
	}
	return int(v), true
}

// iface is a pcapng interface: link type and time stamp units per second.
type iface struct {
	link   uint32
	perSec uint64
}

func pcapngPackets(b []byte) ([]packet, error) {
	var (
		bo     binary.ByteOrder = binary.LittleEndian
		ifaces []iface
		out    []packet
	)
	for off := 0; off < len(b); {
		if len(b)-off < 12 {
			return nil, ErrFormat
		}
		typ := bo.Uint32(b[off:])
		if typ == 0x0a0d0d0a { // section header: byte order from its magic
			switch binary.LittleEndian.Uint32(b[off+8:]) {
			case 0x1a2b3c4d:
				bo = binary.LittleEndian
			case 0x4d3c2b1a:
				bo = binary.BigEndian
			default:
				return nil, ErrFormat
			}
			ifaces = ifaces[:0]
		}
		n, ok := length(bo.Uint32(b[off+4:]))
		if !ok || n < 12 || n%4 != 0 || n > len(b)-off {
			return nil, ErrFormat
		}
		body := b[off+8 : off+n-4]
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				return nil, ErrFormat
			}
			ifaces = append(ifaces, iface{link: uint32(bo.Uint16(body)), perSec: tsresol(body[8:], bo)})
		case 6: // enhanced packet
			if len(body) < 20 {
				return nil, ErrFormat
			}
			ifc, ok1 := length(bo.Uint32(body))
			ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
			capLen, ok2 := length(bo.Uint32(body[12:]))
			if !ok1 || !ok2 || ifc >= len(ifaces) || capLen > len(body)-20 {
				return nil, ErrFormat
			}
			ps := ifaces[ifc].perSec
			sec, ns := ts/ps, ts%ps*(1e9/ps) // ns < 1e9: ps divides 1e9
			if sec > math.MaxInt64 || ns > math.MaxInt64 {
				return nil, ErrFormat
			}
			t := time.Unix(int64(sec), int64(ns)).UTC()
			out = append(out, packet{link: ifaces[ifc].link, time: t, data: body[20 : 20+capLen]})
		case 3: // simple packet, interface 0, no time stamp
			if len(body) < 4 || len(ifaces) == 0 {
				return nil, ErrFormat
			}
			capLen, ok := length(bo.Uint32(body))
			if !ok {
				return nil, ErrFormat
			}
			capLen = min(capLen, len(body)-4)
			out = append(out, packet{link: ifaces[0].link, data: body[4 : 4+capLen]})
		}
		off += n
	}
	return out, nil
}

// tsresol reads the if_tsresol option of an interface description block
// and returns time stamp units per second; the default is microseconds.
// Only decimal resolutions down to 1 ns are supported; others fall back to
// the default.
func tsresol(opts []byte, bo binary.ByteOrder) uint64 {
	for len(opts) >= 4 {
		code, n := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || 4+n > len(opts) {
			break
		}
		if code == 9 && n == 1 && opts[4]&0x80 == 0 && opts[4] <= 9 {
			ps := uint64(1)
			for range opts[4] {
				ps *= 10
			}
			return ps
		}
		opts = opts[4+(n+3)&^3:]
	}
	return 1_000_000
}

// segment is the TCP payload of one frame.
type segment struct {
	frame   int
	time    time.Time
	seq     uint32
	payload []byte
}

// flow is one direction of a TCP connection.
type flow struct {
	syn  bool
	isn  uint32
	segs []segment
}

type connKey struct {
	transport Transport
	a, b      string // the two end points, a < b
}

type conn struct {
	key        connKey
	firstFrame int
	// client is the end point that sent the SYN, if one was captured.
	client string
	flows  map[string]*flow // TCP, by sending end point
	// datagrams of UDP, in capture order, by sending end point.
	datagrams []datagram
}

type datagram struct {
	from    string
	frame   int
	time    time.Time
	payload []byte
}

type assembler struct {
	conns map[connKey]*conn
	// done are connections closed by a new SYN on the same address pair
	// (port reuse).
	done []*conn
}

func newAssembler() *assembler { return &assembler{conns: map[connKey]*conn{}} }

func (a *assembler) get(t Transport, src, dst string, num int) *conn {
	key := connKey{t, src, dst}
	if dst < src {
		key = connKey{t, dst, src}
	}
	c := a.conns[key]
	if c == nil {
		c = &conn{key: key, firstFrame: num, flows: map[string]*flow{}}
		a.conns[key] = c
	}
	return c
}

// frame takes one link-layer frame; frames that are not IPv4 TCP or UDP
// are ignored.
func (a *assembler) frame(num int, p packet) error {
	d := p.data
	switch p.link {
	case linkEthernet:
		if len(d) < 14 {
			return nil
		}
		etherType := binary.BigEndian.Uint16(d[12:14])
		d = d[14:]
		for etherType == etherVLAN {
			if len(d) < 4 {
				return nil
			}
			etherType = binary.BigEndian.Uint16(d[2:4])
			d = d[4:]
		}
		if etherType != etherIPv4 {
			return nil
		}
	case linkNull, linkLoop:
		// BSD loopback: a 4-octet address family, in the byte order of the
		// capturing host (DLT_NULL) or big-endian (DLT_LOOP); 2 is IPv4.
		if len(d) < 4 || (binary.LittleEndian.Uint32(d) != 2 && binary.BigEndian.Uint32(d) != 2) {
			return nil
		}
		d = d[4:]
	default:
		return fmt.Errorf("link type %d: only Ethernet and BSD loopback are supported", p.link)
	}
	if len(d) < 20 || d[0]>>4 != 4 {
		return nil
	}
	ihl := int(d[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[2:4]))
	if ihl < 20 || total < ihl || total > len(d) {
		return nil
	}
	if d[9] != protoTCP && d[9] != protoUDP {
		return nil
	}
	if binary.BigEndian.Uint16(d[6:8])&0x3fff != 0 {
		return errors.New("fragmented IPv4 is not supported")
	}
	src := fmt.Sprintf("%d.%d.%d.%d", d[12], d[13], d[14], d[15])
	dst := fmt.Sprintf("%d.%d.%d.%d", d[16], d[17], d[18], d[19])
	t := d[ihl:total]
	if d[9] == protoUDP {
		a.udp(num, p.time, src, dst, t)
		return nil
	}
	a.tcp(num, p.time, src, dst, t)
	return nil
}

func (a *assembler) udp(num int, ts time.Time, src, dst string, t []byte) {
	if len(t) < 8 {
		return
	}
	n := int(binary.BigEndian.Uint16(t[4:6]))
	if n < 8 || n > len(t) || n == 8 {
		return
	}
	s := fmt.Sprintf("%s:%d", src, binary.BigEndian.Uint16(t[0:2]))
	d := fmt.Sprintf("%s:%d", dst, binary.BigEndian.Uint16(t[2:4]))
	c := a.get(UDP, s, d, num)
	c.datagrams = append(c.datagrams, datagram{from: s, frame: num, time: ts, payload: t[8:n]})
}

func (a *assembler) tcp(num int, ts time.Time, src, dst string, t []byte) {
	if len(t) < 20 {
		return
	}
	thl := int(t[12]>>4) * 4
	if thl < 20 || thl > len(t) {
		return
	}
	s := fmt.Sprintf("%s:%d", src, binary.BigEndian.Uint16(t[0:2]))
	d := fmt.Sprintf("%s:%d", dst, binary.BigEndian.Uint16(t[2:4]))
	c := a.get(TCP, s, d, num)
	if t[13]&0x12 == 0x02 && c.used() { // a new connection on a reused address pair
		a.done = append(a.done, c)
		delete(a.conns, c.key)
		c = a.get(TCP, s, d, num)
	}
	f := c.flows[s]
	if f == nil {
		f = &flow{}
		c.flows[s] = f
	}
	seq := binary.BigEndian.Uint32(t[4:8])
	if t[13]&0x02 != 0 { // SYN: data starts at ISN+1; a new SYN starts the flow again
		f.syn, f.isn, f.segs = true, seq, nil
		if t[13]&0x10 == 0 { // SYN without ACK: the client
			c.client = s
		}
		return
	}
	if payload := t[thl:]; len(payload) > 0 {
		f.segs = append(f.segs, segment{frame: num, time: ts, seq: seq, payload: payload})
	}
}

// used reports whether the connection has seen a SYN or any data.
func (c *conn) used() bool {
	for _, f := range c.flows {
		if f.syn || len(f.segs) > 0 {
			return true
		}
	}
	return false
}

// seqDiff is a - b in TCP sequence space (RFC 1982 serial arithmetic):
// negative when a lies before b.
func seqDiff(a, b uint32) int64 {
	d := int64(a - b)
	if d >= 1<<31 {
		d -= 1 << 32
	}
	return d
}

// stream reassembles a flow in sequence order into runs of contiguous
// bytes. Bytes already delivered (retransmissions, overlaps) are dropped
// and credited to the earliest frame that carried them; a gap starts a new
// run.
func (f *flow) stream(fromClient bool) []Run {
	if len(f.segs) == 0 {
		return nil
	}
	base := f.segs[0].seq
	if f.syn {
		base = f.isn + 1
	} else {
		for _, s := range f.segs {
			if seqDiff(s.seq, base) < 0 {
				base = s.seq
			}
		}
	}
	segs := append([]segment(nil), f.segs...)
	sort.SliceStable(segs, func(i, j int) bool { return seqDiff(segs[i].seq, base) < seqDiff(segs[j].seq, base) })
	out := []Run{{FromClient: fromClient, Cut: !f.syn}}
	var next int64     // offset from base of the next byte expected
	var curStart int64 // offset from base of the current run's first byte
	for _, s := range segs {
		start := seqDiff(s.seq, base)
		end := start + int64(len(s.payload))
		cur := &out[len(out)-1]
		for i := max(start, curStart); i < min(end, next); i++ {
			if j := i - curStart; s.frame < cur.Frames[j] {
				cur.Frames[j], cur.Times[j] = s.frame, s.time
			}
		}
		if end <= next {
			continue
		}
		p := s.payload
		if start > next { // gap: data missing from the capture
			if len(cur.Data) > 0 {
				out = append(out, Run{FromClient: fromClient, Cut: true})
			} else {
				cur.Cut = true
			}
			curStart = start
		} else {
			p = p[next-start:]
		}
		cur = &out[len(out)-1]
		cur.Data = append(cur.Data, p...)
		for range p {
			cur.Frames = append(cur.Frames, s.frame)
			cur.Times = append(cur.Times, s.time)
		}
		next = end
	}
	return out
}

// dnp3Port reports whether p is a port DNP3 is commonly served on.
func dnp3Port(p string) bool {
	_, port, ok := cutPort(p)
	return ok && (port == "20000" || port == "20001")
}

func cutPort(p string) (host, port string, ok bool) {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == ':' {
			return p[:i], p[i+1:], true
		}
	}
	return p, "", false
}

func portNumber(p string) int {
	_, port, _ := cutPort(p)
	n := 0
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	return n
}

// roles decides client and server of a conversation.
func (c *conn) roles() (client, server string, syn bool) {
	a, b := c.key.a, c.key.b
	switch {
	case c.client == a:
		return a, b, true
	case c.client == b:
		return b, a, true
	case dnp3Port(a) && !dnp3Port(b):
		return b, a, false
	case dnp3Port(b) && !dnp3Port(a):
		return a, b, false
	case portNumber(a) < portNumber(b):
		return b, a, false
	default:
		return a, b, false
	}
}

func (a *assembler) conversations() []Conversation {
	conns := append([]*conn(nil), a.done...)
	for _, c := range a.conns {
		conns = append(conns, c)
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].firstFrame < conns[j].firstFrame })
	out := make([]Conversation, 0, len(conns))
	for _, c := range conns {
		client, server, syn := c.roles()
		conv := Conversation{Transport: c.key.transport, Client: client, Server: server, SYN: syn}
		if c.key.transport == UDP {
			for _, d := range c.datagrams {
				r := Run{FromClient: d.from == client, Data: d.payload, Cut: true}
				for range d.payload {
					r.Frames = append(r.Frames, d.frame)
					r.Times = append(r.Times, d.time)
				}
				conv.Runs = append(conv.Runs, r)
			}
		} else {
			for _, from := range []string{client, server} {
				f := c.flows[from]
				if f == nil {
					continue
				}
				runs := f.stream(from == client)
				if n := len(runs); n > 1 {
					conv.Gaps += n - 1
				}
				for _, r := range runs {
					if len(r.Data) > 0 {
						conv.Runs = append(conv.Runs, r)
					}
				}
			}
			sort.SliceStable(conv.Runs, func(i, j int) bool { return conv.Runs[i].Frames[0] < conv.Runs[j].Frames[0] })
		}
		out = append(out, conv)
	}
	return out
}

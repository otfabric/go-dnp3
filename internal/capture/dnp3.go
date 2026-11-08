// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"testing/iotest"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// LinkFrame is one result of link.Reader over a run: a decoded frame, or
// a framing error (skipped octets, a damaged header or data block).
type LinkFrame struct {
	FromClient bool
	// Frame is the capture frame that delivered the last octet the Reader
	// consumed for this result; Time its capture time.
	Frame int
	Time  time.Time
	// Raw is the frame's bytes as recorded (nil for an error).
	Raw []byte
	// Link is the decoded frame; Err the framing error instead.
	Link link.Frame
	Err  error
	// Cut is true for a frame or error at the end of a run: the run ended
	// inside it (io.ErrUnexpectedEOF).
	Cut bool
}

// countingReader counts the octets read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// LinkFrames runs link.Reader over every run of a conversation and returns
// the results of both directions ordered by the capture frame that
// completed them (each direction keeps its stream order). The Reader
// reads one octet at a time, so that after each ReadFrame it has consumed
// exactly the octets of the frame (or of what it skipped): the position
// maps every frame to the capture frame that completed it.
func LinkFrames(c Conversation) []LinkFrame {
	var out []LinkFrame
	for _, r := range c.Runs {
		cr := &countingReader{r: iotest.OneByteReader(bytes.NewReader(r.Data))}
		lr := link.NewReader(cr)
		for {
			f, err := lr.ReadFrame()
			if err == io.EOF {
				break
			}
			end := cr.n
			if end == 0 {
				break
			}
			lf := LinkFrame{FromClient: r.FromClient, Frame: r.Frames[end-1], Time: r.Times[end-1]}
			switch {
			case err == nil:
				n := link.EncodedLen(len(f.Data))
				lf.Link, lf.Raw = f, r.Data[end-n:end]
			case errors.Is(err, io.ErrUnexpectedEOF):
				lf.Err, lf.Cut = err, true
			default:
				lf.Err = err
			}
			out = append(out, lf)
			if lf.Cut {
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Frame < out[j].Frame })
	return out
}

// Fragment is one application fragment reassembled by go-dnp3's transport
// function from the link frames of one direction and address pair.
type Fragment struct {
	FromClient bool
	Src, Dest  link.Address
	// Frame is the capture frame of the FIN segment; Time its time.
	Frame int
	Time  time.Time
	// Segments is the number of transport segments of the fragment.
	Segments int
	Raw      []byte
	// Frag is app.Decode's result; Err its error.
	Frag *app.Fragment
	Err  error
}

// TransportEvent is a segment the Reassembler refused.
type TransportEvent struct {
	FromClient bool
	Frame      int
	Err        error
}

type assocKey struct {
	fromClient bool
	src, dest  link.Address
}

// Fragments reassembles the user data of the frames into application
// fragments, one transport.Reassembler per direction and address pair.
// A CONFIRMED_USER_DATA frame that repeats the previous one of its
// direction with the same FCB is a link layer retransmission (IEEE
// 1815-2012 clause 9.2.6.3.2) and is not given to the transport function
// again.
func Fragments(frames []LinkFrame) ([]Fragment, []TransportEvent) {
	type state struct {
		r        *transport.Reassembler
		segs     int
		lastFCB  bool
		lastData []byte
		haveLast bool
	}
	st := map[assocKey]*state{}
	var out []Fragment
	var events []TransportEvent
	for _, lf := range frames {
		if lf.Err != nil || !lf.Link.Function.HasData() {
			continue
		}
		k := assocKey{lf.FromClient, lf.Link.Src, lf.Link.Dest}
		s := st[k]
		if s == nil {
			s = &state{r: transport.NewReassembler(1 << 16)}
			st[k] = s
		}
		if lf.Link.Function == link.PrimaryConfirmedUserData && lf.Link.FCV {
			if s.haveLast && s.lastFCB == lf.Link.FCB && bytes.Equal(s.lastData, lf.Link.Data) {
				continue
			}
			s.lastFCB, s.lastData, s.haveLast = lf.Link.FCB, lf.Link.Data, true
		}
		if transport.Header(lf.Link.Data[0]).FIR() {
			s.segs = 0
		}
		s.segs++
		frag, err := s.r.Add(lf.Link.Data)
		if err != nil {
			events = append(events, TransportEvent{FromClient: lf.FromClient, Frame: lf.Frame, Err: err})
			continue
		}
		if frag == nil {
			continue
		}
		f := Fragment{FromClient: lf.FromClient, Src: lf.Link.Src, Dest: lf.Link.Dest, Frame: lf.Frame,
			Time: lf.Time, Segments: s.segs, Raw: frag}
		f.Frag, f.Err = app.Decode(frag)
		out = append(out, f)
	}
	return out, events
}

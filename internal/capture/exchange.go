// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"slices"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// Exchange is a request of a master and the solicited response fragments
// the outstation sent for it, in the order of the conversation.
type Exchange struct {
	Request Fragment
	// Responses are the RESPONSE fragments of the request, from FIR (with
	// the request's sequence number) up to FIN (or up to the next request,
	// when the recording ends or the outstation stops early).
	Responses []Fragment
	// Complete reports whether the last response carries FIN.
	Complete bool
}

// Exchanges pairs the requests of a stream with their responses. A
// request app.Decode refused is kept (Request.Err is set: an outstation
// answers it with an IIN2 error); a response it refused is left out, as
// are CONFIRM requests (they have no response). The master is the side
// that sends requests; a fragment that is not a response is a request.
//
// A master may send a request before the response to the previous one
// (some recorded masters pipeline a SELECT, an OPERATE and the next
// SELECT): every request stays open until its response ends, and a first
// response fragment goes to the oldest open request with its sequence
// number. A request that repeats an unanswered open one octet for octet
// closes it: the response goes to the repeat, as for a retransmission.
func Exchanges(s Stream) []Exchange {
	var out []Exchange
	var open []int // indexes into out of the exchanges without a final fragment
	drop := func(i int) {
		for k, j := range open {
			if j == i {
				open = append(open[:k], open[k+1:]...)
				return
			}
		}
	}
	for _, f := range s.Fragments {
		if f.Frag == nil || (f.Err != nil && f.Frag.Function.IsResponse()) {
			continue
		}
		fc := f.Frag.Function
		switch {
		case !fc.IsResponse():
			if fc == app.FuncConfirm {
				continue
			}
			for _, j := range slices.Clone(open) {
				if r := out[j].Request; r.FromClient == f.FromClient && bytes.Equal(r.Raw, f.Raw) && len(out[j].Responses) == 0 {
					drop(j)
				}
			}
			out = append(out, Exchange{Request: f})
			open = append(open, len(out)-1)
		case fc == app.FuncResponse:
			// The first fragment echoes the request's sequence number,
			// each further one the next (IEEE 1815-2012 clause 4.3.3).
			for _, j := range open {
				cur := &out[j]
				if f.FromClient == cur.Request.FromClient {
					continue
				}
				want := cur.Request.Frag.Control.Seq
				if n := len(cur.Responses); n > 0 {
					want = app.NextSeq(cur.Responses[n-1].Frag.Control.Seq)
				}
				if f.Frag.Control.Seq != want || f.Frag.Control.FIR != (len(cur.Responses) == 0) {
					continue
				}
				cur.Responses = append(cur.Responses, f)
				cur.Complete = f.Frag.Control.FIN
				if cur.Complete {
					drop(j)
				}
				break
			}
		}
	}
	return out
}

// Unsolicited returns the UNSOLICITED_RESPONSE fragments of a stream.
func Unsolicited(s Stream) []Fragment {
	var out []Fragment
	for _, f := range s.Fragments {
		if f.Err == nil && f.Frag != nil && f.Frag.Function == app.FuncUnsolicitedResponse {
			out = append(out, f)
		}
	}
	return out
}

// MasterFrames returns the link frames the master sent in a stream, in
// order, with their recorded bytes: the side that sent the first request
// fragment, or the side whose frames have DIR set.
func MasterFrames(s Stream) []LinkFrame {
	fromClient, ok := masterSide(s)
	if !ok {
		return nil
	}
	var out []LinkFrame
	for _, lf := range s.Links {
		if lf.FromClient == fromClient {
			out = append(out, lf)
		}
	}
	return out
}

func masterSide(s Stream) (fromClient, ok bool) {
	for _, f := range s.Fragments {
		if f.Frag != nil && !f.Frag.Function.IsResponse() {
			return f.FromClient, true
		}
	}
	for _, lf := range s.Links {
		if lf.Err == nil {
			return lf.FromClient == lf.Link.Dir, true
		}
	}
	return false, false
}

// Addresses returns the master's and the outstation's link addresses: the
// source and destination of the master's first decoded frame that is not
// a broadcast.
func Addresses(s Stream) (master, outstation link.Address, ok bool) {
	fromClient, ok := masterSide(s)
	if !ok {
		return 0, 0, false
	}
	for _, lf := range s.Links {
		if lf.Err == nil && lf.FromClient == fromClient && !lf.Link.Dest.Broadcast() {
			return lf.Link.Src, lf.Link.Dest, true
		}
	}
	return 0, 0, false
}

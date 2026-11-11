// SPDX-License-Identifier: MIT

package capture

import (
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

func frag(frame int, client bool, fc app.FunctionCode, seq uint8, fir, fin bool, raw ...byte) Fragment {
	return Fragment{
		FromClient: client,
		Frame:      frame,
		Raw:        append([]byte{byte(fc), seq}, raw...),
		Frag:       &app.Fragment{Control: app.Control{FIR: fir, FIN: fin, Seq: seq}, Function: fc},
	}
}

func pairs(exs []Exchange) map[int][]int {
	out := map[int][]int{}
	for _, ex := range exs {
		var rs []int
		for _, r := range ex.Responses {
			rs = append(rs, r.Frame)
		}
		out[ex.Request.Frame] = rs
	}
	return out
}

func TestExchangesPipelined(t *testing.T) {
	// A master sends SELECT, OPERATE and the next SELECT (same sequence
	// number as the first) before the first answer arrives.
	s := Stream{Fragments: []Fragment{
		frag(1, true, app.FuncSelect, 7, true, true, 1),
		frag(2, true, app.FuncOperate, 8, true, true, 1),
		frag(3, true, app.FuncSelect, 7, true, true, 2),
		frag(4, false, app.FuncResponse, 7, true, true),
		frag(5, false, app.FuncResponse, 8, true, true),
		frag(6, false, app.FuncResponse, 7, true, true),
	}}
	got := pairs(Exchanges(s))
	want := map[int][]int{1: {4}, 2: {5}, 3: {6}}
	for k, v := range want {
		if len(got[k]) != 1 || got[k][0] != v[0] {
			t.Errorf("request %d: responses %v, want %v", k, got[k], v)
		}
	}
}

func TestExchangesRetransmission(t *testing.T) {
	// A repeated request closes the unanswered one (the response goes to
	// the repeat); a CONFIRM is no request; a multi-fragment response
	// follows the sequence numbers.
	s := Stream{Fragments: []Fragment{
		frag(1, true, app.FuncRead, 3, true, true, 9),
		frag(2, true, app.FuncRead, 3, true, true, 9),
		frag(3, false, app.FuncResponse, 3, true, false),
		frag(4, true, app.FuncConfirm, 3, true, true),
		frag(5, false, app.FuncResponse, 5, false, true), // wrong sequence: dropped
		frag(6, false, app.FuncResponse, 4, false, true),
	}}
	exs := Exchanges(s)
	if len(exs) != 2 || len(exs[0].Responses) != 0 || exs[1].Request.Frame != 2 || !exs[1].Complete {
		t.Fatalf("exchanges %+v", pairs(exs))
	}
	if got := pairs(exs)[2]; len(got) != 2 || got[0] != 3 || got[1] != 6 {
		t.Errorf("responses %v, want [3 6]", got)
	}
}

func TestExchangesChallenge(t *testing.T) {
	// SAv5: the RESPONSE after the challenge exchange answers the
	// critical request, not the AUTHENTICATE_REQ (both carry its
	// sequence number).
	s := Stream{Fragments: []Fragment{
		frag(1, true, app.FuncDirectOperate, 6, true, true, 1),
		frag(2, false, app.FuncAuthResponse, 6, true, true),
		frag(3, true, app.FuncAuthRequest, 6, true, true, 2),
		frag(4, false, app.FuncResponse, 6, true, true),
	}}
	got := pairs(Exchanges(s))
	if len(got[1]) != 1 || got[1][0] != 4 || len(got[3]) != 0 {
		t.Errorf("pairs %v", got)
	}
}

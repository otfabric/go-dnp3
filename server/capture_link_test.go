// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/internal/capture"
	"github.com/otfabric/go-dnp3/link"
)

// The link replay sends a recorded master's octets to the outstation as
// they were captured, one capture frame at a time, damaged frames
// included, and compares the outstation's link layer reaction to each with
// the recorded outstation's: the secondary functions it answered with
// (ACK, NACK, LINK_STATUS, NOT_SUPPORTED) and whether it sent user data.
// Only conversations whose master uses more of the link layer than
// UNCONFIRMED_USER_DATA, or sends damaged frames, are replayed this way;
// the application replay covers the rest. The igbe attack recording is
// left out: its damaged octets are injected segments of an attacker
// (TCP sequence numbers reused), so the recorded outstation's reactions
// cannot be attributed to the master frame before them.

// linkReaction is what an outstation sent between two master frames.
type linkReaction struct {
	secondary []link.Function
	data      bool
}

func (r linkReaction) String() string {
	var s []string
	for _, f := range r.secondary {
		s = append(s, f.String())
	}
	if r.data {
		s = append(s, "user data")
	}
	if len(s) == 0 {
		return "nothing"
	}
	return strings.Join(s, ", ")
}

func (r *linkReaction) add(f link.Frame) {
	if f.Function.Primary() {
		r.data = r.data || f.Function.HasData()
		return
	}
	r.secondary = append(r.secondary, f.Function)
}

// linkReplayed reports whether a stream's master exercises the link layer.
func linkReplayed(s capture.Stream, master bool) bool {
	for _, lf := range s.Links {
		if lf.FromClient != master {
			continue
		}
		if lf.Err != nil || lf.Link.Function != link.PrimaryUnconfirmedUserData {
			return true
		}
	}
	return false
}

// masterChunks splits the master's octets by the capture frame that
// carried them.
type chunk struct {
	frame int
	data  []byte
}

func masterChunks(s capture.Stream, master bool) []chunk {
	var out []chunk
	for _, r := range s.Runs {
		if r.FromClient != master {
			continue
		}
		for i, b := range r.Data {
			if n := len(out); n > 0 && out[n-1].frame == r.Frames[i] {
				out[n-1].data = append(out[n-1].data, b)
				continue
			}
			out = append(out, chunk{frame: r.Frames[i], data: []byte{b}})
		}
	}
	slices.SortStableFunc(out, func(a, b chunk) int { return a.frame - b.frame })
	return out
}

// serverLinkExpected are the classified differences of the link replay,
// by "file id:capture frame of the master's octets".
var serverLinkExpected = map[string]string{}

func TestCaptureServerLinkReplay(t *testing.T) {
	recs, err := capture.Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	chunks := 0
	for _, r := range recs {
		for si, s := range r.Conversations {
			masterOutstation, outstation, ok := capture.Addresses(s)
			if !ok {
				continue
			}
			side := capture.MasterFrames(s)
			if len(side) == 0 {
				continue
			}
			master := side[0].FromClient
			if !linkReplayed(s, master) || r.File.Source == "igbe" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", r.File.ID, si), func(t *testing.T) {
				cs := masterChunks(s, master)
				chunks += len(cs)
				for k, v := range replayLink(t, r.File.ID, masterOutstation, outstation, s, master, cs) {
					got[k] = v
				}
			})
		}
	}
	for k, what := range got {
		if _, ok := serverLinkExpected[k]; !ok {
			t.Errorf("unclassified link difference %s: %s", k, what)
		}
	}
	for k, why := range serverLinkExpected {
		if _, ok := got[k]; !ok {
			t.Errorf("classified link difference %s (%s) no longer occurs", k, why)
		}
	}
	t.Logf("link replay: %d master frames, %d classified differences", chunks, len(got))
}

func replayLink(t *testing.T, file string, masterAddr, outstation link.Address, s capture.Stream, master bool, cs []chunk) map[string]string {
	t.Helper()
	srv, err := New(WithAddress(outstation), WithHandler(replayHandler{}))
	if err != nil {
		t.Fatal(err)
	}
	replayDB(t, srv.Database(), s)
	c, ss := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(ss, nil) }()
	frames := make(chan link.Frame, 64)
	go func() {
		defer close(frames)
		r := link.NewReader(c)
		for {
			f, err := r.ReadFrame()
			if err != nil {
				if errors.Is(err, link.ErrFraming) {
					continue
				}
				return
			}
			frames <- f
		}
	}()
	defer func() {
		_ = srv.Close()
		_ = c.Close()
		if err := <-done; err != nil {
			t.Logf("ServeConn: %v", err)
		}
	}()
	diffs := map[string]string{}
	for i, ch := range cs {
		next := int(^uint(0) >> 1)
		if i+1 < len(cs) {
			next = cs[i+1].frame
		}
		var want linkReaction
		for _, lf := range s.Links {
			if lf.FromClient != master && lf.Err == nil && lf.Frame > ch.frame && lf.Frame < next {
				want.add(lf.Link)
			}
		}
		if _, err := c.Write(ch.data); err != nil {
			t.Fatal(err)
		}
		var have linkReaction
		wait := 250 * time.Millisecond
		if want.String() != "nothing" {
			wait = time.Second
		}
	collect:
		for {
			select {
			case f, ok := <-frames:
				if !ok {
					break collect
				}
				have.add(f)
				wait = 50 * time.Millisecond
			case <-time.After(wait):
				break collect
			}
		}
		if have.String() != want.String() {
			diffs[fmt.Sprintf("%s:%d", file, ch.frame)] = fmt.Sprintf("go-dnp3 %s, recorded %s", have, want)
		}
	}
	return diffs
}

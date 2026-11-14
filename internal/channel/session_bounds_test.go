// SPDX-License-Identifier: MIT

package channel

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/internal/leaktest"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// TestFragmentKeepsOneDestination: the segments of one fragment share a
// destination. A segment for another destination (broadcast, self address
// or the station's own) discards the partial fragment, so that a fragment
// is never delivered with the destination of its last segment only.
func TestFragmentKeepsOneDestination(t *testing.T) {
	leaktest.Check(t)
	_, m, in := outstationWithRaw(t, SessionConfig{SelfAddress: true})
	seg := func(fir, fin bool, seq uint8, data ...byte) []byte {
		return append([]byte{byte(transport.NewHeader(fir, fin, seq))}, data...)
	}
	send := func(dest link.Address, data []byte) {
		m.write(link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: dest, Src: masterAddr, Data: data})
	}

	// Unicast first segment, broadcast continuation: nothing delivered.
	send(outstationAddr, seg(true, false, 0, 1))
	send(link.BroadcastNoConfirm, seg(false, true, 1, 2))
	// Broadcast first segment, unicast continuation: nothing delivered.
	send(link.BroadcastOptionalConfirm, seg(true, false, 2, 3))
	send(outstationAddr, seg(false, true, 3, 4))
	// Self-address first segment, unicast continuation: nothing delivered.
	send(link.SelfAddress, seg(true, false, 4, 5))
	send(outstationAddr, seg(false, true, 5, 6))
	// A partial unicast fragment followed by a whole broadcast one: the
	// broadcast is delivered alone, with its own destination.
	send(outstationAddr, seg(true, false, 6, 7))
	send(link.BroadcastNoConfirm, seg(true, true, 7, 8))
	if d := in.next(t); !bytes.Equal(d.frag, []byte{8}) || d.dest != link.BroadcastNoConfirm {
		t.Fatalf("got %v to %d, want [8] to the broadcast address", d.frag, d.dest)
	}
	// Segments with one destination still assemble.
	send(outstationAddr, seg(true, false, 8, 9))
	send(outstationAddr, seg(false, true, 9, 10))
	if d := in.next(t); !bytes.Equal(d.frag, []byte{9, 10}) || d.dest != outstationAddr {
		t.Fatalf("got %v to %d, want [9 10] to the station", d.frag, d.dest)
	}
	in.none(t, 50*time.Millisecond)
}

// heldStream is a Stream whose writes wait until release is closed, and
// whose reads end when it is closed.
type heldStream struct {
	writing chan struct{} // closed when the first write starts
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
	wOnce   sync.Once
}

func (h *heldStream) Read([]byte) (int, error) {
	<-h.closed
	return 0, io.EOF
}

func (h *heldStream) Write(b []byte) (int, error) {
	h.wOnce.Do(func() { close(h.writing) })
	<-h.release
	return len(b), nil
}

func (h *heldStream) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

// TestDoneWaitsForKeepAliveProbe: Done means every goroutine of the
// channel has returned, the keep-alive probe included.
func TestDoneWaitsForKeepAliveProbe(t *testing.T) {
	leaktest.Check(t)
	h := &heldStream{writing: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	ch := New(h, Config{})
	ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true,
		KeepAlive: time.Millisecond, ResponseTimeout: time.Hour})
	ch.Start()
	select {
	case <-h.writing: // the probe is writing REQUEST_LINK_STATUS
	case <-time.After(3 * time.Second):
		t.Fatal("no keep-alive probe")
	}
	ch.Close(nil)
	select {
	case <-ch.Done():
		t.Fatal("Done closed while the keep-alive probe was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(h.release)
	select {
	case <-ch.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("channel not done after the probe returned")
	}
}

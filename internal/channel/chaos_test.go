// SPDX-License-Identifier: MIT

package channel

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/link"
)

// faultPipe is an in-memory stream that injects byte-level faults on the
// data written into it: corruption, duplication and truncation. It feeds a
// reader on the other side. It models a noisy link, the kind the link
// layer must resynchronise through.
type faultPipe struct {
	mu                 sync.Mutex
	buf                []byte
	closed             bool
	cond               *sync.Cond
	rng                *rand.Rand
	corrupt, dup, drop float64
}

func newFaultPipe(seed int64, corrupt, dup, drop float64) *faultPipe {
	p := &faultPipe{rng: rand.New(rand.NewSource(seed)), corrupt: corrupt, dup: dup, drop: drop}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *faultPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errors.New("closed")
	}
	for _, x := range b {
		if p.rng.Float64() < p.drop {
			continue
		}
		if p.rng.Float64() < p.corrupt {
			x ^= byte(1 << p.rng.Intn(8))
		}
		p.buf = append(p.buf, x)
		if p.rng.Float64() < p.dup {
			p.buf = append(p.buf, x)
		}
	}
	p.cond.Broadcast()
	return len(b), nil
}

func (p *faultPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		return 0, errors.New("closed")
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *faultPipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
	return nil
}

// TestReaderSurvivesNoisyLink feeds a stream of valid frames through a
// pipe that corrupts, duplicates and drops octets. The reader must never
// hang, never return a frame with a bad CRC, and still deliver some of the
// undamaged frames.
func TestReaderSurvivesNoisyLink(t *testing.T) {
	for _, seed := range []int64{1, 2, 3, 7, 42} {
		p := newFaultPipe(seed, 0.01, 0.01, 0.005)
		const n = 400
		go func() {
			for i := range n {
				f := link.Frame{Dir: true, Function: link.PrimaryUnconfirmedUserData, Dest: 1, Src: 2,
					Data: []byte{byte(i), byte(i >> 8), 0xAA, 0x55}}
				b, _ := f.Encode()
				_, _ = p.Write(b)
			}
			_ = p.Close()
		}()
		r := link.NewReader(p)
		good, framing := 0, 0
		for {
			f, err := r.ReadFrame()
			if err != nil {
				if errors.Is(err, link.ErrFraming) {
					framing++
					continue
				}
				break
			}
			// A frame that decodes has a valid CRC by construction; check
			// its payload is internally consistent.
			if len(f.Data) != 4 || f.Data[2] != 0xAA || f.Data[3] != 0x55 {
				t.Fatalf("seed %d: corrupt frame passed CRC: % x", seed, f.Data)
			}
			good++
		}
		if good == 0 {
			t.Fatalf("seed %d: no frame survived", seed)
		}
		t.Logf("seed %d: %d good frames, %d framing errors", seed, good, framing)
	}
}

// TestSessionSurvivesReorderedDuplicates drives confirmed user data
// through a pipe that duplicates octets (hence whole frames can repeat),
// and checks the reassembled fragments arrive intact and in order.
func TestSessionConfirmedOverDuplicatingLink(t *testing.T) {
	// Duplication at the byte level turns into repeated frames; the link
	// layer's FCB must discard the repeats.
	aPipe := newFaultPipe(100, 0, 0.02, 0)
	bPipe := newFaultPipe(200, 0, 0.02, 0)
	a := &duplexStream{r: bPipe, w: aPipe}
	b := &duplexStream{r: aPipe, w: bPipe}

	in := newInbox()
	mch := New(a, Config{})
	och := New(b, Config{})
	m := mch.AddSession(SessionConfig{Local: 1, Remote: 2, Master: true, Confirmed: true, ResponseTimeout: 500 * time.Millisecond, Retries: 5})
	och.AddSession(SessionConfig{Local: 2, Remote: 1, Confirmed: true, ResponseTimeout: 500 * time.Millisecond, OnFragment: in.fn})
	mch.Start()
	och.Start()
	defer func() { mch.Close(nil); och.Close(nil); <-mch.Done(); <-och.Done() }()

	for i := range 20 {
		if err := m.Send(context.Background(), []byte{byte(i), 0x11, 0x22}); err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	for seen < 20 {
		d := in.next(t)
		// Duplicated frames may deliver a fragment twice at the transport
		// layer only if FCB fails; here we tolerate repeats but require
		// every value to appear and none to be corrupt.
		if len(d.frag) != 3 || d.frag[1] != 0x11 || d.frag[2] != 0x22 {
			t.Fatalf("corrupt fragment % x", d.frag)
		}
		if int(d.frag[0]) == seen {
			seen++
		}
	}
}

// duplexStream joins a reader and a writer into one stream.
type duplexStream struct {
	r, w *faultPipe
}

func (d *duplexStream) Read(b []byte) (int, error)  { return d.r.Read(b) }
func (d *duplexStream) Write(b []byte) (int, error) { return d.w.Write(b) }
func (d *duplexStream) Close() error {
	_ = d.r.Close()
	_ = d.w.Close()
	return nil
}

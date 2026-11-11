package channel

import (
	"context"
	"errors"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/link"
)

// TestSendUnconfirmedFailures checks that SendUnconfirmed, used for the
// time synchronization messages of IEEE 1815-2012 clause 10.3.4.1, reports
// a closed channel before it writes, and a failed write as a lost
// connection.
func TestSendUnconfirmedFailures(t *testing.T) {
	t.Run("closed", func(t *testing.T) {
		s, _ := masterStation(t, SessionConfig{}, Config{})
		s.ch.Close(nil)
		<-s.ch.Done()
		if err := s.SendUnconfirmed(context.Background(), []byte{0xC0, 0x18}); err == nil {
			t.Fatal("sent on a closed channel")
		}
	})
	t.Run("write fails", func(t *testing.T) {
		w := newFaultPipe(1, 0, 0, 0)
		_ = w.Close()
		ch := New(&duplexStream{r: newFaultPipe(1, 0, 0, 0), w: w}, Config{})
		s := ch.AddSession(SessionConfig{Local: masterAddr, Remote: outstationAddr, Master: true})
		ch.Start()
		t.Cleanup(func() { ch.Close(nil); <-ch.Done() })
		err := s.SendUnconfirmed(context.Background(), []byte{0xC0, 0x18})
		if !errors.Is(err, dnp3.ErrConnectionLost) {
			t.Fatalf("got %v, want ErrConnectionLost", err)
		}
		<-ch.Done()
	})
}

// TestHandleFrameSelfAddressNotEnabled checks the session's own guard of
// clause 9.2.5.2.2 (p. 282): a frame to the self address 0xFFFC reaching a
// session without the feature is ignored. The channel does not route such
// frames to it (TestSpec9_2_5_2_2_SelfAddress); the session does not rely
// on that.
func TestHandleFrameSelfAddressNotEnabled(t *testing.T) {
	s, m := outstationStation(t, SessionConfig{}, Config{})
	f := m.pri(link.PrimaryUnconfirmedUserData, false, segmentOf([]byte{1}))
	f.Dest = link.SelfAddress
	s.handleFrame(f)
	m.notDelivered()
	m.noReply()
}

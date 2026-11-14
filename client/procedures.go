// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
)

// procState is the state of the master procedures of IEEE 1815-2012 on
// the current channel.
type procState struct {
	// sendMu is held while a request is handed to the link layer and while
	// a received fragment is handled, so that the confirmation a fragment
	// asks for precedes the next request (clause 4.3 Rule 13).
	sendMu sync.Mutex

	mu sync.Mutex
	// iin are the internal indications of the outstation's latest response.
	iin app.IIN
	// unsSeen, unsSeq and unsObjects describe the last accepted unsolicited
	// response: its sequence number and the octets after its IIN, to
	// recognise a repeat (clause 4.6.6 Rule 7).
	unsSeen    bool
	unsSeq     uint8
	unsObjects []byte
	// sync is the procedure of automatic time synchronization on this
	// channel; auto is set when it is the client's own choice, which falls
	// back to the non-LAN procedure.
	sync TimeSync
	auto bool
	// enabled is when ENABLE_UNSOLICITED of the startup or restart
	// procedure last completed.
	enabled time.Time
	// restartAt is when the latest report of a restart (IIN1.7) was
	// received. rekey is set while a restart that calls for a session key
	// change waits for the restart procedure, and rekeyKey is the session
	// key in use when it was reported.
	restartAt time.Time
	rekey     bool
	rekeyKey  []byte
}

// reset starts the state of a new channel.
func (p *procState) reset(sync TimeSync, auto bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.iin = 0
	p.unsSeen, p.unsSeq, p.unsObjects = false, 0, nil
	p.sync, p.auto = sync, auto
	p.enabled = time.Time{}
	p.restartAt, p.rekey, p.rekeyKey = time.Time{}, false, nil
}

func (p *procState) lastIIN() app.IIN {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.iin
}

func (p *procState) setIIN(iin app.IIN) {
	p.mu.Lock()
	p.iin = iin
	p.mu.Unlock()
}

func (p *procState) timeSync() (TimeSync, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sync, p.auto
}

func (p *procState) setTimeSync(s TimeSync) {
	p.mu.Lock()
	p.sync = s
	p.mu.Unlock()
}

func (p *procState) enabledSince(t time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled.After(t)
}

func (p *procState) setEnabled() {
	p.mu.Lock()
	p.enabled = time.Now()
	p.mu.Unlock()
}

// restarted records a report of a restart; rekey, with the session key
// in use, when it calls for a session key change.
func (p *procState) restarted(rekey bool, key []byte) {
	p.mu.Lock()
	p.restartAt = time.Now()
	if rekey {
		p.rekey, p.rekeyKey = true, key
	}
	p.mu.Unlock()
}

// lastRestart returns when the latest report of a restart was received,
// and takes the session key change it calls for: whether one is due, and
// the session key in use when it was reported.
func (p *procState) lastRestart() (at time.Time, rekey bool, key []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at, rekey, key = p.restartAt, p.rekey, p.rekeyKey
	p.rekey, p.rekeyKey = false, nil
	return at, rekey, key
}

// autoTimeSync returns the automatic time synchronization procedure of a
// channel over stream, and whether it is the client's own choice: that of
// WithTimeSync when set, otherwise the LAN procedure over a network
// connection and the non-LAN procedure over other streams (IEEE 1815-2012
// clauses 10.3.3.1 and 10.3.3.2).
func (c *Client) autoTimeSync(stream channel.Stream) (TimeSync, bool) {
	if c.opts.timeSyncSet {
		return c.opts.timeSync, false
	}
	if _, ok := stream.(net.Conn); ok {
		return TimeSyncLAN, true
	}
	return TimeSyncNonLAN, true
}

// unsContradicts reports whether the UNS bit of a response fragment
// contradicts its function code (IEEE 1815-2012 clause 4.2.2.4.4):
// outstations set it in unsolicited responses only.
func unsContradicts(f *app.Fragment) bool {
	switch f.Function {
	case app.FuncResponse:
		return f.Control.UNS
	case app.FuncUnsolicitedResponse:
		return !f.Control.UNS
	default:
		return false
	}
}

// receiveUnsolicited handles an unsolicited response (IEEE 1815-2012
// clause 4.6.6 and Table 6-3): it is confirmed at once when it asks for
// it, whatever the master is doing (Rule 6), and the state of its FIR and
// FIN bits is ignored (Rule 4). One with the sequence number of the
// previous one and the same octets after the IIN is a repeat (Rule 7) and
// is not processed again, unless it reports a restart (Table 6-3 row 8);
// one with the same sequence number and other octets is processed and,
// with WithAutoIntegrity, followed by an integrity poll (Table 6-3 row 5).
//
// While the handler's queue is full (maxNotices), an unsolicited response
// is neither processed nor confirmed, as one lost on the line: the
// outstation keeps its events and repeats it.
func (c *Client) receiveUnsolicited(sess *channel.Session, f *app.Fragment, data []byte) {
	if c.opts.handler != nil && c.events.full() {
		err := fmt.Errorf("%w: handler queue full (%d fragments), unsolicited response seq %d not taken", dnp3.ErrProtocol, maxNotices, f.Control.Seq)
		c.log.Warn("unsolicited response dropped", "error", err)
		if m := c.opts.metrics; m != nil {
			m.OnDecodeError(c.remoteAddr(), err)
		}
		return
	}
	if f.Control.CON {
		if c.opts.noUnsConfirm {
			c.log.Debug("unsolicited response not confirmed (WithUnsolicitedConfirm)", "seq", f.Control.Seq)
		} else {
			c.confirmResponse(sess, f, data, true)
		}
	}
	objects := data[4:] // app.Decode accepted it: the header and the IIN are there
	p := &c.proc
	p.mu.Lock()
	sameSeq := p.unsSeen && p.unsSeq == f.Control.Seq
	repeat := sameSeq && bytes.Equal(p.unsObjects, objects)
	p.unsSeen, p.unsSeq, p.unsObjects = true, f.Control.Seq, objects
	p.mu.Unlock()
	if repeat && !f.IIN.Has(app.IINDeviceRestart) {
		c.log.Debug("repeated unsolicited response ignored", "seq", f.Control.Seq)
		return
	}
	c.events.response(f, fragmentCost(f, data), true)
	c.onIIN(f.IIN)
	if sameSeq && !repeat && c.opts.autoIntegrity {
		c.log.Debug("new unsolicited response with the previous sequence number: integrity poll", "seq", f.Control.Seq)
		c.enqueueIntegrity()
	}
}

// enqueueIntegrity queues an integrity poll, skipped when one completes
// before it runs.
func (c *Client) enqueueIntegrity() {
	queued := time.Now()
	c.enqueue(task{name: "integrity", run: func(ctx context.Context) error {
		// An integrity poll that completed since, by the startup sequence,
		// the restart procedure or the application, already did what this
		// one would.
		if c.integritySince(queued) {
			return nil
		}
		_, err := c.IntegrityPoll(ctx)
		return err
	}})
}

// currentKey returns the control direction session key of the channel,
// nil without one.
func (c *Client) currentKey() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.auth.sessionKey
}

// sameKey reports whether a and b are the same session key, not merely
// equal: a session key change allocates a new one.
func sameKey(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// hasRestartSteps reports whether the restart procedure has a step to run
// with the client's options.
func (c *Client) hasRestartSteps() bool {
	o := c.opts
	return o.autoClearRestart || o.autoIntegrity || len(o.startup.EnableUnsolicited) > 0 ||
		(o.auth != nil && len(o.auth.UpdateKey) > 0)
}

// restartProcedure answers a restart of the outstation (IIN1.7) with the
// steps of IEEE 1815-2012 clause 5.1.1.1.2 Rule 2, in their order. It
// works from the latest report of a restart, so that the procedure a
// report finds queued answers it: a step done since that report, by the
// startup sequence or an earlier run of the procedure, is not repeated.
//
//  1. with secure authentication and an update key, the session keys are
//     changed when the restart calls for it (restartRekey: IIN1.7 newly
//     set, within Max Rekeys Due to Restarts, clause 7.5.4.2), since the
//     restart lost them, unless they were changed since it was reported;
//  2. IIN1.7 is cleared (WithAutoClearRestart), while the outstation still
//     reports it;
//  3. the time is synchronized while the outstation reports NEED_TIME and
//     automatic time synchronization is on;
//  4. an integrity poll runs (WithAutoIntegrity);
//  5. unsolicited reporting is enabled again for the classes of
//     Startup.EnableUnsolicited, since the restart disabled it (clause
//     5.1.1.1.1 Rule 3).
//
// A step the outstation rejects (an IINError) is logged and the procedure
// goes on; a step without a valid response ends it. A restart reported
// during the procedure queues it again.
func (c *Client) restartProcedure(ctx context.Context) error {
	detected, rekey, key := c.proc.lastRestart()
	o := c.opts
	if rekey && sameKey(c.currentKey(), key) {
		if err := c.changeSessionKeys(ctx); err != nil {
			c.rekeySoon()
			return err
		}
	}
	if o.autoClearRestart && c.proc.lastIIN().Has(app.IINDeviceRestart) {
		if err := c.procedureStep("restart", "clear restart", c.ClearRestart(ctx)); err != nil {
			return err
		}
	}
	if c.needTime.Load() {
		if err := c.procedureStep("restart", "time sync", c.autoSyncTime(ctx)); err != nil {
			return err
		}
	}
	if o.autoIntegrity && !c.integritySince(detected) {
		_, err := c.IntegrityPoll(ctx)
		if err := c.procedureStep("restart", "integrity poll", err); err != nil {
			return err
		}
	}
	if cl := o.startup.EnableUnsolicited; len(cl) > 0 && !c.proc.enabledSince(detected) {
		if err := c.procedureStep("restart", "enable unsolicited", c.EnableUnsolicited(ctx, cl...)); err != nil {
			return err
		}
		c.proc.setEnabled()
	}
	return nil
}

// procedureStep returns the error of a step that ends a procedure: an
// IINError, a step the outstation rejected, is logged instead.
func (c *Client) procedureStep(procedure, step string, err error) error {
	if _, ok := errors.AsType[*dnp3.IINError](err); ok {
		c.log.Warn("procedure step rejected", "procedure", procedure, "step", step, "error", err)
		return nil
	}
	return err
}

// notSupported reports whether err is the rejection of a request the
// outstation does not support: IIN2.0 (function code) or IIN2.1 (object).
func notSupported(err error) bool {
	ie, ok := errors.AsType[*dnp3.IINError](err)
	return ok && ie.IIN&(app.IINNoFuncCodeSupport|app.IINObjectUnknown) != 0
}

// autoSyncTime answers NEED_TIME with the automatic time synchronization
// procedure of the channel (IEEE 1815-2012 clauses 4.5.5 and 10.3.3).
// When the procedure is the client's own choice and the outstation
// refuses the LAN procedure as not supported, the non-LAN procedure is
// used from then on; when it refuses that too, automatic time
// synchronization stops for the channel.
func (c *Client) autoSyncTime(ctx context.Context) error {
	p, auto := c.proc.timeSync()
	if p == TimeSyncNone {
		return nil
	}
	err := c.SyncTime(ctx, p)
	if err == nil {
		c.lastSync.Store(time.Now().UnixNano())
	}
	if !auto || !notSupported(err) {
		return err
	}
	if p == TimeSyncLAN {
		c.log.Info("the outstation does not support the LAN time synchronization: using the non-LAN procedure", "error", err)
		c.proc.setTimeSync(TimeSyncNonLAN)
		if err = c.SyncTime(ctx, TimeSyncNonLAN); !notSupported(err) {
			return err
		}
	}
	c.log.Warn("the outstation does not support time synchronization: automatic time synchronization off for this connection", "error", err)
	c.proc.setTimeSync(TimeSyncNone)
	return err
}

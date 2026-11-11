// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"strconv"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// task is work the client does on its own: answering internal indications
// and periodic polls. Tasks run one at a time on the task goroutine; a
// task already queued is not queued twice.
type task struct {
	name string
	run  func(ctx context.Context) error
}

func (c *Client) enqueue(t task) {
	c.taskMu.Lock()
	defer c.taskMu.Unlock()
	if c.queued[t.name] {
		return
	}
	select {
	case c.tasks <- t:
		c.queued[t.name] = true
	default:
		c.log.Debug("automatic task dropped: queue full", "task", t.name)
	}
}

func (c *Client) dequeued(name string) {
	c.taskMu.Lock()
	delete(c.queued, name)
	c.taskMu.Unlock()
}

func (c *Client) taskLoop() {
	defer c.wg.Done()
	var polls sync.WaitGroup
	stop := make(chan struct{})
	for i, p := range c.opts.polls {
		polls.Go(func() {
			c.pollLoop(i, p, stop)
		})
	}
	if u := c.opts.auth; u != nil && len(u.UpdateKey) > 0 {
		polls.Go(func() {
			c.keyChangeLoop(stop)
		})
	}
	defer func() {
		close(stop)
		polls.Wait()
		// Forget what is still queued.
		for {
			select {
			case t := <-c.tasks:
				c.dequeued(t.name)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-c.closeCh:
			return
		case t := <-c.tasks:
			c.dequeued(t.name)
			// Wait for the startup sequence: it may already do what the
			// task would, and the two must not compete for the turn.
			if done := c.startupDone(); done != nil {
				select {
				case <-done:
				case <-c.closeCh:
					return
				}
			}
			if c.State() != dnp3.StateConnected {
				continue
			}
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-c.closeCh:
					cancel()
				case <-ctx.Done():
				}
			}()
			if err := t.run(ctx); err != nil {
				c.log.Warn("automatic task failed", "task", t.name, "error", err)
			}
			cancel()
		}
	}
}

func (c *Client) pollLoop(i int, p Poll, stop <-chan struct{}) {
	timer := time.NewTimer(p.Interval)
	defer timer.Stop()
	name := "poll-" + strconv.Itoa(i)
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			c.enqueue(task{name: name, run: func(ctx context.Context) error {
				_, err := c.Read(ctx, p.Headers...)
				return err
			}})
			timer.Reset(p.Interval)
		}
	}
}

// onIIN queues the tasks the internal indications of a response call
// for.
func (c *Client) onIIN(iin app.IIN) {
	o := c.opts
	c.proc.setIIN(iin)
	// With secure authentication, IIN1.7 newly set calls for a session key
	// change (IEEE 1815-2012 clause 7.5.4.2): the first step of the
	// restart procedure, not a task of its own, so that the keys are set
	// before IIN1.7 is cleared (clause 5.1.1.1.2 Rule 2).
	rekey := c.restartRekey(iin)
	c.needTime.Store(iin.Has(app.IINNeedTime))
	if iin.Has(app.IINDeviceRestart) && c.hasRestartSteps() {
		// IEEE 1815-2012 clause 5.1.1.1.2 Rule 2 and Table 6-3 rows 4 and
		// 8. A detection while the procedure is queued is answered by it:
		// it works from the latest one.
		c.proc.restarted(rekey, c.currentKey())
		c.enqueue(task{name: "restart", run: c.restartProcedure})
	}
	if iin.Has(app.IINNeedTime) {
		// IEEE 1815-2012 clauses 4.5.5 and 10.3.3: promptly.
		c.enqueue(task{name: "time-sync", run: func(ctx context.Context) error {
			// The startup sequence or the restart procedure may have
			// synchronized it since.
			if !c.needTime.Load() {
				return nil
			}
			return c.autoSyncTime(ctx)
		}})
	}
	if o.autoIntegrity && iin.Has(app.IINEventBufferOverflow) {
		c.enqueueIntegrity()
	}
	if o.autoEventPoll && iin&app.IINClassEvents != 0 {
		var classes []int
		for cl, bit := range map[int]app.IIN{1: app.IINClass1Events, 2: app.IINClass2Events, 3: app.IINClass3Events} {
			if iin.Has(bit) {
				classes = append(classes, cl)
			}
		}
		c.enqueue(task{name: "event-poll", run: func(ctx context.Context) error {
			_, err := c.EventPoll(ctx, classes...)
			return err
		}})
	}
}

// runStartup runs the startup sequence of WithStartup, the master startup
// of IEEE 1815-2012 clause 5.1.1.2 Rule 1 after the session key change of
// connect: DISABLE_UNSOLICITED, the optional steps, the integrity poll and
// ENABLE_UNSOLICITED, in that order. An outstation that rejects a step (an
// IINError: one without unsolicited responses answers DISABLE_UNSOLICITED
// with IIN2.0, for one) is logged and the sequence goes on; only a step
// that gets no valid response fails it.
//
// When a response so far reported a restart (IIN1.7), the indication is
// cleared before the other steps (clause 5.1.1.1.2 Rule 2 and the NOTE of
// clause 4.5.8). When the outstation needs the time and automatic time
// sync is on, the time is synchronized before the integrity poll, so that
// its events carry synchronized time.
func (c *Client) runStartup(ctx context.Context) error {
	s := c.opts.startup
	if s.DisableUnsolicited {
		if err := c.startupStep("disable unsolicited", c.DisableUnsolicited(ctx)); err != nil {
			return err
		}
	}
	if c.opts.autoClearRestart && c.proc.lastIIN().Has(app.IINDeviceRestart) {
		if err := c.startupStep("clear restart", c.ClearRestart(ctx)); err != nil {
			return err
		}
	}
	if s.Integrity {
		if c.needTime.Load() {
			if err := c.startupStep("time sync", c.autoSyncTime(ctx)); err != nil {
				return err
			}
		}
		_, err := c.IntegrityPoll(ctx)
		if err := c.startupStep("integrity poll", err); err != nil {
			return err
		}
	}
	if len(s.EnableUnsolicited) > 0 {
		if err := c.startupStep("enable unsolicited", c.EnableUnsolicited(ctx, s.EnableUnsolicited...)); err != nil {
			return err
		}
		c.proc.setEnabled()
	}
	return nil
}

// startupStep returns the error of a startup step that ends the sequence:
// an IINError is logged instead.
func (c *Client) startupStep(step string, err error) error {
	return c.procedureStep("startup", step, err)
}

// keyRetryDelay is how soon the session keys are changed again while a
// connected client has none, the first time; it doubles up to the key
// change interval.
const keyRetryDelay = time.Second

// keyRetries is how many times the session keys are changed again with
// the backoff while a connected client has none: the default threshold of
// Reply Timeouts (IEEE 1815-2012 Table 7-6 #3). After that the client
// waits the key change interval (Table 7-13, Max Reply Timeouts
// Exceeded).
const keyRetries = 3

// keyRetryIdle is the wait between key change attempts without session
// keys once the retries are spent, when the key change interval is
// disabled (WithKeyChangeInterval(0)).
const keyRetryIdle = 15 * time.Minute

// keyChangeLoop changes the session keys at the key change interval
// (IEEE 1815-2012 clause 7.6.1.4.3), when rekeySoon asks (the key change
// count, an outstation restart, an authentication failure), and sooner
// while connected without session keys: after a key change that failed,
// keyRetries times with a backoff, then at the interval.
func (c *Client) keyChangeLoop(stop <-chan struct{}) {
	interval := c.opts.keyChange
	period := interval
	if period == 0 {
		period = keyRetryIdle
	}
	retry, retries := keyRetryDelay, 0
	t := time.NewTimer(period)
	defer t.Stop()
	for {
		timeout := false
		select {
		case <-stop:
			return
		case <-c.rekey:
		case <-t.C:
			timeout = true
		}
		keys := c.controlKey() != nil
		switch {
		case timeout && interval == 0 && keys:
			// No key change interval: only the count changes the keys.
		case timeout:
			c.keyChangeTimeout()
			fallthrough
		default:
			c.enqueue(task{name: "key-change", run: c.changeSessionKeys})
		}
		wait := period
		switch {
		case keys:
			retry, retries = keyRetryDelay, 0
		case c.State() == dnp3.StateConnected && retries < keyRetries:
			wait = min(retry, period)
			retry = min(2*retry, period)
			retries++
		default:
		}
		// Since Go 1.23 Reset discards a value the timer may have sent.
		t.Reset(wait)
	}
}

// rekeySoon asks the key change loop for a session key change now.
func (c *Client) rekeySoon() {
	select {
	case c.rekey <- struct{}{}:
	default:
	}
}

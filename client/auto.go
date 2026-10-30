// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
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
		polls.Add(1)
		go func() {
			defer polls.Done()
			c.pollLoop(i, p, stop)
		}()
	}
	if u := c.opts.auth; u != nil && len(u.UpdateKey) > 0 {
		polls.Add(1)
		go func() {
			defer polls.Done()
			c.keyChangeLoop(stop)
		}()
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
	if iin.Has(app.IINDeviceRestart) && o.autoClearRestart {
		c.enqueue(task{name: "clear-restart", run: c.ClearRestart})
	}
	c.needTime.Store(iin.Has(app.IINNeedTime))
	// Time first, so that the integrity poll's events carry synchronized
	// time.
	if iin.Has(app.IINNeedTime) && o.timeSync != TimeSyncNone {
		c.enqueue(task{name: "time-sync", run: func(ctx context.Context) error {
			// The startup sequence may have synchronized it since.
			if !c.needTime.Load() {
				return nil
			}
			return c.SyncTime(ctx, o.timeSync)
		}})
	}
	if o.autoIntegrity && (iin.Has(app.IINDeviceRestart) || iin.Has(app.IINEventBufferOverflow)) {
		queued := time.Now()
		c.enqueue(task{name: "integrity", run: func(ctx context.Context) error {
			// An integrity poll that completed since, by the startup
			// sequence or the application, already did what this one would.
			if c.integritySince(queued) {
				return nil
			}
			_, err := c.IntegrityPoll(ctx)
			return err
		}})
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

// runStartup runs the startup sequence of WithStartup. An outstation that
// rejects a step (an IINError: one without unsolicited responses answers
// DISABLE_UNSOLICITED with IIN2.0, for one) is logged and the sequence goes
// on; only a step that gets no valid response fails it. When the outstation
// needs the time and automatic time sync is on, the time is synchronized
// before the integrity poll, so that its events carry synchronized time.
func (c *Client) runStartup(ctx context.Context) error {
	s := c.opts.startup
	if s.DisableUnsolicited {
		if err := c.startupStep("disable unsolicited", c.DisableUnsolicited(ctx)); err != nil {
			return err
		}
	}
	if s.Integrity {
		if c.needTime.Load() && c.opts.timeSync != TimeSyncNone {
			if err := c.startupStep("time sync", c.SyncTime(ctx, c.opts.timeSync)); err != nil {
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
	}
	return nil
}

// startupStep returns the error of a startup step that ends the sequence:
// an IINError is logged instead.
func (c *Client) startupStep(step string, err error) error {
	var ie *dnp3.IINError
	if errors.As(err, &ie) {
		c.log.Warn("startup step rejected", "step", step, "error", err)
		return nil
	}
	return err
}

// keyRetryDelay is how soon the session keys are changed again while a
// connected client has none, the first time; it doubles up to the key
// change interval.
const keyRetryDelay = time.Second

// keyChangeLoop changes the session keys at the key change interval, and
// sooner while connected without session keys: after a key change that
// failed, with a backoff.
func (c *Client) keyChangeLoop(stop <-chan struct{}) {
	retry := keyRetryDelay
	t := time.NewTimer(c.opts.keyChange)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-c.rekey:
		case <-t.C:
		}
		c.enqueue(task{name: "key-change", run: c.changeSessionKeys})
		wait := c.opts.keyChange
		if c.State() == dnp3.StateConnected && c.controlKey() == nil {
			wait = min(retry, wait)
			retry = min(2*retry, c.opts.keyChange)
		} else {
			retry = keyRetryDelay
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

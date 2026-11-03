// SPDX-License-Identifier: MIT

package client

import (
	"errors"
	"sync"
	"testing"

	"github.com/otfabric/go-dnp3"
)

// A request turned away reported the queue length after releasing the lock,
// while another request left the queue: the race detector stopped TestChaos.
func TestAcquireBusyDoesNotRace(t *testing.T) {
	c := &Client{turn: make(chan struct{}, 1), closeCh: make(chan struct{})}
	c.opts.queueLimit = 1
	ctx := t.Context()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 2000 {
				switch err := c.acquire(ctx); {
				case err == nil:
					c.release()
				case !errors.Is(err, dnp3.ErrBusy):
					t.Errorf("acquire: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

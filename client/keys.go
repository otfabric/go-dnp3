// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// keyStatusWithMAC selects the form of the key status message in the key
// change data: the g120v5 object as received, with or without its MAC
// value. Without it is what every known outstation accepts: the DSC
// go-dnp3 outstation compares the message without the MAC and refuses
// the other form, which matters from the second key change of a session on (the
// first key status carries no MAC); opendnp3 and this library's
// outstation accept both.
const keyStatusWithMAC = false

// controlKey returns a copy of the key challenge replies are computed
// with, nil while there is none: a session key change clears the session
// key it replaces, which must not change a MAC being computed with it.
// The caller clears the copy after use.
func (c *Client) controlKey() []byte {
	u := c.opts.auth
	if len(u.UpdateKey) == 0 {
		return slices.Clone(u.Key)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.auth.sessionKey)
}

// hasControlKey reports whether there is a key challenge replies are
// computed with.
func (c *Client) hasControlKey() bool {
	u := c.opts.auth
	if len(u.UpdateKey) == 0 {
		return u.Key != nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.auth.sessionKey != nil
}

// changeSessionKeys runs the session key change procedure (IEEE 1815-2012
// clauses 7.5.4.2 and 7.5.5.3, A.45.4-A.45.6) when an update key is
// configured: request the key status, check it (checkKeyStatus), wrap
// fresh control and monitoring direction session keys with the update key
// together with that key status message, send them, and check the
// outstation's confirmation, a MAC over the key change with the new
// monitoring key. Failures count in the security statistics (Table 7-13).
func (c *Client) changeSessionKeys(ctx context.Context) error {
	u := c.opts.auth
	if u == nil || len(u.UpdateKey) == 0 {
		return nil
	}
	err := c.do(ctx, app.FuncAuthRequest, true, func(ctx context.Context) error {
		res, err := c.exchange(ctx, app.FuncAuthRequest, []app.Header{
			app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: u.Number})})
		if err != nil {
			return err
		}
		st, err := keyStatus(res)
		if err != nil {
			return err
		}
		if err := c.checkKeyStatus(st); err != nil {
			return err
		}
		wrapped, control, monitoring, err := wrapSessionKeys(*u, st, keyStatusWithMAC)
		if err != nil {
			return err
		}
		res, err = c.exchange(ctx, app.FuncAuthRequest, []app.Header{
			app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: u.Number, WrappedKeys: wrapped})})
		if err == nil {
			var done app.AuthSessionKeyStatus
			if done, err = keyStatus(res); err == nil {
				// The confirmation's MAC algorithm is the outstation's
				// choice, within those this client accepts.
				want, merr := secauth.MAC(done.MAC, monitoring, res.request)
				if merr == nil && !c.acceptsKeyStatusMAC(done.MAC) {
					merr = fmt.Errorf("%s not among the accepted MAC algorithms", done.MAC)
				}
				if merr != nil || done.Status != app.KeyStatusOK || !secauth.Equal(want, done.MACValue) {
					if done.Status == app.KeyStatusOK {
						c.count(secauth.StatAuthenticationFailures)
					}
					err = fmt.Errorf("%w: the outstation did not confirm the session key change (status %s)", dnp3.ErrAuthentication, done.Status)
				}
			}
		}
		if err != nil {
			clear(control)
			clear(monitoring)
			return err
		}
		c.keysChanged(control, monitoring, res.request)
		c.log.Info("session keys changed", "user", u.Number)
		return nil
	})
	if err != nil {
		c.mu.Lock()
		c.countLocked(secauth.StatFailedSessionKeyChanges)
		// A key change the key change count asked for is asked for again
		// with the next authentication message.
		c.auth.countAsked = false
		if errors.Is(err, dnp3.ErrTimeout) {
			c.countLocked(secauth.StatReplyTimeouts)
		}
		c.mu.Unlock()
	}
	return err
}

// wrapSessionKeys generates fresh control and monitoring direction session
// keys and wraps them with the user's update key, together with the key
// status message st: the g120v5 object as it was received, with its MAC
// value when withMAC is set.
func wrapSessionKeys(u secauth.User, st app.AuthSessionKeyStatus, withMAC bool) (wrapped, control, monitoring []byte, err error) {
	if !withMAC {
		st.MACValue = nil
	}
	msg, err := app.AppendObjectValue(nil, app.G120V5, st)
	if err != nil {
		return nil, nil, nil, err
	}
	keys := make([]byte, 2*u.SessionKeyLen())
	_, _ = rand.Read(keys) // never fails (crypto/rand, Go 1.24)
	control, monitoring = keys[:u.SessionKeyLen()], keys[u.SessionKeyLen():]
	plain, err := secauth.KeyChangeData(control, monitoring, msg)
	if err == nil {
		wrapped, err = secauth.KeyWrap(u.UpdateKey, plain)
		clear(plain)
	}
	if err != nil {
		clear(keys)
		return nil, nil, nil, err
	}
	return wrapped, control, monitoring, nil
}

// keyStatus returns the session key status object of a response.
func keyStatus(res *Result) (app.AuthSessionKeyStatus, error) {
	for _, h := range res.Headers() {
		for _, o := range h.Objects {
			if st, ok := o.Value.(app.AuthSessionKeyStatus); ok {
				return st, nil
			}
		}
	}
	return app.AuthSessionKeyStatus{}, fmt.Errorf("%w: no session key status in the response", dnp3.ErrProtocol)
}

// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/rand"
	"fmt"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/secauth"
)

// keyStatusWithMAC selects the form of the key status message in the key
// change data: the g120v5 object as received, with its MAC value. DSC
// Systems go-dnp3 leaves the MAC out; outstations of this library accept
// both forms.
const keyStatusWithMAC = true

// controlKey returns the key challenge replies are computed with.
func (c *Client) controlKey() []byte {
	u := c.opts.auth
	if len(u.UpdateKey) == 0 {
		return u.Key
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionKey
}

// changeSessionKeys runs the session key change procedure (IEEE 1815-2012
// clause 7.5.2.3) when an update key is configured: request the key status,
// wrap fresh control and monitoring direction session keys with the update
// key together with that key status message, send them, and check the
// outstation's confirmation, a MAC over the key change with the new
// monitoring key.
func (c *Client) changeSessionKeys(ctx context.Context) error {
	u := c.opts.auth
	if u == nil || len(u.UpdateKey) == 0 {
		return nil
	}
	return c.do(ctx, app.FuncAuthRequest, true, func(ctx context.Context) error {
		res, err := c.exchange(ctx, app.FuncAuthRequest, []app.Header{
			app.Counted(app.G120V4, app.AuthSessionKeyStatusRequest{User: u.Number})})
		if err != nil {
			return err
		}
		st, err := keyStatus(res)
		if err != nil {
			return err
		}
		form := st
		if !keyStatusWithMAC {
			form.MACValue = nil
		}
		msg, err := app.AppendObjectValue(nil, app.G120V5, form)
		if err != nil {
			return err
		}
		control, monitoring := make([]byte, u.SessionKeyLen()), make([]byte, u.SessionKeyLen())
		if _, err := rand.Read(control); err != nil {
			return err
		}
		if _, err := rand.Read(monitoring); err != nil {
			return err
		}
		plain, err := secauth.KeyChangeData(control, monitoring, msg)
		if err != nil {
			return err
		}
		wrapped, err := secauth.KeyWrap(u.UpdateKey, plain)
		clear(plain)
		if err != nil {
			return err
		}
		res, err = c.exchange(ctx, app.FuncAuthRequest, []app.Header{
			app.FreeFormat(app.G120V6, app.AuthSessionKeyChange{KSQ: st.KSQ, User: u.Number, WrappedKeys: wrapped})})
		if err != nil {
			return err
		}
		done, err := keyStatus(res)
		if err != nil {
			return err
		}
		want, err := secauth.MAC(done.MAC, monitoring, res.request)
		if err != nil || done.Status != app.KeyStatusOK || !secauth.Equal(want, done.MACValue) {
			return fmt.Errorf("%w: the outstation did not confirm the session key change (status %s)", dnp3.ErrAuthentication, done.Status)
		}
		c.mu.Lock()
		clear(c.sessionKey)
		c.sessionKey = control
		c.mu.Unlock()
		clear(monitoring)
		c.log.Info("session keys changed", "user", u.Number)
		return nil
	})
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

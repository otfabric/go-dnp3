// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/internal/channel"
	"github.com/otfabric/go-dnp3/secauth"
)

// onAuthResponse handles an AUTHENTICATE_RESP received while a request
// waits. For a challenge it sends the reply and returns the sequence
// number the response to the critical request will carry: the reply keeps
// the sequence number of the challenge, which is that of the critical
// request (IEEE 1815-2012 clause 7.4). An
// authentication error fails the request. For other authentication objects
// it returns -1: the fragment is the response itself.
func (c *Client) onAuthResponse(ctx context.Context, sess *channel.Session, f *app.Fragment, raw, critical []byte) (int, error) {
	for _, h := range f.Headers {
		for _, o := range h.Objects {
			switch v := o.Value.(type) {
			case app.AuthError:
				return 0, &dnp3.AuthError{Code: v.Code, User: v.User, Text: string(v.Text)}
			case app.AuthChallenge:
				u := c.opts.auth
				if u == nil {
					return 0, fmt.Errorf("%w: challenged without secure authentication configured", dnp3.ErrAuthentication)
				}
				if v.MAC != u.Algorithm() {
					return 0, fmt.Errorf("%w: challenge asks for %s, configured %s", dnp3.ErrAuthentication, v.MAC, u.Algorithm())
				}
				key := c.controlKey()
				if key == nil {
					return 0, fmt.Errorf("%w: challenged before the session keys were changed", dnp3.ErrAuthentication)
				}
				mac, err := secauth.MAC(v.MAC, key, secauth.AuthData(raw, critical))
				if err != nil {
					return 0, fmt.Errorf("%w: %w", dnp3.ErrAuthentication, err)
				}
				seq := f.Control.Seq
				reply := &app.Fragment{Control: app.SingleControl(seq), Function: app.FuncAuthRequest,
					Headers: []app.Header{app.FreeFormat(app.G120V2, app.AuthReply{CSQ: v.CSQ, User: u.Number, MAC: mac})}}
				data, err := reply.Encode()
				if err != nil {
					return 0, err
				}
				if err := sess.Send(ctx, data); err != nil {
					return 0, sendError(err)
				}
				if m := c.opts.metrics; m != nil {
					m.OnFragmentSent(c.remoteAddr(), reply, len(data))
				}
				c.log.DebugContext(ctx, "challenge answered", "csq", v.CSQ, "user", u.Number)
				return int(seq), nil
			}
		}
	}
	return -1, nil
}

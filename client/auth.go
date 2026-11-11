// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"
	"slices"

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
				// The challenge (g120v1, IEEE 1815-2012 clause 7) names
				// the MAC algorithm of the reply: the outstation's choice,
				// within the algorithms this client accepts.
				if !c.acceptsMAC(v.MAC) {
					return 0, fmt.Errorf("%w: challenge asks for %s, not among the accepted MAC algorithms", dnp3.ErrAuthentication, v.MAC)
				}
				key := c.controlKey()
				if key == nil {
					return 0, fmt.Errorf("%w: challenged before the session keys were changed", dnp3.ErrAuthentication)
				}
				mac, err := secauth.MAC(v.MAC, key, secauth.AuthData(raw, critical))
				if err != nil {
					return 0, fmt.Errorf("%w: %w", dnp3.ErrAuthentication, err)
				}
				c.mu.Lock()
				c.lastChallenge, c.lastMAC, c.csq = append([]byte(nil), raw...), v.MAC, v.CSQ
				c.mu.Unlock()
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

// aggressive turns req into an aggressive mode request when its function
// is configured for it and a challenge was received on this channel: a
// g120v3 object first and a g120v9 MAC over the last challenge and the
// request last.
func (c *Client) aggressive(req *app.Fragment) error {
	u := c.opts.auth
	if u == nil || !slices.Contains(c.opts.aggressive, req.Function) {
		return nil
	}
	c.mu.Lock()
	last, alg, csq := c.lastChallenge, c.lastMAC, c.csq
	c.mu.Unlock()
	key := c.controlKey()
	if last == nil || key == nil {
		return nil
	}
	req.Headers = append([]app.Header{app.Counted(app.G120V3, app.AuthAggressiveMode{CSQ: csq + 1, User: u.Number})}, req.Headers...)
	b, err := req.Encode()
	if err != nil {
		return err
	}
	// The MAC covers the last challenge and uses its algorithm, which
	// onAuthResponse accepted: MAC cannot fail.
	mac, _ := secauth.MAC(alg, key, secauth.AuthData(last, b))
	req.Headers = append(req.Headers, app.FreeFormat(app.G120V9, app.AuthMAC{MAC: mac}))
	c.mu.Lock()
	c.csq = csq + 1
	c.mu.Unlock()
	return nil
}

// acceptsMAC reports whether a challenge may ask for the MAC algorithm alg:
// one of WithChallengeMACs, or by default any algorithm secauth computes
// except the obsolete HMAC-SHA-1 truncated to 4 octets.
func (c *Client) acceptsMAC(alg app.MACAlgorithm) bool {
	if c.opts.challengeMACs != nil {
		return slices.Contains(c.opts.challengeMACs, alg)
	}
	if alg == app.MACHMACSHA1Trunc4 {
		return false
	}
	_, err := secauth.MAC(alg, []byte{0}, nil)
	return err == nil
}

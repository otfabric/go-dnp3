// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net"
)

// errNoConn is the error of a dial whose dialer returned neither a
// connection nor an error.
var errNoConn = errors.New("dialer returned neither a connection nor an error")

// dialConn dials with d and holds it to the contract of net.Dialer: a
// connection exactly when the error is nil. A connection returned
// together with an error is closed; one returned with neither fails the
// dial with errNoConn. The caller wraps the error with its operation
// (dnp3.ErrConnectFailed). The dialer's context carries the dial timeout
// (dialTimeout, 10 s) besides the caller's deadline and cancel.
func dialConn(ctx context.Context, d Dialer, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, network, addr)
	switch {
	case err != nil:
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	case conn == nil:
		return nil, errNoConn
	}
	return conn, nil
}

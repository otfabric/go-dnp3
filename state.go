// SPDX-License-Identifier: MIT

package dnp3

// State is the state of a channel as seen by one station.
type State uint8

// Channel states.
const (
	// StateDisconnected means there is no transport connection.
	StateDisconnected State = iota
	// StateConnecting means the client is establishing or re-establishing
	// the transport connection.
	StateConnecting
	// StateConnected means the transport is open and frames flow.
	StateConnected
)

// String returns "disconnected", "connecting" or "connected".
func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	default:
		return "unknown"
	}
}

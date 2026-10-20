// SPDX-License-Identifier: MIT

// Package link is the DNP3 data link layer codec (IEEE 1815-2012 clause 9):
// the FT3 frame format with its 16-bit CRCs, the control octet, the
// function codes and the addresses, and a [Reader] that reads frames from a
// byte stream and resynchronises after damage.
//
// The package is a pure codec. The link layer procedures (reset of link
// states, confirmed user data with the frame count bit, link status
// keep-alive) run in the channel used by the client and the server.
//
// It imports nothing outside the standard library and is useful on its own
// to analysers and test tools.
package link

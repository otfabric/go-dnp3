// SPDX-License-Identifier: MIT

// Package secauth implements the cryptographic core of DNP3 Secure
// Authentication version 5 (IEEE 1815-2012 clause 7): the message
// authentication codes and the construction of the data they protect.
//
// The challenge-reply procedure that uses it is wired into the client and
// the server through their WithSecureAuthentication option. This package
// supports pre-shared session keys and HMAC with SHA-256 (the algorithm
// every SAv5 device must implement) and SHA-1; the session key change and
// update key change procedures of clause 7.6 are not implemented, so keys
// are configured on both ends out of band.
package secauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"

	"github.com/otfabric/go-dnp3/app"
)

// MAC computes the message authentication code of data under key for the
// algorithm alg, truncated to the algorithm's length. It returns an error
// for an algorithm this package does not implement.
func MAC(alg app.MACAlgorithm, key, data []byte) ([]byte, error) {
	var h func() hash.Hash
	switch alg {
	case app.MACHMACSHA1Trunc4, app.MACHMACSHA1Trunc10, app.MACHMACSHA1Trunc8:
		h = sha1.New
	case app.MACHMACSHA256Trunc8, app.MACHMACSHA256Trunc16:
		h = sha256.New
	default:
		return nil, fmt.Errorf("secauth: unsupported MAC algorithm %s", alg)
	}
	mac := hmac.New(h, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	n := alg.Len()
	if n > len(sum) {
		n = len(sum)
	}
	return sum[:n], nil
}

// Equal reports whether the two MACs are equal, in constant time.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// AuthData is the data a challenge reply authenticates (IEEE 1815-2012
// clause 7.5.2.1): the full challenge object as it was sent, followed by
// the critical application fragment that was challenged.
//
// Both stations build it the same way, so the master's reply MAC and the
// outstation's verification MAC match when the key matches.
func AuthData(challenge, criticalFragment []byte) []byte {
	out := make([]byte, 0, len(challenge)+len(criticalFragment))
	out = append(out, challenge...)
	return append(out, criticalFragment...)
}

// User holds the keys and identity of one SAv5 user. In pre-shared mode
// the control-direction session key is used for both challenge and reply.
type User struct {
	// Number is the user number; 1 is the default user.
	Number uint16
	// Key is the pre-shared control-direction session key (16 or 32
	// octets for AES key wrap, but any length works for HMAC).
	Key []byte
	// MAC is the algorithm; zero selects HMAC-SHA-256 truncated to 16.
	MAC app.MACAlgorithm
}

// Algorithm returns the user's MAC algorithm, defaulting to
// HMAC-SHA-256-16.
func (u User) Algorithm() app.MACAlgorithm {
	if u.MAC == app.MACNone {
		return app.MACHMACSHA256Trunc16
	}
	return u.MAC
}

// Validate checks that the user can be used.
func (u User) Validate() error {
	if len(u.Key) == 0 {
		return fmt.Errorf("secauth: user %d has no key", u.Number)
	}
	if u.Algorithm().Len() == 0 {
		return fmt.Errorf("secauth: user %d has unsupported MAC algorithm %s", u.Number, u.Algorithm())
	}
	return nil
}

// SPDX-License-Identifier: MIT

// Package secauth implements the cryptographic core of DNP3 Secure
// Authentication version 5 (IEEE 1815-2012 clause 7): the message
// authentication codes and the construction of the data they protect.
//
// The procedures that use it are wired into the client and the server
// through their WithSecureAuthentication option: the challenge of critical
// requests ([DefaultCritical] by default), aggressive mode
// ([AggressiveOverhead] is what it adds to a request), the session key
// change and the security statistics ([Statistic]), with HMAC-SHA-256
// (which every SAv5 device must implement) or HMAC-SHA-1, and AES-128 or
// AES-256 key wrap (RFC 3394). Update keys are configured on both ends out
// of band: the update key change and user management procedures, and
// AES-GMAC, are not implemented.
package secauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"log/slog"

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

// User holds the keys and identity of one SAv5 user.
//
// With an UpdateKey the session keys are negotiated by the session key
// change procedure: the master wraps fresh keys with the update key on
// every connection and at the key change interval. Without one, Key is a
// pre-shared control direction session key used directly.
type User struct {
	// Number is the user number; 1 is the default user.
	Number uint16
	// UpdateKey is the update key: 16 octets (AES-128 key wrap) or 32
	// octets (AES-256).
	UpdateKey []byte
	// Key is a pre-shared control direction session key, used when there
	// is no UpdateKey.
	Key []byte
	// MAC is the algorithm; zero selects HMAC-SHA-256 truncated to 16.
	MAC app.MACAlgorithm
}

// String formats the user without its keys, so that printing options or
// a configuration does not reveal them.
func (u User) String() string {
	return fmt.Sprintf("{Number:%d UpdateKey:%s Key:%s MAC:%v}", u.Number, redactKey(u.UpdateKey), redactKey(u.Key), u.MAC)
}

// GoString is String, for %#v.
func (u User) GoString() string { return "secauth.User" + u.String() }

// LogValue logs the user number and key lengths, for log/slog.
func (u User) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("number", int(u.Number)),
		slog.String("update_key", redactKey(u.UpdateKey)), slog.String("key", redactKey(u.Key)))
}

// redactKey stands for a key in formatted output: its length only.
func redactKey(k []byte) string {
	if len(k) == 0 {
		return "[none]"
	}
	return fmt.Sprintf("[REDACTED %d octets]", len(k))
}

// KeyWrapAlgorithm returns the key wrap algorithm of the update key.
func (u User) KeyWrapAlgorithm() app.KeyWrap {
	if len(u.UpdateKey) == 32 {
		return app.KeyWrapAES256
	}
	return app.KeyWrapAES128
}

// SessionKeyLen returns the length of the session keys the master
// generates: that of the update key.
func (u User) SessionKeyLen() int {
	if len(u.UpdateKey) == 32 {
		return 32
	}
	return 16
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
	switch {
	case len(u.UpdateKey) != 0 && len(u.UpdateKey) != 16 && len(u.UpdateKey) != 32:
		return fmt.Errorf("secauth: user %d: update key of %d octets, need 16 or 32", u.Number, len(u.UpdateKey))
	case len(u.UpdateKey) == 0 && len(u.Key) == 0:
		return fmt.Errorf("secauth: user %d has no update key and no session key", u.Number)
	}
	if _, err := MAC(u.Algorithm(), []byte{0}, nil); err != nil {
		return fmt.Errorf("secauth: user %d: unsupported MAC algorithm %s", u.Number, u.Algorithm())
	}
	return nil
}

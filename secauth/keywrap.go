// SPDX-License-Identifier: MIT

package secauth

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrKeyWrap reports wrapped key data that does not unwrap: a wrong key,
// damaged data, or data whose integrity check fails.
var ErrKeyWrap = errors.New("secauth: key unwrap failed")

// defaultIV is the initial value of RFC 3394, section 2.2.3.1.
var defaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// KeyWrap wraps plaintext with the AES key wrap algorithm of RFC 3394
// under kek (16 or 32 octets). plaintext must be a multiple of 8 octets and
// at least 16.
func KeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("secauth: key wrap of %d octets: need a multiple of 8, at least 16", len(plaintext))
	}
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("secauth: key wrap: %w", err)
	}
	n := len(plaintext) / 8
	out := make([]byte, 8+len(plaintext))
	copy(out, defaultIV[:])
	copy(out[8:], plaintext)
	var b [16]byte
	for j := range 6 {
		for i := 1; i <= n; i++ {
			copy(b[:8], out[:8])
			copy(b[8:], out[8*i:8*i+8])
			c.Encrypt(b[:], b[:])
			binary.BigEndian.PutUint64(out[:8], binary.BigEndian.Uint64(b[:8])^uint64(n*j+i))
			copy(out[8*i:], b[8:])
		}
	}
	return out, nil
}

// KeyUnwrap reverses KeyWrap and checks the integrity value. A wrong key
// or damaged data fails with ErrKeyWrap.
func KeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("%w: %d octets", ErrKeyWrap, len(wrapped))
	}
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("secauth: key unwrap: %w", err)
	}
	n := len(wrapped)/8 - 1
	out := append([]byte(nil), wrapped...)
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(out[:8])^uint64(n*j+i))
			copy(b[8:], out[8*i:8*i+8])
			c.Decrypt(b[:], b[:])
			copy(out[:8], b[:8])
			copy(out[8*i:], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(out[:8], defaultIV[:]) != 1 {
		clear(out)
		return nil, ErrKeyWrap
	}
	return out[8:], nil
}

// KeyChangeData is the plaintext of a session key change (g120v6, IEEE
// 1815-2012 clause 7.5.2.3): the length of a session key, the control
// direction and the monitoring direction session keys, and the key status
// message the outstation sent last, padded with zeros to a multiple of 8
// octets for the key wrap.
func KeyChangeData(control, monitoring, keyStatus []byte) ([]byte, error) {
	if len(control) != len(monitoring) || len(control) < 16 || len(control) > 64 {
		return nil, fmt.Errorf("secauth: session keys of %d and %d octets: need equal lengths of 16..64", len(control), len(monitoring))
	}
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(control)))
	b = append(b, control...)
	b = append(b, monitoring...)
	b = append(b, keyStatus...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b, nil
}

// ParseKeyChangeData returns the session keys of unwrapped key change
// data, after checking that it carries one of the given key status
// messages followed only by padding. Several forms are accepted because
// implementations differ in whether the key status message includes its
// MAC value.
func ParseKeyChangeData(plain []byte, keyStatus ...[]byte) (control, monitoring []byte, err error) {
	if len(plain) < 2 {
		return nil, nil, ErrKeyWrap
	}
	n := int(binary.LittleEndian.Uint16(plain))
	end := 2 + 2*n
	if n < 16 || n > 64 || end > len(plain) {
		return nil, nil, fmt.Errorf("%w: session key length %d", ErrKeyWrap, n)
	}
	rest := plain[end:]
	for _, ks := range keyStatus {
		if len(rest) < len(ks) || len(rest)-len(ks) > 7 {
			continue
		}
		if subtle.ConstantTimeCompare(rest[:len(ks)], ks) != 1 {
			continue
		}
		pad := rest[len(ks):]
		zero := true
		for _, x := range pad {
			zero = zero && x == 0
		}
		if !zero {
			continue
		}
		return append([]byte(nil), plain[2:2+n]...), append([]byte(nil), plain[2+n:end]...), nil
	}
	return nil, nil, fmt.Errorf("%w: the key status message does not match the last one sent", ErrKeyWrap)
}

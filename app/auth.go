// SPDX-License-Identifier: MIT

package app

import "fmt"

// The objects of DNP3 Secure Authentication version 5 (group 120,
// IEEE 1815-2012 clause 7 and A.45). The procedures that use them are in
// package secauth; this file is their wire format only.

// MACAlgorithm identifies the MAC algorithm and the length of the MAC.
type MACAlgorithm uint8

// MAC algorithms (IEEE 1815-2012 Table A-12).
const (
	MACNone              MACAlgorithm = 0
	MACHMACSHA1Trunc4    MACAlgorithm = 1 // obsolete
	MACHMACSHA1Trunc10   MACAlgorithm = 2
	MACHMACSHA256Trunc8  MACAlgorithm = 3
	MACHMACSHA256Trunc16 MACAlgorithm = 4
	MACHMACSHA1Trunc8    MACAlgorithm = 5
	MACAESGMAC           MACAlgorithm = 6
)

// Len returns the length of the MAC in octets, or 0 for an unknown
// algorithm.
func (m MACAlgorithm) Len() int {
	switch m {
	case MACHMACSHA1Trunc4:
		return 4
	case MACHMACSHA1Trunc10:
		return 10
	case MACHMACSHA256Trunc8, MACHMACSHA1Trunc8:
		return 8
	case MACHMACSHA256Trunc16:
		return 16
	case MACAESGMAC:
		return 12
	default:
		return 0
	}
}

// String returns, for example, "HMAC-SHA-256-16".
func (m MACAlgorithm) String() string {
	switch m {
	case MACNone:
		return "NONE"
	case MACHMACSHA1Trunc4:
		return "HMAC-SHA-1-4"
	case MACHMACSHA1Trunc10:
		return "HMAC-SHA-1-10"
	case MACHMACSHA256Trunc8:
		return "HMAC-SHA-256-8"
	case MACHMACSHA256Trunc16:
		return "HMAC-SHA-256-16"
	case MACHMACSHA1Trunc8:
		return "HMAC-SHA-1-8"
	case MACAESGMAC:
		return "AES-GMAC"
	default:
		return fmt.Sprintf("MAC(%d)", uint8(m))
	}
}

// KeyWrap identifies the algorithm that wraps session keys.
type KeyWrap uint8

// Key wrap algorithms.
const (
	KeyWrapAES128 KeyWrap = 1
	KeyWrapAES256 KeyWrap = 2
)

// KeyStatus is the status of the session keys of a user.
type KeyStatus uint8

// Key status values.
const (
	KeyStatusOK       KeyStatus = 1
	KeyStatusNotInit  KeyStatus = 2
	KeyStatusCommFail KeyStatus = 3
	KeyStatusAuthFail KeyStatus = 4
)

// String returns "OK", "NOT_INIT", "COMM_FAIL", "AUTH_FAIL" or
// "KEY_STATUS(n)".
func (k KeyStatus) String() string {
	switch k {
	case KeyStatusOK:
		return "OK"
	case KeyStatusNotInit:
		return "NOT_INIT"
	case KeyStatusCommFail:
		return "COMM_FAIL"
	case KeyStatusAuthFail:
		return "AUTH_FAIL"
	default:
		return fmt.Sprintf("KEY_STATUS(%d)", uint8(k))
	}
}

// AuthErrorCode is the error code of an authentication error object.
type AuthErrorCode uint8

// Authentication error codes (IEEE 1815-2012 Table A-14).
const (
	AuthErrAuthenticationFailed        AuthErrorCode = 1
	AuthErrAggressiveModeNotSupported  AuthErrorCode = 4
	AuthErrMACNotSupported             AuthErrorCode = 5
	AuthErrKeyWrapNotSupported         AuthErrorCode = 6
	AuthErrAuthorizationFailed         AuthErrorCode = 7
	AuthErrUpdateKeyMethodNotPermitted AuthErrorCode = 8
	AuthErrInvalidSignature            AuthErrorCode = 9
	AuthErrInvalidCertification        AuthErrorCode = 10
	AuthErrUnknownUser                 AuthErrorCode = 11
	AuthErrMaxSessionKeyStatusRequests AuthErrorCode = 12
)

// String returns the name of the code, for example
// "AUTHENTICATION_FAILED".
func (e AuthErrorCode) String() string {
	switch e {
	case AuthErrAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case AuthErrAggressiveModeNotSupported:
		return "AGGRESSIVE_MODE_NOT_SUPPORTED"
	case AuthErrMACNotSupported:
		return "MAC_NOT_SUPPORTED"
	case AuthErrKeyWrapNotSupported:
		return "KEY_WRAP_NOT_SUPPORTED"
	case AuthErrAuthorizationFailed:
		return "AUTHORIZATION_FAILED"
	case AuthErrUpdateKeyMethodNotPermitted:
		return "UPDATE_KEY_METHOD_NOT_PERMITTED"
	case AuthErrInvalidSignature:
		return "INVALID_SIGNATURE"
	case AuthErrInvalidCertification:
		return "INVALID_CERTIFICATION_DATA"
	case AuthErrUnknownUser:
		return "UNKNOWN_USER"
	case AuthErrMaxSessionKeyStatusRequests:
		return "MAX_SESSION_KEY_STATUS_REQUESTS_EXCEEDED"
	default:
		return fmt.Sprintf("AUTH_ERROR(%d)", uint8(e))
	}
}

// ChallengeReason is the reason code of a challenge.
type ChallengeReason uint8

// ReasonCritical is the only defined reason: a critical request.
const ReasonCritical ChallengeReason = 1

// AuthChallenge is g120v1.
type AuthChallenge struct {
	// CSQ is the challenge sequence number.
	CSQ uint32
	// User is the user number.
	User   uint16
	MAC    MACAlgorithm
	Reason ChallengeReason
	// Data is the pseudo-random challenge data.
	Data []byte
}

// AuthReply is g120v2.
type AuthReply struct {
	CSQ  uint32
	User uint16
	MAC  []byte
}

// AuthAggressiveMode is g120v3, the aggressive mode request that precedes
// the objects of a critical request authenticated without a challenge.
type AuthAggressiveMode struct {
	CSQ  uint32
	User uint16
}

// AuthSessionKeyStatusRequest is g120v4.
type AuthSessionKeyStatusRequest struct {
	User uint16
}

// AuthSessionKeyStatus is g120v5.
type AuthSessionKeyStatus struct {
	// KSQ is the key change sequence number.
	KSQ     uint32
	User    uint16
	KeyWrap KeyWrap
	Status  KeyStatus
	MAC     MACAlgorithm
	// Challenge is the challenge data for the next key change.
	Challenge []byte
	// MACValue is the MAC of the previous key status message; empty when
	// the keys are not initialized.
	MACValue []byte
}

// AuthSessionKeyChange is g120v6.
type AuthSessionKeyChange struct {
	KSQ  uint32
	User uint16
	// WrappedKeys is the key wrap of the control and monitoring direction
	// session keys and the key status message.
	WrappedKeys []byte
}

// AuthError is g120v7.
type AuthError struct {
	CSQ         uint32
	User        uint16
	Association uint16
	Code        AuthErrorCode
	Time        Timestamp
	Text        []byte
}

// AuthUserCertificate is g120v8.
type AuthUserCertificate struct {
	KeyChangeMethod uint8
	CertificateType uint8
	Certificate     []byte
}

// AuthMAC is g120v9, the MAC that ends an aggressive mode request.
type AuthMAC struct {
	MAC []byte
}

// AuthUserStatusChange is g120v10.
type AuthUserStatusChange struct {
	KeyChangeMethod uint8
	Operation       uint8
	SCS             uint32
	Role            uint16
	RoleExpiry      uint16
	UserName        string
	PublicKey       []byte
	Certification   []byte
}

// AuthUpdateKeyChangeRequest is g120v11.
type AuthUpdateKeyChangeRequest struct {
	KeyChangeMethod uint8
	UserName        string
	Challenge       []byte
}

// AuthUpdateKeyChangeReply is g120v12.
type AuthUpdateKeyChangeReply struct {
	KSQ       uint32
	User      uint16
	Challenge []byte
}

// AuthUpdateKeyChange is g120v13.
type AuthUpdateKeyChange struct {
	KSQ          uint32
	User         uint16
	EncryptedKey []byte
}

// AuthUpdateKeyChangeSignature is g120v14.
type AuthUpdateKeyChangeSignature struct {
	Signature []byte
}

// AuthUpdateKeyChangeConfirmation is g120v15.
type AuthUpdateKeyChangeConfirmation struct {
	MAC []byte
}

func (AuthChallenge) isValue()                   {}
func (AuthReply) isValue()                       {}
func (AuthAggressiveMode) isValue()              {}
func (AuthSessionKeyStatusRequest) isValue()     {}
func (AuthSessionKeyStatus) isValue()            {}
func (AuthSessionKeyChange) isValue()            {}
func (AuthError) isValue()                       {}
func (AuthUserCertificate) isValue()             {}
func (AuthMAC) isValue()                         {}
func (AuthUserStatusChange) isValue()            {}
func (AuthUpdateKeyChangeRequest) isValue()      {}
func (AuthUpdateKeyChangeReply) isValue()        {}
func (AuthUpdateKeyChange) isValue()             {}
func (AuthUpdateKeyChangeSignature) isValue()    {}
func (AuthUpdateKeyChangeConfirmation) isValue() {}

func decAuth(v uint8, b []byte) (Value, error) {
	r := reader{b: b}
	var out Value
	switch v {
	case 1:
		out = AuthChallenge{CSQ: r.u32(), User: r.u16(), MAC: MACAlgorithm(r.u8()), Reason: ChallengeReason(r.u8()), Data: clone(r.rest())}
	case 2:
		out = AuthReply{CSQ: r.u32(), User: r.u16(), MAC: clone(r.rest())}
	case 3:
		out = AuthAggressiveMode{CSQ: r.u32(), User: r.u16()}
	case 4:
		out = AuthSessionKeyStatusRequest{User: r.u16()}
	case 5:
		s := AuthSessionKeyStatus{KSQ: r.u32(), User: r.u16(), KeyWrap: KeyWrap(r.u8()), Status: KeyStatus(r.u8()), MAC: MACAlgorithm(r.u8())}
		s.Challenge = clone(r.bytes(int(r.u16())))
		s.MACValue = clone(r.rest())
		out = s
	case 6:
		out = AuthSessionKeyChange{KSQ: r.u32(), User: r.u16(), WrappedKeys: clone(r.rest())}
	case 7:
		out = AuthError{CSQ: r.u32(), User: r.u16(), Association: r.u16(), Code: AuthErrorCode(r.u8()), Time: r.time(), Text: clone(r.rest())}
	case 8:
		out = AuthUserCertificate{KeyChangeMethod: r.u8(), CertificateType: r.u8(), Certificate: clone(r.rest())}
	case 9:
		out = AuthMAC{MAC: clone(r.rest())}
	case 10:
		s := AuthUserStatusChange{KeyChangeMethod: r.u8(), Operation: r.u8(), SCS: r.u32(), Role: r.u16(), RoleExpiry: r.u16()}
		nu, nk, nc := r.u16(), r.u16(), r.u16()
		s.UserName = string(r.bytes(int(nu)))
		s.PublicKey = clone(r.bytes(int(nk)))
		s.Certification = clone(r.bytes(int(nc)))
		out = s
	case 11:
		s := AuthUpdateKeyChangeRequest{KeyChangeMethod: r.u8()}
		nu, nc := r.u16(), r.u16()
		s.UserName = string(r.bytes(int(nu)))
		s.Challenge = clone(r.bytes(int(nc)))
		out = s
	case 12:
		s := AuthUpdateKeyChangeReply{KSQ: r.u32(), User: r.u16()}
		s.Challenge = clone(r.bytes(int(r.u16())))
		out = s
	case 13:
		s := AuthUpdateKeyChange{KSQ: r.u32(), User: r.u16()}
		s.EncryptedKey = clone(r.bytes(int(r.u16())))
		out = s
	case 14:
		out = AuthUpdateKeyChangeSignature{Signature: clone(r.rest())}
	case 15:
		out = AuthUpdateKeyChangeConfirmation{MAC: clone(r.rest())}
	default:
		return nil, malformed("g120v%d", v)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}

func encAuth(b []byte, v Value) ([]byte, error) {
	switch o := v.(type) {
	case AuthChallenge:
		b = le32(b, o.CSQ)
		b = le16(b, o.User)
		b = append(b, byte(o.MAC), byte(o.Reason))
		return append(b, o.Data...), nil
	case AuthReply:
		b = le32(b, o.CSQ)
		b = le16(b, o.User)
		return append(b, o.MAC...), nil
	case AuthAggressiveMode:
		b = le32(b, o.CSQ)
		return le16(b, o.User), nil
	case AuthSessionKeyStatusRequest:
		return le16(b, o.User), nil
	case AuthSessionKeyStatus:
		if len(o.Challenge) > 0xFFFF {
			return b, invalid("g120v5 challenge too long")
		}
		b = le32(b, o.KSQ)
		b = le16(b, o.User)
		b = append(b, byte(o.KeyWrap), byte(o.Status), byte(o.MAC))
		b = le16(b, uint16(len(o.Challenge)))
		b = append(b, o.Challenge...)
		return append(b, o.MACValue...), nil
	case AuthSessionKeyChange:
		b = le32(b, o.KSQ)
		b = le16(b, o.User)
		return append(b, o.WrappedKeys...), nil
	case AuthError:
		b = le32(b, o.CSQ)
		b = le16(b, o.User)
		b = le16(b, o.Association)
		b = append(b, byte(o.Code))
		b = le48(b, o.Time)
		return append(b, o.Text...), nil
	case AuthUserCertificate:
		b = append(b, o.KeyChangeMethod, o.CertificateType)
		return append(b, o.Certificate...), nil
	case AuthMAC:
		return append(b, o.MAC...), nil
	case AuthUserStatusChange:
		if len(o.UserName) > 0xFFFF || len(o.PublicKey) > 0xFFFF || len(o.Certification) > 0xFFFF {
			return b, invalid("g120v10 field too long")
		}
		b = append(b, o.KeyChangeMethod, o.Operation)
		b = le32(b, o.SCS)
		b = le16(b, o.Role)
		b = le16(b, o.RoleExpiry)
		b = le16(b, uint16(len(o.UserName)))
		b = le16(b, uint16(len(o.PublicKey)))
		b = le16(b, uint16(len(o.Certification)))
		b = append(b, o.UserName...)
		b = append(b, o.PublicKey...)
		return append(b, o.Certification...), nil
	case AuthUpdateKeyChangeRequest:
		if len(o.UserName) > 0xFFFF || len(o.Challenge) > 0xFFFF {
			return b, invalid("g120v11 field too long")
		}
		b = append(b, o.KeyChangeMethod)
		b = le16(b, uint16(len(o.UserName)))
		b = le16(b, uint16(len(o.Challenge)))
		b = append(b, o.UserName...)
		return append(b, o.Challenge...), nil
	case AuthUpdateKeyChangeReply:
		if len(o.Challenge) > 0xFFFF {
			return b, invalid("g120v12 challenge too long")
		}
		b = le32(b, o.KSQ)
		b = le16(b, o.User)
		b = le16(b, uint16(len(o.Challenge)))
		return append(b, o.Challenge...), nil
	case AuthUpdateKeyChange:
		if len(o.EncryptedKey) > 0xFFFF {
			return b, invalid("g120v13 key data too long")
		}
		b = le32(b, o.KSQ)
		b = le16(b, o.User)
		b = le16(b, uint16(len(o.EncryptedKey)))
		return append(b, o.EncryptedKey...), nil
	case AuthUpdateKeyChangeSignature:
		return append(b, o.Signature...), nil
	case AuthUpdateKeyChangeConfirmation:
		return append(b, o.MAC...), nil
	default:
		return b, invalid("%T is not an authentication object", v)
	}
}

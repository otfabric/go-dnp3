// SPDX-License-Identifier: MIT

package link

import "fmt"

// Function is a link layer function code together with the PRM bit (0x40),
// so that the primary and the secondary codes, which overlap numerically,
// are distinct values. It is the control octet without DIR, FCB/FCV and DFC.
type Function uint8

// Primary function codes (PRM = 1): frames that initiate a transaction.
const (
	PrimaryResetLinkStates     Function = 0x40
	PrimaryTestLinkStates      Function = 0x40 | 2
	PrimaryConfirmedUserData   Function = 0x40 | 3
	PrimaryUnconfirmedUserData Function = 0x40 | 4
	PrimaryRequestLinkStatus   Function = 0x40 | 9
)

// Secondary function codes (PRM = 0): the replies.
const (
	SecondaryAck          Function = 0
	SecondaryNack         Function = 1
	SecondaryLinkStatus   Function = 11
	SecondaryNotSupported Function = 15
)

// Primary reports whether f is a primary function code (PRM set).
func (f Function) Primary() bool { return f&0x40 != 0 }

// Code returns the four-bit function code without the PRM bit.
func (f Function) Code() uint8 { return uint8(f & 0x0F) }

// Defined reports whether IEEE 1815-2012 defines f. The obsolete primary
// code 1 (reset of user process) is not defined.
func (f Function) Defined() bool {
	switch f {
	case PrimaryResetLinkStates, PrimaryTestLinkStates, PrimaryConfirmedUserData,
		PrimaryUnconfirmedUserData, PrimaryRequestLinkStatus,
		SecondaryAck, SecondaryNack, SecondaryLinkStatus, SecondaryNotSupported:
		return true
	default:
		return false
	}
}

// HasData reports whether frames of this function carry user data.
func (f Function) HasData() bool {
	return f == PrimaryConfirmedUserData || f == PrimaryUnconfirmedUserData
}

// UsesFCB reports whether the frame count bit is valid for this function:
// the FCV bit is set on its frames.
func (f Function) UsesFCB() bool {
	return f == PrimaryTestLinkStates || f == PrimaryConfirmedUserData
}

// String returns the name of the function in the standard's notation, for
// example "RESET_LINK_STATES".
func (f Function) String() string {
	switch f {
	case PrimaryResetLinkStates:
		return "RESET_LINK_STATES"
	case PrimaryTestLinkStates:
		return "TEST_LINK_STATES"
	case PrimaryConfirmedUserData:
		return "CONFIRMED_USER_DATA"
	case PrimaryUnconfirmedUserData:
		return "UNCONFIRMED_USER_DATA"
	case PrimaryRequestLinkStatus:
		return "REQUEST_LINK_STATUS"
	case SecondaryAck:
		return "ACK"
	case SecondaryNack:
		return "NACK"
	case SecondaryLinkStatus:
		return "LINK_STATUS"
	case SecondaryNotSupported:
		return "NOT_SUPPORTED"
	default:
		if f.Primary() {
			return fmt.Sprintf("PRIMARY(%d)", f.Code())
		}
		return fmt.Sprintf("SECONDARY(%d)", f.Code())
	}
}

// Address is a link layer address. 0x0000..0xFFEF identify stations; the
// range above is reserved for the special addresses below.
type Address uint16

// Special addresses (IEEE 1815-2012 clause 9.2.5.3).
const (
	// MaxStationAddress is the largest address of an individual station.
	MaxStationAddress Address = 0xFFEF

	// SelfAddress is the self-address: an outstation that supports it
	// accepts frames sent to it as if they were sent to its own address.
	SelfAddress Address = 0xFFFC

	// BroadcastNoConfirm is the broadcast address (0xFFFD) for which the
	// outstations must not request an application confirmation.
	BroadcastNoConfirm Address = 0xFFFD

	// BroadcastConfirm is the broadcast address (0xFFFE) for which the
	// outstations must request an application confirmation.
	BroadcastConfirm Address = 0xFFFE

	// BroadcastOptionalConfirm is the broadcast address (0xFFFF) for which
	// the outstations may request an application confirmation.
	BroadcastOptionalConfirm Address = 0xFFFF
)

// Broadcast reports whether a is one of the three broadcast addresses.
func (a Address) Broadcast() bool { return a >= BroadcastNoConfirm }

// Reserved reports whether a is in the reserved range 0xFFF0..0xFFFB.
func (a Address) Reserved() bool { return a > MaxStationAddress && a < SelfAddress }

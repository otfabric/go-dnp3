// SPDX-License-Identifier: MIT

package app

import "strings"

// IIN is the internal indications field of a response (IEEE 1815-2012
// clause 4.2.2.6): IIN1 in the low octet, IIN2 in the high octet, as they
// are sent.
type IIN uint16

// IIN1 bits.
const (
	// IINBroadcast: a broadcast message was received.
	IINBroadcast IIN = 1 << iota
	// IINClass1Events: the outstation has unreported class 1 events.
	IINClass1Events
	// IINClass2Events: the outstation has unreported class 2 events.
	IINClass2Events
	// IINClass3Events: the outstation has unreported class 3 events.
	IINClass3Events
	// IINNeedTime: the outstation requires time synchronization.
	IINNeedTime
	// IINLocalControl: one or more output points are in local mode.
	IINLocalControl
	// IINDeviceTrouble: an abnormal, device specific condition exists.
	IINDeviceTrouble
	// IINDeviceRestart: the outstation restarted; cleared by the master.
	IINDeviceRestart

	// IIN2 bits.

	// IINNoFuncCodeSupport: the function code is not implemented.
	IINNoFuncCodeSupport
	// IINObjectUnknown: an object, variation or qualifier is not supported,
	// or a point does not exist.
	IINObjectUnknown
	// IINParameterError: a parameter in the request is invalid, or the
	// request could not be parsed.
	IINParameterError
	// IINEventBufferOverflow: an event buffer overflowed and events were
	// lost.
	IINEventBufferOverflow
	// IINAlreadyExecuting: the requested operation is already executing.
	IINAlreadyExecuting
	// IINConfigCorrupt: the outstation detected corrupt configuration.
	IINConfigCorrupt
	// IINReserved2 and IINReserved1 are reserved; they are sent as zero.
	IINReserved2
	IINReserved1
)

// IINClassEvents is the union of the three class event bits.
const IINClassEvents = IINClass1Events | IINClass2Events | IINClass3Events

// IINRequestErrors is the union of the IIN2 bits that report a rejected
// request.
const IINRequestErrors = IINNoFuncCodeSupport | IINObjectUnknown | IINParameterError

var iinNames = [16]string{
	"BROADCAST", "CLASS_1_EVENTS", "CLASS_2_EVENTS", "CLASS_3_EVENTS",
	"NEED_TIME", "LOCAL_CONTROL", "DEVICE_TROUBLE", "DEVICE_RESTART",
	"NO_FUNC_CODE_SUPPORT", "OBJECT_UNKNOWN", "PARAMETER_ERROR", "EVENT_BUFFER_OVERFLOW",
	"ALREADY_EXECUTING", "CONFIG_CORRUPT", "RESERVED_2", "RESERVED_1",
}

// Has reports whether every bit of bits is set.
func (i IIN) Has(bits IIN) bool { return i&bits == bits }

// IIN1 returns the first octet.
func (i IIN) IIN1() uint8 { return uint8(i) }

// IIN2 returns the second octet.
func (i IIN) IIN2() uint8 { return uint8(i >> 8) }

// String returns the names of the set bits joined by "|", or "" when none
// is set.
func (i IIN) String() string {
	var parts []string
	for b := range 16 {
		if i&(1<<b) != 0 {
			parts = append(parts, iinNames[b])
		}
	}
	return strings.Join(parts, "|")
}

// IINBit returns the index of a single IIN bit in the numbering of group
// 80 (IIN1.0 is 0, IIN2.7 is 15), the index a master writes to clear it.
func IINBit(bit IIN) uint32 {
	for b := range 16 {
		if bit == 1<<b {
			return uint32(b)
		}
	}
	return 0
}

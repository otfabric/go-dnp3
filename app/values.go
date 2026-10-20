// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"strings"
	"time"
)

// Value is one decoded object: the value of a point, a command, a time
// object, a file or authentication object.
//
// The set of implementations is closed: it is the value structs of this
// package, used by value. Several variations share a struct; the
// variation the object is sent in is that of its [Header]. Use a type
// switch to consume them:
//
//	for _, o := range h.Objects {
//		switch v := o.Value.(type) {
//		case app.Analog:
//			...
//		case app.Binary:
//			...
//		}
//	}
type Value interface {
	isValue()
}

// Flags is the quality flags octet of a point (IEEE 1815-2012
// clause 11.9.6.2).
//
// The state bits that share the octet with the flags of binary and
// double-bit points (bit 7, bits 6..7) are not part of Flags: they are the
// Value of [Binary] and [DoubleBitBinary], merged on encoding.
type Flags uint8

// Flag bits common to all point types.
const (
	// FlagOnline: the point is available and its value is valid.
	FlagOnline Flags = 0x01
	// FlagRestart: the value has not been updated since the device
	// restarted.
	FlagRestart Flags = 0x02
	// FlagCommLost: the value was obtained from a device that has lost
	// communication.
	FlagCommLost Flags = 0x04
	// FlagRemoteForced: the value is forced at a downstream device.
	FlagRemoteForced Flags = 0x08
	// FlagLocalForced: the value is forced at this device.
	FlagLocalForced Flags = 0x10
)

// Flag bits specific to some point types.
const (
	// FlagChatterFilter: binary and double-bit inputs; the input is
	// changing too fast and is filtered.
	FlagChatterFilter Flags = 0x20
	// FlagRollover: counters; obsolete, sent as zero by current devices.
	FlagRollover Flags = 0x20
	// FlagOverRange: analog inputs and outputs; the value exceeds the
	// range of the variation or of the device.
	FlagOverRange Flags = 0x20
	// FlagDiscontinuity: counters; the value cannot be compared with the
	// previous one.
	FlagDiscontinuity Flags = 0x40
	// FlagReferenceErr: analog inputs; the reference signal is in error.
	FlagReferenceErr Flags = 0x40
)

// String returns the common flags by name and the type-specific bits as
// "BIT5"/"BIT6", for example "ONLINE|BIT5".
func (f Flags) String() string {
	names := [...]string{"ONLINE", "RESTART", "COMM_LOST", "REMOTE_FORCED", "LOCAL_FORCED", "BIT5", "BIT6", "BIT7"}
	var parts []string
	for b := range 8 {
		if f&(1<<b) != 0 {
			parts = append(parts, names[b])
		}
	}
	return strings.Join(parts, "|")
}

// DoubleBit is the state of a double-bit binary input.
type DoubleBit uint8

// Double-bit states.
const (
	DoubleBitIntermediate  DoubleBit = 0
	DoubleBitOff           DoubleBit = 1
	DoubleBitOn            DoubleBit = 2
	DoubleBitIndeterminate DoubleBit = 3
)

// String returns "INTERMEDIATE", "DETERMINED_OFF", "DETERMINED_ON" or
// "INDETERMINATE".
func (d DoubleBit) String() string {
	switch d & 3 {
	case DoubleBitIntermediate:
		return "INTERMEDIATE"
	case DoubleBitOff:
		return "DETERMINED_OFF"
	case DoubleBitOn:
		return "DETERMINED_ON"
	default:
		return "INDETERMINATE"
	}
}

// CommandStatus is the status code of a control (IEEE 1815-2012
// Table 11-4), returned by the outstation in the echo of a command.
type CommandStatus uint8

// Command status codes.
const (
	StatusSuccess            CommandStatus = 0
	StatusTimeout            CommandStatus = 1
	StatusNoSelect           CommandStatus = 2
	StatusFormatError        CommandStatus = 3
	StatusNotSupported       CommandStatus = 4
	StatusAlreadyActive      CommandStatus = 5
	StatusHardwareError      CommandStatus = 6
	StatusLocal              CommandStatus = 7
	StatusTooManyObjects     CommandStatus = 8
	StatusNotAuthorized      CommandStatus = 9
	StatusAutomationInhibit  CommandStatus = 10
	StatusProcessingLimited  CommandStatus = 11
	StatusOutOfRange         CommandStatus = 12
	StatusDownstreamLocal    CommandStatus = 13
	StatusAlreadyComplete    CommandStatus = 14
	StatusBlocked            CommandStatus = 15
	StatusCanceled           CommandStatus = 16
	StatusBlockedOtherMaster CommandStatus = 17
	StatusDownstreamFail     CommandStatus = 18
	StatusNonParticipating   CommandStatus = 126
	StatusUndefined          CommandStatus = 127
)

var commandStatusNames = map[CommandStatus]string{
	StatusSuccess: "SUCCESS", StatusTimeout: "TIMEOUT", StatusNoSelect: "NO_SELECT",
	StatusFormatError: "FORMAT_ERROR", StatusNotSupported: "NOT_SUPPORTED",
	StatusAlreadyActive: "ALREADY_ACTIVE", StatusHardwareError: "HARDWARE_ERROR",
	StatusLocal: "LOCAL", StatusTooManyObjects: "TOO_MANY_OBJS", StatusNotAuthorized: "NOT_AUTHORIZED",
	StatusAutomationInhibit: "AUTOMATION_INHIBIT", StatusProcessingLimited: "PROCESSING_LIMITED",
	StatusOutOfRange: "OUT_OF_RANGE", StatusDownstreamLocal: "DOWNSTREAM_LOCAL",
	StatusAlreadyComplete: "ALREADY_COMPLETE", StatusBlocked: "BLOCKED", StatusCanceled: "CANCELLED",
	StatusBlockedOtherMaster: "BLOCKED_OTHER_MASTER", StatusDownstreamFail: "DOWNSTREAM_FAIL",
	StatusNonParticipating: "NON_PARTICIPATING", StatusUndefined: "UNDEFINED",
}

// String returns the name of the status code, for example "NO_SELECT".
func (s CommandStatus) String() string {
	if n, ok := commandStatusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("STATUS(%d)", uint8(s))
}

// OpType is the operation type of a control relay output block.
type OpType uint8

// Operation types.
const (
	OpNul      OpType = 0
	OpPulseOn  OpType = 1
	OpPulseOff OpType = 2
	OpLatchOn  OpType = 3
	OpLatchOff OpType = 4
)

// String returns "NUL", "PULSE_ON", "PULSE_OFF", "LATCH_ON", "LATCH_OFF"
// or "OP(n)".
func (o OpType) String() string {
	switch o {
	case OpNul:
		return "NUL"
	case OpPulseOn:
		return "PULSE_ON"
	case OpPulseOff:
		return "PULSE_OFF"
	case OpLatchOn:
		return "LATCH_ON"
	case OpLatchOff:
		return "LATCH_OFF"
	default:
		return fmt.Sprintf("OP(%d)", uint8(o))
	}
}

// TripClose is the trip-close code of a control relay output block.
type TripClose uint8

// Trip-close codes.
const (
	TCCNul   TripClose = 0
	TCCClose TripClose = 1
	TCCTrip  TripClose = 2
)

// String returns "NUL", "CLOSE", "TRIP" or "TCC(n)".
func (t TripClose) String() string {
	switch t {
	case TCCNul:
		return "NUL"
	case TCCClose:
		return "CLOSE"
	case TCCTrip:
		return "TRIP"
	default:
		return fmt.Sprintf("TCC(%d)", uint8(t))
	}
}

// Binary is a single-bit point: a binary input (groups 1 and 2), a
// binary output status (groups 10 and 11), a pattern mask bit (g12v3) or
// an internal indication bit (g80v1).
type Binary struct {
	Value bool
	// Flags are not sent in the packed variations (g1v1, g10v1, g12v3,
	// g80v1) and are zero when decoded from them.
	Flags Flags
	// Time is the time of the event in the variations with time.
	Time Timestamp
}

// DoubleBitBinary is a double-bit binary input (groups 3 and 4).
type DoubleBitBinary struct {
	Value DoubleBit
	Flags Flags
	Time  Timestamp
}

// BinaryCommandEvent is a binary output command event (group 13): a
// command the outstation received for a binary output.
type BinaryCommandEvent struct {
	// Value is the commanded state.
	Value  bool
	Status CommandStatus
	Time   Timestamp
}

// CROB is a control relay output block (g12v1) or a pattern control block
// (g12v2), which has the same layout.
type CROB struct {
	Op        OpType
	TripClose TripClose
	// Queue is the obsolete queue bit; Clear the clear bit.
	Queue, Clear bool
	// Count is the number of times to repeat the operation.
	Count uint8
	// OnTime and OffTime are in milliseconds.
	OnTime, OffTime uint32
	Status          CommandStatus
}

// Code returns the control code octet.
func (c CROB) Code() uint8 {
	b := uint8(c.Op)&0x0F | uint8(c.TripClose&3)<<6
	if c.Queue {
		b |= 0x10
	}
	if c.Clear {
		b |= 0x20
	}
	return b
}

// setCode sets the fields of the control code octet.
func (c *CROB) setCode(b uint8) {
	c.Op = OpType(b & 0x0F)
	c.Queue = b&0x10 != 0
	c.Clear = b&0x20 != 0
	c.TripClose = TripClose(b >> 6)
}

// String returns, for example, "LATCH_ON count=1 on=100ms off=0ms SUCCESS".
func (c CROB) String() string {
	s := c.Op.String()
	if c.TripClose != TCCNul {
		s = c.TripClose.String() + "/" + s
	}
	if c.Queue {
		s += " queue"
	}
	if c.Clear {
		s += " clear"
	}
	return fmt.Sprintf("%s count=%d on=%dms off=%dms %s", s, c.Count, c.OnTime, c.OffTime, c.Status)
}

// Counter is a counter (group 20), a frozen counter (group 21) or a
// counter event of either (groups 22 and 23). The 16-bit variations carry
// the low 16 bits of Value.
type Counter struct {
	Value uint32
	Flags Flags
	// Time is the time of freeze (g21) or of the event, in the variations
	// with time.
	Time Timestamp
}

// Analog is an analog input (group 30), a frozen analog input (group 31),
// an analog output status (group 40) or an event of one of these (groups
// 32, 33 and 42).
//
// Encoding a value into an integer variation rounds it to the nearest
// integer; a value the variation cannot hold is sent as the nearest value
// it can, with [FlagOverRange] set in the variations with flags.
type Analog struct {
	Value float64
	Flags Flags
	Time  Timestamp
}

// AnalogDeadband is an analog input reporting deadband (group 34).
type AnalogDeadband struct {
	Value float64
}

// AnalogOutput is an analog output block (group 41): a set-point command
// and its echo.
type AnalogOutput struct {
	Value  float64
	Status CommandStatus
}

// AnalogCommandEvent is an analog output command event (group 43).
type AnalogCommandEvent struct {
	Value  float64
	Status CommandStatus
	Time   Timestamp
}

// IntervalUnit is the unit of the interval of g50v4.
type IntervalUnit uint8

// Interval units (IEEE 1815-2012 Table 11-23).
const (
	UnitNone         IntervalUnit = 0
	UnitMilliseconds IntervalUnit = 1
	UnitSeconds      IntervalUnit = 2
	UnitMinutes      IntervalUnit = 3
	UnitHours        IntervalUnit = 4
	UnitDays         IntervalUnit = 5
	UnitWeeks        IntervalUnit = 6
	UnitMonths       IntervalUnit = 7
	UnitMonthsDay    IntervalUnit = 8
	UnitMonthsLast   IntervalUnit = 9
	UnitMonthsSame   IntervalUnit = 10
)

// AbsoluteTime is a time and date object (group 50): the absolute time
// (v1), the time and interval of a freeze (v2), the time at last recorded
// time (v3), or an indexed absolute time and long interval (v4).
type AbsoluteTime struct {
	Time Timestamp
	// Interval is the interval of g50v2 in milliseconds and of g50v4 in
	// Units.
	Interval uint32
	// Units is the interval unit of g50v4.
	Units IntervalUnit
}

// CTO is a common time of occurrence (group 51): the base time of the
// relative-time event variations that follow it in the same fragment.
// g51v1 is a synchronized and g51v2 an unsynchronized base time.
type CTO struct {
	Time Timestamp
}

// TimeDelay is a time delay object (group 52): coarse (v1, seconds) or
// fine (v2, milliseconds).
type TimeDelay struct {
	Delay time.Duration
}

// OctetString is an octet string (group 110), an octet string event
// (group 111), or a virtual terminal output block or event (groups 112 and
// 113). The variation is the length of Data, 1..255.
type OctetString struct {
	Data []byte
}

// BCD is a binary-coded decimal integer (group 101): 4 digits (v1), 8
// digits (v2) or 16 digits (v3). Value is the decimal number.
type BCD struct {
	Value uint64
}

// UnsignedInteger is an unsigned 8-bit integer (g102v1).
type UnsignedInteger struct {
	Value uint8
}

// DataSetCharacteristics is the characteristics octet of a data set
// descriptor (g86v2, IEEE 1815-2012 Annex A).
type DataSetCharacteristics struct {
	Flags DataSetFlags
}

// DataSetFlags are the bits of [DataSetCharacteristics].
type DataSetFlags uint8

// Data set characteristics bits.
const (
	// DataSetReadable (RD): the data set can be read.
	DataSetReadable DataSetFlags = 1 << iota
	// DataSetWritable (WR): the data set can be written.
	DataSetWritable
	// DataSetStatic (ST): the outstation maintains a static data set.
	DataSetStatic
	// DataSetEvents (EV): the outstation generates data set events.
	DataSetEvents
	// DataSetMasterDefined (DF): the data set was defined by a master.
	DataSetMasterDefined
)

// String returns the names of the set bits, joined by "|".
func (f DataSetFlags) String() string {
	names := [...]string{"RD", "WR", "ST", "EV", "DF", "BIT5", "BIT6", "BIT7"}
	var parts []string
	for b := range 8 {
		if f&(1<<b) != 0 {
			parts = append(parts, names[b])
		}
	}
	return strings.Join(parts, "|")
}

// SecurityStatistic is a secure authentication statistic (group 121) or
// a statistic event (group 122).
type SecurityStatistic struct {
	// Flags are the quality flags.
	Flags Flags
	// Association identifies the association the statistic is about.
	Association uint16
	// Value is the count.
	Value uint32
	// Time is when an event (group 122 with time) was raised.
	Time Timestamp
}

// Raw is a free-format object that this package carries without
// decoding: the obsolete g70v1, private registration objects (group 83),
// the data set objects of groups 85..88 but the characteristics (g86v2), the application identifier (g90v1) and
// the status of requested operation (g91v1).
type Raw struct {
	Data []byte
}

func (Binary) isValue()                 {}
func (DoubleBitBinary) isValue()        {}
func (BinaryCommandEvent) isValue()     {}
func (CROB) isValue()                   {}
func (Counter) isValue()                {}
func (Analog) isValue()                 {}
func (AnalogDeadband) isValue()         {}
func (AnalogOutput) isValue()           {}
func (AnalogCommandEvent) isValue()     {}
func (AbsoluteTime) isValue()           {}
func (CTO) isValue()                    {}
func (TimeDelay) isValue()              {}
func (OctetString) isValue()            {}
func (BCD) isValue()                    {}
func (UnsignedInteger) isValue()        {}
func (DataSetCharacteristics) isValue() {}
func (SecurityStatistic) isValue()      {}
func (Raw) isValue()                    {}

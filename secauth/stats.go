// SPDX-License-Identifier: MIT

package secauth

import (
	"fmt"

	"github.com/otfabric/go-dnp3/app"
)

// Statistic is the index of a security statistic (group 121, events in
// group 122), as IEEE 1815-2012 Table 7-6 (clause 7.5.2.2) numbers them.
type Statistic uint16

// The security statistics.
const (
	StatUnexpectedMessages Statistic = iota
	StatAuthorizationFailures
	StatAuthenticationFailures
	StatReplyTimeouts
	StatRekeysDueToAuthFailure
	StatTotalMessagesSent
	StatTotalMessagesReceived
	StatCriticalMessagesSent
	StatCriticalMessagesReceived
	StatDiscardedMessages
	StatErrorMessagesSent
	StatErrorMessagesReceived
	StatSuccessfulAuthentications
	StatSessionKeyChanges
	StatFailedSessionKeyChanges
	StatUpdateKeyChanges
	StatFailedUpdateKeyChanges
	StatRekeysDueToRestarts
	// NumStatistics is the number of statistics: indexes 0..NumStatistics-1.
	NumStatistics
)

var statNames = [NumStatistics]string{
	"unexpected messages", "authorization failures", "authentication failures", "reply timeouts",
	"rekeys due to authentication failure", "total messages sent", "total messages received",
	"critical messages sent", "critical messages received", "discarded messages", "error messages sent",
	"error messages received", "successful authentications", "session key changes",
	"failed session key changes", "update key changes", "failed update key changes", "rekeys due to restarts",
}

// String returns the statistic's name, for example "session key changes".
func (s Statistic) String() string {
	if s < NumStatistics {
		return statNames[s]
	}
	return fmt.Sprintf("statistic %d", uint16(s))
}

// DefaultThreshold returns the default event threshold of the statistic
// (IEEE 1815-2012 Table 7-6, 7.6.1.4.2): how many increments between two
// of its events (g122), and, for the five statistics of Table 7-15, the
// step of the moving maximum the state machines act on (for example Max
// Error Messages Sent). It returns 0 for an unknown statistic.
func (s Statistic) DefaultThreshold() uint16 {
	if s < NumStatistics {
		return defaultThresholds[s]
	}
	return 0
}

var defaultThresholds = [NumStatistics]uint16{3, 5, 5, 3, 3, 100, 100, 100, 100, 10, 2, 10, 100, 10, 5, 1, 1, 3}

// MandatoryCritical are the request function codes IEEE 1815-2012 Table
// 7-7 marks MANDATORY: an outstation must challenge every request with one
// of them (clause 7.5.2.3.2 a). Package server always adds them to the
// codes it challenges.
var MandatoryCritical = []app.FunctionCode{
	app.FuncWrite, app.FuncSelect, app.FuncOperate, app.FuncDirectOperate, app.FuncDirectOperateNoAck,
	app.FuncColdRestart, app.FuncWarmRestart, app.FuncInitializeApplication, app.FuncStartApplication,
	app.FuncStopApplication, app.FuncSaveConfiguration, app.FuncEnableUnsolicited, app.FuncDisableUnsolicited,
	app.FuncRecordCurrentTime, app.FuncOpenFile, app.FuncCloseFile, app.FuncDeleteFile, app.FuncGetFileInfo,
	app.FuncAuthenticateFile, app.FuncAbortFile, app.FuncActivateConfig,
}

// DefaultCritical are the function codes an outstation challenges by
// default, and a master sends in aggressive mode: the MANDATORY ones of
// IEEE 1815-2012 Table 7-7 ([MandatoryCritical]) and the optional ones
// that change the outstation's state (the freezes, INITIALIZE_DATA and
// ASSIGN_CLASS, clause 7.5.2.3.2 b).
var DefaultCritical = []app.FunctionCode{
	app.FuncWrite, app.FuncSelect, app.FuncOperate, app.FuncDirectOperate, app.FuncDirectOperateNoAck,
	app.FuncImmediateFreeze, app.FuncImmediateFreezeNoAck, app.FuncFreezeClear, app.FuncFreezeClearNoAck,
	app.FuncFreezeAtTime, app.FuncFreezeAtTimeNoAck, app.FuncColdRestart, app.FuncWarmRestart,
	app.FuncInitializeData, app.FuncInitializeApplication, app.FuncStartApplication, app.FuncStopApplication,
	app.FuncSaveConfiguration, app.FuncEnableUnsolicited, app.FuncDisableUnsolicited, app.FuncAssignClass,
	app.FuncRecordCurrentTime, app.FuncOpenFile, app.FuncCloseFile, app.FuncDeleteFile, app.FuncGetFileInfo,
	app.FuncAuthenticateFile, app.FuncAbortFile, app.FuncActivateConfig,
}

// AggressiveOverhead is the most an aggressive mode request adds to a
// request: the g120v3 object with its header (10 octets) and the g120v9
// MAC with its header (6 octets and a MAC of up to 16).
const AggressiveOverhead = 32

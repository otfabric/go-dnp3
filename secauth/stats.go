// SPDX-License-Identifier: MIT

package secauth

import (
	"fmt"

	"github.com/otfabric/go-dnp3/app"
)

// Statistic is the index of a security statistic (group 121, events in
// group 122), as IEEE 1815-2012 clause 7.6 numbers them.
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

// DefaultCritical are the function codes an outstation challenges by
// default, and a master sends in aggressive mode: the ones that change the
// outstation's state.
var DefaultCritical = []app.FunctionCode{
	app.FuncWrite, app.FuncSelect, app.FuncOperate, app.FuncDirectOperate, app.FuncDirectOperateNoAck,
	app.FuncImmediateFreeze, app.FuncImmediateFreezeNoAck, app.FuncFreezeClear, app.FuncFreezeClearNoAck,
	app.FuncFreezeAtTime, app.FuncFreezeAtTimeNoAck, app.FuncColdRestart, app.FuncWarmRestart,
	app.FuncInitializeData, app.FuncInitializeApplication, app.FuncStartApplication, app.FuncStopApplication,
	app.FuncSaveConfiguration, app.FuncAssignClass, app.FuncOpenFile, app.FuncDeleteFile,
	app.FuncActivateConfig, app.FuncAuthenticateFile,
}

// AggressiveOverhead is the most an aggressive mode request adds to a
// request: the g120v3 object with its header (10 octets) and the g120v9
// MAC with its header (6 octets and a MAC of up to 16).
const AggressiveOverhead = 32

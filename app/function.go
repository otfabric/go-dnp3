// SPDX-License-Identifier: MIT

package app

import "fmt"

// FunctionCode is the application layer function code (IEEE 1815-2012
// clause 4.2.2.5, Table 4-1 and Table 4-2).
type FunctionCode uint8

// Request function codes.
const (
	FuncConfirm               FunctionCode = 0
	FuncRead                  FunctionCode = 1
	FuncWrite                 FunctionCode = 2
	FuncSelect                FunctionCode = 3
	FuncOperate               FunctionCode = 4
	FuncDirectOperate         FunctionCode = 5
	FuncDirectOperateNoAck    FunctionCode = 6
	FuncImmediateFreeze       FunctionCode = 7
	FuncImmediateFreezeNoAck  FunctionCode = 8
	FuncFreezeClear           FunctionCode = 9
	FuncFreezeClearNoAck      FunctionCode = 10
	FuncFreezeAtTime          FunctionCode = 11
	FuncFreezeAtTimeNoAck     FunctionCode = 12
	FuncColdRestart           FunctionCode = 13
	FuncWarmRestart           FunctionCode = 14
	FuncInitializeData        FunctionCode = 15
	FuncInitializeApplication FunctionCode = 16
	FuncStartApplication      FunctionCode = 17
	FuncStopApplication       FunctionCode = 18
	FuncSaveConfiguration     FunctionCode = 19
	FuncEnableUnsolicited     FunctionCode = 20
	FuncDisableUnsolicited    FunctionCode = 21
	FuncAssignClass           FunctionCode = 22
	FuncDelayMeasure          FunctionCode = 23
	FuncRecordCurrentTime     FunctionCode = 24
	FuncOpenFile              FunctionCode = 25
	FuncCloseFile             FunctionCode = 26
	FuncDeleteFile            FunctionCode = 27
	FuncGetFileInfo           FunctionCode = 28
	FuncAuthenticateFile      FunctionCode = 29
	FuncAbortFile             FunctionCode = 30
	FuncActivateConfig        FunctionCode = 31
	FuncAuthRequest           FunctionCode = 32
	FuncAuthRequestNoAck      FunctionCode = 33
)

// Response function codes.
const (
	FuncResponse            FunctionCode = 129
	FuncUnsolicitedResponse FunctionCode = 130
	FuncAuthResponse        FunctionCode = 131
)

var functionNames = map[FunctionCode]string{
	FuncConfirm:               "CONFIRM",
	FuncRead:                  "READ",
	FuncWrite:                 "WRITE",
	FuncSelect:                "SELECT",
	FuncOperate:               "OPERATE",
	FuncDirectOperate:         "DIRECT_OPERATE",
	FuncDirectOperateNoAck:    "DIRECT_OPERATE_NR",
	FuncImmediateFreeze:       "IMMED_FREEZE",
	FuncImmediateFreezeNoAck:  "IMMED_FREEZE_NR",
	FuncFreezeClear:           "FREEZE_CLEAR",
	FuncFreezeClearNoAck:      "FREEZE_CLEAR_NR",
	FuncFreezeAtTime:          "FREEZE_AT_TIME",
	FuncFreezeAtTimeNoAck:     "FREEZE_AT_TIME_NR",
	FuncColdRestart:           "COLD_RESTART",
	FuncWarmRestart:           "WARM_RESTART",
	FuncInitializeData:        "INITIALIZE_DATA",
	FuncInitializeApplication: "INITIALIZE_APPL",
	FuncStartApplication:      "START_APPL",
	FuncStopApplication:       "STOP_APPL",
	FuncSaveConfiguration:     "SAVE_CONFIG",
	FuncEnableUnsolicited:     "ENABLE_UNSOLICITED",
	FuncDisableUnsolicited:    "DISABLE_UNSOLICITED",
	FuncAssignClass:           "ASSIGN_CLASS",
	FuncDelayMeasure:          "DELAY_MEASURE",
	FuncRecordCurrentTime:     "RECORD_CURRENT_TIME",
	FuncOpenFile:              "OPEN_FILE",
	FuncCloseFile:             "CLOSE_FILE",
	FuncDeleteFile:            "DELETE_FILE",
	FuncGetFileInfo:           "GET_FILE_INFO",
	FuncAuthenticateFile:      "AUTHENTICATE_FILE",
	FuncAbortFile:             "ABORT_FILE",
	FuncActivateConfig:        "ACTIVATE_CONFIG",
	FuncAuthRequest:           "AUTHENTICATE_REQ",
	FuncAuthRequestNoAck:      "AUTH_REQ_NO_ACK",
	FuncResponse:              "RESPONSE",
	FuncUnsolicitedResponse:   "UNSOLICITED_RESPONSE",
	FuncAuthResponse:          "AUTHENTICATE_RESP",
}

// String returns the name of the function code in the standard's
// notation, for example "DIRECT_OPERATE".
func (f FunctionCode) String() string {
	if s, ok := functionNames[f]; ok {
		return s
	}
	return fmt.Sprintf("FUNCTION(%d)", uint8(f))
}

// Defined reports whether IEEE 1815-2012 defines f.
func (f FunctionCode) Defined() bool {
	_, ok := functionNames[f]
	return ok
}

// IsResponse reports whether f is a response function code: the header of
// such a fragment carries the internal indications.
func (f FunctionCode) IsResponse() bool { return f >= FuncResponse }

// NoAck reports whether the outstation sends no response to a request with
// this function code.
func (f FunctionCode) NoAck() bool {
	switch f {
	case FuncDirectOperateNoAck, FuncImmediateFreezeNoAck, FuncFreezeClearNoAck,
		FuncFreezeAtTimeNoAck, FuncAuthRequestNoAck, FuncConfirm:
		return true
	default:
		return false
	}
}

// carriesObjects reports whether the object headers of a request with this
// function code are followed by objects. READ, freeze, unsolicited control
// and assign class requests name points but carry no values.
func (f FunctionCode) carriesObjects() bool {
	switch f {
	case FuncRead, FuncImmediateFreeze, FuncImmediateFreezeNoAck, FuncFreezeClear,
		FuncFreezeClearNoAck, FuncEnableUnsolicited, FuncDisableUnsolicited,
		FuncAssignClass, FuncColdRestart, FuncWarmRestart, FuncDelayMeasure,
		FuncRecordCurrentTime, FuncInitializeData, FuncSaveConfiguration,
		FuncFreezeAtTime, FuncFreezeAtTimeNoAck:
		return false
	default:
		return true
	}
}

// SPDX-License-Identifier: MIT

package dnp3

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-dnp3/app"
)

// Sentinel errors shared by the client and the server. They are usually
// wrapped with detail; test with errors.Is.
var (
	// ErrClosed reports an operation on a client, server or association
	// that was closed by the application.
	ErrClosed = errors.New("dnp3: closed")

	// ErrNotConnected reports a request on a client that has no
	// established channel.
	ErrNotConnected = errors.New("dnp3: not connected")

	// ErrConnectFailed reports that a client could not establish its
	// channel: the dial, the TLS handshake or the opening of the serial
	// port failed. The underlying error is wrapped alongside it.
	ErrConnectFailed = errors.New("dnp3: connect failed")

	// ErrConnectionLost reports that the peer closed the channel or the
	// transport failed while a request was in progress.
	ErrConnectionLost = errors.New("dnp3: connection lost")

	// ErrTimeout reports that the peer did not answer within the response
	// timeout (client) or did not confirm within the confirm timeout
	// (server), or that a link layer confirmation did not arrive.
	ErrTimeout = errors.New("dnp3: timeout")

	// ErrProtocol reports a peer that violated the protocol: a response
	// with an unexpected sequence number or function, objects that do not
	// match the request, or a fragment that could not be decoded.
	ErrProtocol = errors.New("dnp3: protocol violation")

	// ErrBusy reports a request that cannot be issued because the
	// association has reached its queue limit.
	ErrBusy = errors.New("dnp3: too many pending requests")

	// ErrInvalidOption reports an option value a client or server cannot
	// be constructed with.
	ErrInvalidOption = errors.New("dnp3: invalid option")

	// ErrAuthentication reports a failure of secure authentication: a MAC
	// that does not verify, a key that is not initialized, or a challenge
	// that was not answered. An *[AuthError] carries the code the peer sent.
	ErrAuthentication = errors.New("dnp3: authentication failed")
)

// IINError reports that an outstation rejected a request: the response
// carried IIN2 bits that report an error (no function code support,
// object unknown, parameter error, already executing).
type IINError struct {
	// Function is the function code of the rejected request.
	Function app.FunctionCode
	// IIN is the internal indications of the response.
	IIN app.IIN
}

// Error describes the rejection, for example
// "dnp3: SELECT rejected: OBJECT_UNKNOWN".
func (e *IINError) Error() string {
	return fmt.Sprintf("dnp3: %s rejected: %s", e.Function, (e.IIN & IINErrorBits).String())
}

// IINErrorBits are the internal indications that make a response an
// [IINError].
const IINErrorBits = app.IINNoFuncCodeSupport | app.IINObjectUnknown | app.IINParameterError | app.IINAlreadyExecuting

// CommandError reports a control the outstation did not execute: its
// echo carried a status other than SUCCESS.
type CommandError struct {
	// GV is the object of the command, for example app.G12V1.
	GV app.GroupVariation
	// Index is the point index.
	Index uint32
	// Status is the status code of the echo.
	Status app.CommandStatus
}

// Error describes the failure, for example
// "dnp3: g12v1 index 3: command status NO_SELECT".
func (e *CommandError) Error() string {
	return fmt.Sprintf("dnp3: %s index %d: command status %s", e.GV, e.Index, e.Status)
}

// FileError reports a file operation the outstation refused.
type FileError struct {
	// Op is the operation: "open", "close", "delete", "read", "write",
	// "abort", "info" or "authenticate".
	Op string
	// Status is the file status the outstation answered.
	Status app.FileStatus
	// Text is the optional text the outstation sent with the status.
	Text string
}

// Error describes the failure, for example
// "dnp3: file open: FILE_NOT_FOUND".
func (e *FileError) Error() string {
	s := fmt.Sprintf("dnp3: file %s: %s", e.Op, e.Status)
	if e.Text != "" {
		s += " (" + e.Text + ")"
	}
	return s
}

// AuthError reports an authentication error object (g120v7) received from
// the peer. It matches [ErrAuthentication] with errors.Is.
type AuthError struct {
	// Code is the error code of the g120v7 object.
	Code app.AuthErrorCode
	// User is the user number the error is about.
	User uint16
	// Text is the optional error text the peer sent.
	Text string
}

// Error describes the failure, for example
// "dnp3: authentication error AUTHENTICATION_FAILED (user 1)".
func (e *AuthError) Error() string {
	s := fmt.Sprintf("dnp3: authentication error %s (user %d)", e.Code, e.User)
	if e.Text != "" {
		s += ": " + e.Text
	}
	return s
}

// Is makes an AuthError match [ErrAuthentication].
func (e *AuthError) Is(target error) bool { return target == ErrAuthentication }

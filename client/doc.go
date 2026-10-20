// SPDX-License-Identifier: MIT

// Package client is the DNP3 master (IEEE 1815-2012).
//
// A [Client] talks to one outstation. [Dial] connects and runs the startup
// sequence (with secure authentication and an update key, the session key
// change first; then clearing DEVICE_RESTART, disabling and enabling
// unsolicited responses and an integrity poll, as [WithStartup] says);
// [New] and [Client.Connect] do the same in two steps. Requests are
// methods that block until the outstation answered or the context ended:
// [Client.IntegrityPoll], [Client.EventPoll], [Client.Read],
// [Client.Operate], [Client.SyncTime], [Client.ColdRestart], [Client.Broadcast],
// [Client.ReadAttributeSet], the file transfer methods and more. Unsolicited responses and the measurements of
// every response go to the [Handler] of [WithHandler].
//
// Transports: TCP (the default, port 20000), TLS ([WithTLS]), UDP
// ([UDP] with [WithStream]), any byte stream such as a serial port
// ([WithStream]), and the dual end point, where the outstation establishes
// the connection ([Accept]).
//
// For a long-running master: [WithReconnect] re-establishes a lost
// channel with backoff, [WithRetry] repeats the requests that are safe to
// repeat, [WithPoll] runs periodic polls, [WithLogger] and [WithMetrics]
// report what happens. Secure Authentication version 5 is
// [WithSecureAuthentication], with [WithKeyChangeInterval] and
// [WithAggressiveMode].
//
// Errors match the sentinels of the root package with errors.Is; see
// ERRORS.md. API.md lists the whole API.
package client

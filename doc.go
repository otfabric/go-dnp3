// SPDX-License-Identifier: MIT

// Package dnp3 is the module root of a pure Go implementation of DNP3
// (IEEE 1815-2012), the SCADA protocol between masters and outstations in
// electric, water and oil and gas utilities.
//
// Applications import the subpackages:
//
//   - [github.com/otfabric/go-dnp3/client]: the master: integrity and
//     event polls, unsolicited responses, controls with select-before-
//     operate, time synchronization, restarts, file transfer, secure
//     authentication, automatic reconnect and retries
//   - [github.com/otfabric/go-dnp3/server]: the outstation: a point
//     database with event buffers per class, request handling, unsolicited
//     responses, controls and command events, file transfer, secure
//     authentication with statistics, and the dual end point
//   - [github.com/otfabric/go-dnp3/secauth]: Secure Authentication
//     version 5: users and keys, MACs, the AES key wrap, statistics
//   - [github.com/otfabric/go-dnp3/app]: the application layer codec and
//     the object library
//   - [github.com/otfabric/go-dnp3/transport]: the transport function
//   - [github.com/otfabric/go-dnp3/link]: the data link layer codec
//
// This package holds what client and server share: the sentinel and typed
// errors, the [Logger] and [Metrics] interfaces and the channel [State].
//
// Docs: README.md, API.md (public API), ARCHITECTURE.md, ERRORS.md (error
// semantics), OBSERVABILITY.md (logging and metrics), INTEROPERABILITY.md
// (conformance and interop coverage), SECURITY.md, CONTRIBUTING.md,
// RELEASE.md (changelog).
package dnp3

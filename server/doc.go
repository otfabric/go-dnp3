// SPDX-License-Identifier: MIT

// Package server is the DNP3 outstation (IEEE 1815-2012).
//
// A [Server] holds a [Database] of points (binary, double-bit, counters,
// frozen counters, analogs, frozen analogs, outputs, octet strings) whose
// changes become events in classes 1 to 3, buffered per master
// (association) and reported in polls and unsolicited responses. Controls,
// restarts, time synchronization and the application functions go to the
// [Handler] of [WithHandler] and its optional interfaces; file transfer to
// the [FileServer] of [WithFileServer].
//
// Device attributes are [WithAttributes] (set 0) and [WithAttributeSet];
// FREEZE_AT_TIME requests are scheduled ([MaxScheduledFreezes]).
//
// Transports: [Server.ListenAndServe] and [Server.Serve] for TCP, TLS with
// [WithTLS], [Server.ServeUDP] for UDP, [Server.ServeConn] for any byte
// stream such as a serial port, and [Server.DialAndServe] for the dual end
// point, where the outstation connects to its master. [Server.Close] ends
// them all. A [Group] serves several outstations, each a Server at its own
// link address, on the same port or line (multi-drop).
//
// Secure Authentication version 5 ([WithSecureAuthentication]) challenges
// critical requests, takes part in the session key change, accepts
// aggressive mode requests and keeps the security statistics (g121, g122)
// per master.
//
// API.md lists the whole API; INTEROPERABILITY.md what is implemented,
// clause by clause.
package server

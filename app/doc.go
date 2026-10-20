// SPDX-License-Identifier: MIT

// Package app is the DNP3 application layer codec (IEEE 1815-2012
// clause 4 and Annex A): fragments with their control octet, function
// code and internal indications, object headers with their qualifiers, and
// the object library.
//
// A [Fragment] is a list of [Header] values; each header names a group and
// variation ([GroupVariation]) and carries [Object] values, an index plus a
// [Value]. The value types are a closed set of structs (for example
// [Binary], [Analog], [Counter], [CROB], [FileTransport], [AuthChallenge]);
// variations of the same kind of point share one struct and the header's
// variation decides the encoding.
//
// The library covers every object group of IEEE 1815-2012 Annex A that a
// current device sends: binary and double-bit inputs, binary outputs and
// commands, counters and frozen counters, analog inputs, frozen analog
// inputs, deadbands, analog outputs and commands, time objects, class
// objects, file control (group 70), internal indications, device
// attributes (group 0), BCD and small integers, octet strings and virtual
// terminal objects, and the secure authentication objects (groups 120 to
// 122). Data set and private registration objects (groups 83 to 91) are
// carried as [Raw] payload.
//
// The package is a pure codec: it does no I/O and keeps no state between
// fragments. It imports nothing outside the standard library.
package app
